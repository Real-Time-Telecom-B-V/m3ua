# m3ua

[![crates.io](https://img.shields.io/crates/v/m3ua.svg)](https://crates.io/crates/m3ua)
[![docs.rs](https://docs.rs/m3ua/badge.svg)](https://docs.rs/m3ua)
[![CI](https://github.com/Real-Time-Telecom-B-V/m3ua/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/m3ua/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An **M3UA ([RFC 4666](https://www.rfc-editor.org/rfc/rfc4666.html))** codec and
SG-side ASP state machine — the **MTP3 User Adaptation Layer** that carries SS7
MTP3-User signalling (SCCP, ISUP, …) over IP using SCTP as the transport. It
ships as **both** a Rust crate (`cargo add m3ua`) and a Rust-backed Python wheel
(`pip install m3ua`), built from one source tree and one version.

This crate is the **wire format** (common header, TLV parameters, the Protocol
Data payload) plus the **pure ASP/AS state machine**. It does no I/O — the SCTP
association and the running event loop belong to the composing runtime, so the
codec stays portable and every consumer can unit-test against it.

```rust
use m3ua::{M3uaMessage, MessageType, ProtocolData};

// ASPSM handshake: build an ASP-UP, round-trip it on the wire.
let aspup = M3uaMessage::asp_up(Some(1), None);
let bytes = aspup.encode();
let decoded = M3uaMessage::decode(&bytes).unwrap();
assert_eq!(decoded.message_type, MessageType::AspUp);

// A DATA message carrying an MTP3-User payload (e.g. an SCCP UDT).
let pd = ProtocolData::new(
    100,               // OPC
    200,               // DPC
    3,                 // SI = SCCP
    2,                 // NI = National
    0,                 // MP
    5,                 // SLS
    vec![0x09, 0x01],  // user data (SCCP/ISUP/…)
);
let data = M3uaMessage::data(None, Some(42), pd, None);
let bytes = data.encode();
let decoded = M3uaMessage::decode(&bytes).unwrap();
assert_eq!(decoded.routing_context(), Some(42));
assert_eq!(decoded.protocol_data().unwrap().dpc, 200);
```

```python
import m3ua

# ASPSM handshake message.
aspup = m3ua.M3uaMessage.asp_up(asp_id=1)
wire = aspup.encode()                                # bytes
msg = m3ua.decode(wire)                               # -> M3uaMessage
assert msg.message_type == m3ua.MessageType.AspUp

# A DATA message carrying an MTP3-User payload.
pd = m3ua.ProtocolData(opc=100, dpc=200, si=3, ni=2, mp=0, sls=5,
                       user_data=b"\x09\x01")
data = m3ua.M3uaMessage.data(pd, routing_context=42)
assert m3ua.decode(data.encode()).protocol_data().dpc == 200
```

📖 More: [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

## What's in the box

| Piece | Type |
|---|---|
| Common Message Header — version / reserved / class / type / length | `CommonHeader` |
| Message classes and types (MGMT / Transfer / SSNM / ASPSM / ASPTM / RKM) | `MessageClass`, `MessageType` |
| TLV parameter — tag / length / 4-byte-padded value | `Parameter`, `tags` |
| Protocol Data payload — OPC / DPC / SI / NI / MP / SLS + user data | `ProtocolData` |
| Whole-message encode / decode with validation | `M3uaMessage` |
| SG-side ASP/AS state machine | `Asp`, `AspState`, `AspAction` |
| Typed errors | `M3uaError` |
| Constants — protocol `VERSION`, SCTP `SCTP_PPID` | — |

## RFC 4666 coverage

| Feature | Status |
|---|---|
| Common Message Header (version 1, all six message classes) | ✅ encode / decode + validation |
| Header validation — version = 1, known class + type | ✅ rejected as `M3uaError` |
| Transfer — `DATA` with Protocol Data (OPC/DPC/SI/NI/MP/SLS + user data) | ✅ `ProtocolData` |
| ASPSM — `ASP-UP` / `ASP-DOWN` / `BEAT` (+ their ACKs) | ✅ builders + state machine |
| ASPTM — `ASP-ACTIVE` / `ASP-INACTIVE` (+ their ACKs) | ✅ builders + state machine |
| SSNM — `DUNA` / `DAVA` / `DAUD` / `SCON` / `DUPU` / `DRST` | ✅ types; builders for DUNA/DAVA/DAUD |
| MGMT — `ERR` / `NTFY` | ✅ builders |
| RKM — `REG-REQ` / `REG-RSP` / `DEREG-REQ` / `DEREG-RSP` | ✅ types + tags |
| TLV parameters — tag/length, value padded to a 4-byte boundary | ✅ `Parameter` |
| SG-side ASP state machine (Down → Inactive → Active) | ✅ `Asp` |
| SCTP association setup, retransmission, congestion, the PPID on the wire | ⛔ out of scope — belongs to the runtime that owns the socket |

## Boundary: what this crate does and doesn't do

M3UA's job splits cleanly:

- **This crate (pure, no I/O):** serialise / parse the messages and their TLV
  parameters, and compute ASP state transitions from received messages.
- **The composing runtime:** owns the SCTP association (multi-streaming,
  ordered/unordered delivery, the registered PPID), drives retransmission and the
  M3UA timers, and feeds received messages into the `Asp` state machine. Anything
  that speaks SCTP — a SIGTRAN gateway, an STP, a test rig — can host it.

Keeping the codec I/O-free is what makes it trivial to unit-test against
RFC-derived vectors and to embed unchanged in different transports — and is what
lets the exact same logic back the Rust crate and the Python wheel.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec
is allocation-light. Indicative numbers (encode/decode of a DATA with a ~36-byte
payload, a DUNA, and an ASP-UP):

| Operation | Time | Throughput |
|---|---|---|
| DATA decode | ~30 ns | ~34 M msg/s |
| DATA encode | ~82 ns | ~12 M msg/s |
| DUNA decode | ~29 ns | ~34 M msg/s |
| ASP-UP decode | ~29 ns | ~34 M msg/s |
| DATA decode + extract Protocol Data | ~39 ns | ~26 M msg/s |

A counting-allocator [leak check](examples/leak_check.rs)
(`./scripts/mem_leak_test.sh`) hammers encode/decode and the ASP state machine
and asserts **live bytes stay flat** (Δ 0 over millions of cycles). Both run in
CI.

The Python wheel is the same Rust code behind PyO3; per-call overhead is the
Python↔Rust boundary, not the codec. The module is declared `gil_used = false`,
so it loads on free-threaded ("no-GIL") CPython 3.13t / 3.14t.

## Install

```bash
cargo add m3ua          # Rust crate (zero pyo3 in the default build)
pip install m3ua        # Rust-backed Python wheel
```

## Development

```bash
cargo test                                  # unit + integration + doctests
cargo test --features python                # + the PyO3 binding face
cargo clippy --all-targets -- -D warnings
cargo bench --no-run
./scripts/mem_leak_test.sh                  # live-bytes leak check (PASS/FAIL)
cargo deny check                            # advisories, licenses, sources

# Python wheel
maturin develop && pytest python/tests -q
```

## License

MIT — see [LICENSE](LICENSE).

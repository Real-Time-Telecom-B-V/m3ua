# m3ua — overview

A pure-Rust **M3UA** ([RFC 4666](https://www.rfc-editor.org/rfc/rfc4666.html))
codec and SG-side ASP state machine. M3UA is the **MTP3 User Adaptation Layer**:
it carries SS7 MTP3-User signalling (SCCP, ISUP, …) across an IP network, using
SCTP as the transport. This crate is the wire format plus the pure state
machine — no sockets, no async runtime of its own — so it stays portable and
every consumer can unit-test against it.

## The idea

An M3UA message is a fixed 8-byte **common header** followed by zero or more
**TLV parameters**. The header carries a message *class* (MGMT, Transfer, SSNM,
ASPSM, ASPTM, RKM) and a *type* within that class; the parameters carry the
routing context, the affected point codes, the Protocol Data payload, and so on.
Transfer-class `DATA` messages wrap an MTP3-User MSU in a **Protocol Data**
parameter (OPC / DPC / SI / NI / MP / SLS + the user payload).

Two peers — a **Signalling Gateway (SG)** and one or more **Application Server
Processes (ASPs)** — run the ASPSM/ASPTM handshake (`ASP-UP` → `ASP-UP-ACK`,
`ASP-ACTIVE` → `ASP-ACTIVE-ACK`) before `DATA` may flow. This crate models the
SG side of that handshake as a pure state machine.

## Module map

| Module | Public surface | Role |
|---|---|---|
| `header` | `CommonHeader`, `MessageClass`, `MessageType`, `VERSION`, `SCTP_PPID` | The 8-byte common header; class/type enums with `(class, type)` mapping and validation. |
| `parameter` | `Parameter`, `tags`, `decode_parameters`, `encode_parameters`, `find_parameter` | TLV parameters: tag/length, value padded to a 4-byte boundary, and the well-known tag constants. |
| `protocol_data` | `ProtocolData` | The Protocol Data payload (tag `0x0210`): OPC/DPC/SI/NI/MP/SLS + user data. |
| `message` | `M3uaMessage` | A whole message (type + parameters); typed builders (`asp_up`, `data`, `duna`, `notify`, `error`, …) and accessors (`protocol_data`, `routing_context`, `affected_point_codes`). |
| `asp` | `Asp`, `AspState`, `AspAction` | The SG-side ASP/AS state machine: fed an inbound message, it updates state and yields the action the transport must take. |
| `error` | `M3uaError` | Typed decode/validation errors. |

## Public API surface

Re-exported at the crate root (`use m3ua::…`):

- **Messages** — `M3uaMessage` with builders for the ASPSM/ASPTM handshake
  (`asp_up`/`asp_up_ack`/`asp_down`/`asp_down_ack`/`asp_active`/`asp_active_ack`/
  `asp_inactive`/`asp_inactive_ack`/`heartbeat`/`heartbeat_ack`), Transfer
  (`data`), SSNM (`duna`/`dava`/`daud`), and MGMT (`error`/`notify`); accessors
  `protocol_data`, `routing_context`, `affected_point_codes`, plus `encode` /
  `decode`.
- **Header** — `CommonHeader`, `MessageClass`, `MessageType`, `VERSION`,
  `SCTP_PPID`.
- **Parameters** — `Parameter` (with `from_u32` / `as_u32` / `wire_length`) and
  the `tags` module of well-known parameter tags.
- **Protocol Data** — `ProtocolData`.
- **State machine** — `Asp`, `AspState` (`Down`/`Inactive`/`Active`),
  `AspAction` (`Reply`/`Deliver`/`Ignore`).
- **Errors** — `M3uaError`.

## Why it's pure

Every type here is transport-independent: encode/decode operate on byte slices,
and the state machine is a plain `match` over the inbound message type. The SCTP
association (multi-streaming, the registered PPID, retransmission, congestion,
the M3UA timers) belongs to whatever runtime owns the socket. That separation is
what keeps the codec portable and unit-testable against RFC-derived vectors.

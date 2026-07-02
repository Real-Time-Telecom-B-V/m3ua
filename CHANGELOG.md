# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.0.0]

First release — an M3UA (RFC 4666) codec and SG-side ASP state machine for the
SS7 stack.

### Added
- **`M3uaMessage`** — whole-message encode / decode with typed builders for the
  ASPSM/ASPTM handshake (`asp_up`/`asp_down`/`asp_active`/`asp_inactive` and
  their ACKs, `heartbeat`/`heartbeat_ack`), Transfer (`data`), SSNM
  (`duna`/`dava`/`daud`), and MGMT (`error`/`notify`); accessors
  `protocol_data`, `routing_context`, and `affected_point_codes`.
- **`CommonHeader`** — the 8-byte common header, with **`MessageClass`** and
  **`MessageType`** covering all six classes (MGMT / Transfer / SSNM / ASPSM /
  ASPTM / RKM) and their `(class, type)` mapping + validation.
- **`Parameter`** and the **`tags`** module — TLV parameters with 4-byte-boundary
  padding and the well-known parameter tags.
- **`ProtocolData`** — the Protocol Data payload (OPC / DPC / SI / NI / MP / SLS
  + user data).
- **`Asp`** / **`AspState`** / **`AspAction`** — the pure SG-side ASP/AS state
  machine (Down → Inactive → Active), driving the handshake and gating `DATA`.
- **`M3uaError`** — typed decode / validation errors.
- Constants **`VERSION`** and **`SCTP_PPID`**.
- Unit, integration, and doctest coverage, including RFC-derived exact-wire-byte
  vectors.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/m3ua/releases/tag/v1.0.0

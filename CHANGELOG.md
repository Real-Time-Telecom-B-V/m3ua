# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.1.0]

### Added
- **SSNM builders** `M3uaMessage::scon` (with the Concerned Destination and
  Congestion Indications parameters of RFC 4666 3.4.4), `dupu` (User/Cause,
  3.4.5) and `drst` (3.4.6). 1.0 had the message types and no way to build
  them short of assembling the parameters by hand.
- **Accessors** for the parameters the management procedures read:
  `routing_contexts` (the parameter is a list; `routing_context` reads its
  first value), `affected_destinations` (mask and point code apart;
  `affected_point_codes` returns the mask octet above the point code, as it
  did), `traffic_mode_type`, `asp_identifier`, `heartbeat_data`, `error_code`,
  `diagnostic_info`, `status`, `congestion_level`, `concerned_destination` and
  `user_cause`. A fixed-size parameter of the wrong length reads as absent;
  `routing_context_octets` and `affected_point_code_octets` give the length of
  the two list parameters, so a caller can tell a wrong length field.
- `M3uaMessage::with_routing_contexts`, to put a list of contexts in an
  acknowledgement or an Error, and `M3uaMessage::notify_status`, which takes
  the Status Type and Status Information apart.
- The value tables **`error_code`** (3.8.1), **`status`** (3.8.2) and
  **`traffic_mode`** (3.7.1) as constants.
- Known-answer tests for all of the above, written from the figures of the
  RFC (`tests/management.rs`).

The Python wheel is unchanged: the additions are in the Rust API only.

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

[1.1.0]: https://github.com/Real-Time-Telecom-B-V/m3ua/releases/tag/v1.1.0
[1.0.0]: https://github.com/Real-Time-Telecom-B-V/m3ua/releases/tag/v1.0.0

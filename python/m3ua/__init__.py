"""m3ua — Rust-backed M3UA (RFC 4666) codec for Python.

M3UA (MTP3 User Adaptation Layer) carries SS7 MTP3-User signalling (SCCP, ISUP,
…) over SCTP, so an SS7 network can ride IP the way it would ride TDM. This
package exposes the same codec the Rust crate (``cargo add m3ua``) ships, from
one source tree / one version.

The wire work (common-header pack/unpack, TLV parameters, the Protocol Data
copy) runs in Rust; Python just builds and inspects messages.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._m3ua import (
    SCTP_PPID,
    TAG_AFFECTED_POINT_CODE,
    TAG_ASP_IDENTIFIER,
    TAG_CORRELATION_ID,
    TAG_DIAGNOSTIC_INFO,
    TAG_ERROR_CODE,
    TAG_HEARTBEAT_DATA,
    TAG_INFO_STRING,
    TAG_NETWORK_APPEARANCE,
    TAG_PROTOCOL_DATA,
    TAG_ROUTING_CONTEXT,
    TAG_STATUS,
    TAG_TRAFFIC_MODE_TYPE,
    VERSION,
    M3uaError,
    M3uaMessage,
    MessageType,
    ProtocolData,
    decode,
    pack_affected_point_codes,
    unpack_affected_point_codes,
)

try:
    __version__ = version("m3ua")
except PackageNotFoundError:  # running from a source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # messages + codec
    "M3uaMessage",
    "ProtocolData",
    "decode",
    "M3uaError",
    # enums
    "MessageType",
    # point-code helpers
    "pack_affected_point_codes",
    "unpack_affected_point_codes",
    # protocol constants
    "VERSION",
    "SCTP_PPID",
    # parameter tags
    "TAG_INFO_STRING",
    "TAG_ROUTING_CONTEXT",
    "TAG_DIAGNOSTIC_INFO",
    "TAG_HEARTBEAT_DATA",
    "TAG_TRAFFIC_MODE_TYPE",
    "TAG_ERROR_CODE",
    "TAG_STATUS",
    "TAG_ASP_IDENTIFIER",
    "TAG_AFFECTED_POINT_CODE",
    "TAG_CORRELATION_ID",
    "TAG_NETWORK_APPEARANCE",
    "TAG_PROTOCOL_DATA",
    "__version__",
]

"""Type stubs for the Rust-backed ``m3ua._m3ua`` extension module."""

from __future__ import annotations

# ── Protocol constants (RFC 4666 §1) ─────────────────────────────────────────
VERSION: int
SCTP_PPID: int

# ── Well-known parameter tags (RFC 4666 §3.2) ────────────────────────────────
TAG_INFO_STRING: int
TAG_ROUTING_CONTEXT: int
TAG_DIAGNOSTIC_INFO: int
TAG_HEARTBEAT_DATA: int
TAG_TRAFFIC_MODE_TYPE: int
TAG_ERROR_CODE: int
TAG_STATUS: int
TAG_ASP_IDENTIFIER: int
TAG_AFFECTED_POINT_CODE: int
TAG_CORRELATION_ID: int
TAG_NETWORK_APPEARANCE: int
TAG_PROTOCOL_DATA: int

class M3uaError(Exception):
    """M3UA protocol / codec error (RFC 4666)."""

class MessageType:
    """M3UA message types across all six classes (RFC 4666 §3.1).

    A PyO3 enum: members compare equal to each other, but it is not a Python
    ``enum.Enum`` (no iteration, no ``.value``).
    """

    Error: MessageType
    Notify: MessageType
    Data: MessageType
    Duna: MessageType
    Dava: MessageType
    Daud: MessageType
    Scon: MessageType
    Dupu: MessageType
    Drst: MessageType
    AspUp: MessageType
    AspDown: MessageType
    Heartbeat: MessageType
    AspUpAck: MessageType
    AspDownAck: MessageType
    HeartbeatAck: MessageType
    AspActive: MessageType
    AspInactive: MessageType
    AspActiveAck: MessageType
    AspInactiveAck: MessageType
    RegReq: MessageType
    RegRsp: MessageType
    DeregReq: MessageType
    DeregRsp: MessageType
    def class_and_type(self) -> tuple[int, int]:
        """The ``(class, type)`` header octet pair for this message type."""
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class ProtocolData:
    """The Protocol Data payload carried by a DATA message: the MTP3 routing
    label (OPC/DPC/SI/NI/MP/SLS) plus the upper-layer user data."""

    opc: int
    dpc: int
    si: int
    ni: int
    mp: int
    sls: int
    user_data: bytes
    def __init__(
        self,
        opc: int,
        dpc: int,
        si: int,
        ni: int,
        mp: int,
        sls: int,
        user_data: bytes = ...,
    ) -> None: ...
    def encode(self) -> bytes:
        """Encode just the Protocol Data payload (no TLV tag/length wrapper)."""

class M3uaMessage:
    """A complete M3UA message. Build one with a typed constructor, ``encode()``
    for the wire form, and :func:`decode` to parse bytes back."""

    @property
    def message_type(self) -> MessageType: ...
    @staticmethod
    def asp_up(asp_id: int | None = ..., info: str | None = ...) -> M3uaMessage: ...
    @staticmethod
    def asp_up_ack(info: str | None = ...) -> M3uaMessage: ...
    @staticmethod
    def asp_down(info: str | None = ...) -> M3uaMessage: ...
    @staticmethod
    def asp_down_ack(info: str | None = ...) -> M3uaMessage: ...
    @staticmethod
    def asp_active(
        traffic_mode: int | None = ..., routing_context: int | None = ...
    ) -> M3uaMessage: ...
    @staticmethod
    def asp_active_ack(
        traffic_mode: int | None = ..., routing_context: int | None = ...
    ) -> M3uaMessage: ...
    @staticmethod
    def asp_inactive(routing_context: int | None = ...) -> M3uaMessage: ...
    @staticmethod
    def asp_inactive_ack(routing_context: int | None = ...) -> M3uaMessage: ...
    @staticmethod
    def heartbeat(data: bytes | None = ...) -> M3uaMessage: ...
    @staticmethod
    def heartbeat_ack(data: bytes | None = ...) -> M3uaMessage: ...
    @staticmethod
    def data(
        protocol_data: ProtocolData,
        *,
        network_appearance: int | None = ...,
        routing_context: int | None = ...,
        correlation_id: int | None = ...,
    ) -> M3uaMessage: ...
    @staticmethod
    def duna(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> M3uaMessage: ...
    @staticmethod
    def dava(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> M3uaMessage: ...
    @staticmethod
    def daud(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> M3uaMessage: ...
    @staticmethod
    def error(
        error_code: int,
        *,
        routing_context: int | None = ...,
        diagnostic_info: bytes | None = ...,
    ) -> M3uaMessage: ...
    @staticmethod
    def notify(
        status: int, *, asp_id: int | None = ..., routing_context: int | None = ...
    ) -> M3uaMessage: ...
    def routing_context(self) -> int | None:
        """The Routing Context value, if present."""
    def affected_point_codes(self) -> list[int]:
        """The affected point codes in an SSNM message (DUNA/DAVA/DAUD/…)."""
    def protocol_data(self) -> ProtocolData:
        """The Protocol Data from a DATA message. Raises ``M3uaError`` if absent."""
    def parameter_tags(self) -> list[int]:
        """The parameter tags present on this message, in wire order."""
    def encode(self) -> bytes:
        """Encode the complete M3UA message (common header + TLV parameters)."""

def decode(data: bytes) -> M3uaMessage:
    """Decode a complete M3UA message into an :class:`M3uaMessage`."""

def pack_affected_point_codes(pcs: list[int]) -> bytes:
    """Pack point codes into the on-wire Affected Point Code value (4 octets each)."""

def unpack_affected_point_codes(data: bytes) -> list[int]:
    """Unpack an Affected Point Code value (4 octets each) into point codes."""

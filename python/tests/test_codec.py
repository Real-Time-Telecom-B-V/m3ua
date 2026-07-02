"""Codec parity / round-trip tests for the m3ua wheel.

These exercise the same Rust codec the crate ships, through the Python surface:
``encode`` must match the RFC 4666 wire form, ``decode`` must recover the type
and fields, and re-encoding must reproduce the exact bytes.
"""

from __future__ import annotations

import pytest

import m3ua

# RFC 4666 wire form of an ASP-UP with no parameters: version 1, reserved 0,
# class 3 (ASPSM), type 1 (ASP-UP), length 8 (header only).
GOLDEN_ASPUP = bytes.fromhex("0100030100000008")


def test_constants() -> None:
    assert m3ua.VERSION == 1
    assert m3ua.SCTP_PPID == 3
    # A couple of well-known parameter tags (RFC 4666 §3.2).
    assert m3ua.TAG_ROUTING_CONTEXT == 0x0006
    assert m3ua.TAG_PROTOCOL_DATA == 0x0210
    assert m3ua.TAG_AFFECTED_POINT_CODE == 0x0012


def test_aspup_matches_golden_vector() -> None:
    msg = m3ua.M3uaMessage.asp_up()
    assert msg.encode() == GOLDEN_ASPUP
    assert msg.message_type == m3ua.MessageType.AspUp


def test_message_type_class_and_type() -> None:
    assert m3ua.MessageType.Data.class_and_type() == (1, 1)
    assert m3ua.MessageType.AspUp.class_and_type() == (3, 1)
    assert m3ua.MessageType.Duna.class_and_type() == (2, 1)


def test_decode_golden_aspup() -> None:
    msg = m3ua.decode(GOLDEN_ASPUP)
    assert isinstance(msg, m3ua.M3uaMessage)
    assert msg.message_type == m3ua.MessageType.AspUp
    assert msg.parameter_tags() == []


def test_aspup_with_params_round_trip() -> None:
    msg = m3ua.M3uaMessage.asp_up(asp_id=1, info="node-a")
    wire = msg.encode()
    decoded = m3ua.decode(wire)
    assert decoded.message_type == m3ua.MessageType.AspUp
    assert m3ua.TAG_ASP_IDENTIFIER in decoded.parameter_tags()
    assert m3ua.TAG_INFO_STRING in decoded.parameter_tags()
    assert decoded.encode() == wire


def test_data_round_trip() -> None:
    user_data = bytes([0x09, 0x01, 0x03]) + bytes(range(32))
    pd = m3ua.ProtocolData(
        opc=0x00112233, dpc=0x00445566, si=3, ni=2, mp=0, sls=5, user_data=user_data
    )
    msg = m3ua.M3uaMessage.data(pd, routing_context=42)
    wire = msg.encode()

    decoded = m3ua.decode(wire)
    assert decoded.message_type == m3ua.MessageType.Data
    assert decoded.routing_context() == 42

    dpd = decoded.protocol_data()
    assert dpd.opc == 0x00112233
    assert dpd.dpc == 0x00445566
    assert dpd.si == 3
    assert dpd.ni == 2
    assert dpd.mp == 0
    assert dpd.sls == 5
    assert dpd.user_data == user_data

    # Re-encoding reproduces the exact bytes.
    assert decoded.encode() == wire


def test_protocol_data_default_user_data() -> None:
    pd = m3ua.ProtocolData(opc=1, dpc=2, si=3, ni=0, mp=0, sls=0)
    assert pd.user_data == b""
    msg = m3ua.M3uaMessage.data(pd)
    assert m3ua.decode(msg.encode()).protocol_data().user_data == b""


def test_duna_round_trip_and_affected_point_codes() -> None:
    pcs = [0x00001000, 0x00001001, 0x00001002]
    msg = m3ua.M3uaMessage.duna(pcs, routing_context=42)
    wire = msg.encode()
    decoded = m3ua.decode(wire)
    assert decoded.message_type == m3ua.MessageType.Duna
    assert decoded.affected_point_codes() == pcs
    assert decoded.routing_context() == 42
    assert decoded.encode() == wire


@pytest.mark.parametrize(
    "builder,expected_type",
    [
        (lambda: m3ua.M3uaMessage.asp_up_ack(), m3ua.MessageType.AspUpAck),
        (lambda: m3ua.M3uaMessage.asp_down(), m3ua.MessageType.AspDown),
        (lambda: m3ua.M3uaMessage.asp_down_ack(), m3ua.MessageType.AspDownAck),
        (lambda: m3ua.M3uaMessage.asp_active(), m3ua.MessageType.AspActive),
        (lambda: m3ua.M3uaMessage.asp_active_ack(), m3ua.MessageType.AspActiveAck),
        (lambda: m3ua.M3uaMessage.asp_inactive(), m3ua.MessageType.AspInactive),
        (lambda: m3ua.M3uaMessage.asp_inactive_ack(), m3ua.MessageType.AspInactiveAck),
        (lambda: m3ua.M3uaMessage.heartbeat(), m3ua.MessageType.Heartbeat),
        (lambda: m3ua.M3uaMessage.heartbeat_ack(), m3ua.MessageType.HeartbeatAck),
        (lambda: m3ua.M3uaMessage.dava([1, 2]), m3ua.MessageType.Dava),
        (lambda: m3ua.M3uaMessage.daud([3]), m3ua.MessageType.Daud),
        (lambda: m3ua.M3uaMessage.error(0x01), m3ua.MessageType.Error),
        (lambda: m3ua.M3uaMessage.notify(0), m3ua.MessageType.Notify),
    ],
)
def test_all_builders_round_trip(builder, expected_type) -> None:
    msg = builder()
    assert msg.message_type == expected_type
    wire = msg.encode()
    decoded = m3ua.decode(wire)
    assert decoded.message_type == expected_type
    assert decoded.encode() == wire


def test_heartbeat_data_survives() -> None:
    msg = m3ua.M3uaMessage.heartbeat(data=b"ping-1234")
    decoded = m3ua.decode(msg.encode())
    assert decoded.message_type == m3ua.MessageType.Heartbeat
    assert m3ua.TAG_HEARTBEAT_DATA in decoded.parameter_tags()


def test_point_code_helpers_round_trip() -> None:
    pcs = [1, 0x00ABCDEF, 0x00FFFFFF]
    packed = m3ua.pack_affected_point_codes(pcs)
    assert len(packed) == 4 * len(pcs)
    assert m3ua.unpack_affected_point_codes(packed) == pcs


def test_protocol_data_missing_raises() -> None:
    # A NTFY carries no Protocol Data parameter.
    msg = m3ua.M3uaMessage.notify(0)
    with pytest.raises(m3ua.M3uaError):
        msg.protocol_data()


def test_decode_rejects_truncated() -> None:
    with pytest.raises(m3ua.M3uaError):
        m3ua.decode(b"\x01\x00\x03")


def test_decode_rejects_bad_version() -> None:
    bad = bytearray(GOLDEN_ASPUP)
    bad[0] = 9
    with pytest.raises(m3ua.M3uaError):
        m3ua.decode(bytes(bad))


def test_decode_rejects_unknown_type() -> None:
    # class 3, type 9 is not a defined (class, type) pair.
    bad = bytes.fromhex("0100030900000008")
    with pytest.raises(m3ua.M3uaError):
        m3ua.decode(bad)

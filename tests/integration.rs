//! Integration tests — M3UA message encoding with known byte patterns.

use m3ua::*;

/// Verify ASPUP message has correct wire format.
#[test]
fn aspup_wire_format() {
    let msg = M3uaMessage::asp_up(None, None);
    let bytes = msg.encode();

    // Header: version=1, reserved=0, class=3 (ASPSM), type=1 (ASPUP), length=8
    assert_eq!(bytes[0], 1); // version
    assert_eq!(bytes[1], 0); // reserved
    assert_eq!(bytes[2], 3); // class ASPSM
    assert_eq!(bytes[3], 1); // type ASPUP
    assert_eq!(
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        8
    ); // length
}

/// Verify ASPUP ACK wire format.
#[test]
fn aspup_ack_wire_format() {
    let msg = M3uaMessage::asp_up_ack(None);
    let bytes = msg.encode();

    assert_eq!(bytes[2], 3); // class ASPSM
    assert_eq!(bytes[3], 4); // type ASPUP_ACK
}

/// Verify ASPAC with traffic mode and routing context.
#[test]
fn aspac_with_params() {
    let msg = M3uaMessage::asp_active(Some(2), Some(100)); // Override mode, RC=100
    let bytes = msg.encode();

    assert_eq!(bytes[2], 4); // class ASPTM
    assert_eq!(bytes[3], 1); // type ASPAC

    let decoded = M3uaMessage::decode(&bytes).unwrap();
    assert_eq!(decoded.routing_context(), Some(100));

    let tm = parameter::find_parameter(&decoded.parameters, tags::TRAFFIC_MODE_TYPE);
    assert_eq!(tm.unwrap().as_u32(), Some(2)); // Override
}

/// DATA message with Protocol Data — verify TLV encoding.
#[test]
fn data_protocol_data_encoding() {
    let pd = ProtocolData::new(
        100,
        200,
        3,                      // SI = SCCP
        2,                      // NI = National
        0,                      // MP
        5,                      // SLS
        vec![0x09, 0x00, 0x03], // SCCP UDT stub
    );
    let msg = M3uaMessage::data(Some(1), Some(42), pd, Some(999));
    let bytes = msg.encode();

    assert_eq!(bytes[2], 1); // class Transfer
    assert_eq!(bytes[3], 1); // type DATA

    let decoded = M3uaMessage::decode(&bytes).unwrap();
    let decoded_pd = decoded.protocol_data().unwrap();
    assert_eq!(decoded_pd.opc, 100);
    assert_eq!(decoded_pd.dpc, 200);
    assert_eq!(decoded_pd.si, 3);
    assert_eq!(decoded_pd.ni, 2);
    assert_eq!(decoded_pd.sls, 5);
    assert_eq!(decoded_pd.user_data, vec![0x09, 0x00, 0x03]);

    // Verify optional params
    assert_eq!(decoded.routing_context(), Some(42));

    let na = parameter::find_parameter(&decoded.parameters, tags::NETWORK_APPEARANCE);
    assert_eq!(na.unwrap().as_u32(), Some(1));

    let ci = parameter::find_parameter(&decoded.parameters, tags::CORRELATION_ID);
    assert_eq!(ci.unwrap().as_u32(), Some(999));
}

/// DUNA with multiple affected point codes.
#[test]
fn duna_multiple_pcs() {
    let msg = M3uaMessage::duna(Some(1), vec![100, 200, 300]);
    let bytes = msg.encode();
    let decoded = M3uaMessage::decode(&bytes).unwrap();

    assert_eq!(decoded.message_type, MessageType::Duna);
    let apc = parameter::find_parameter(&decoded.parameters, tags::AFFECTED_POINT_CODE).unwrap();
    // 3 PCs × 4 bytes each
    assert_eq!(apc.value.len(), 12);
}

/// ERR message with error code and diagnostic.
#[test]
fn error_message() {
    let diag = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let msg = M3uaMessage::error(0x04, Some(1), Some(diag.clone()));
    let bytes = msg.encode();
    let decoded = M3uaMessage::decode(&bytes).unwrap();

    assert_eq!(decoded.message_type, MessageType::Error);

    let ec = parameter::find_parameter(&decoded.parameters, tags::ERROR_CODE).unwrap();
    assert_eq!(ec.as_u32(), Some(0x04));

    let di = parameter::find_parameter(&decoded.parameters, tags::DIAGNOSTIC_INFO).unwrap();
    assert_eq!(di.value, diag);
}

/// NTFY message.
#[test]
fn notify_message() {
    // Status type 1 (AS state change), info 3 (AS-Active)
    let status = (1u32 << 16) | 3;
    let msg = M3uaMessage::notify(status, Some(42), Some(1));
    let bytes = msg.encode();
    let decoded = M3uaMessage::decode(&bytes).unwrap();

    assert_eq!(decoded.message_type, MessageType::Notify);
    let st = parameter::find_parameter(&decoded.parameters, tags::STATUS).unwrap();
    assert_eq!(st.as_u32(), Some(status));
}

/// M3UA ASPUP wire bytes: verify exact encoding matches spec.
/// Per RFC 4666: version=1, reserved=0, class=3 (ASPSM), type=1 (ASPUP)
#[test]
fn aspup_exact_wire_bytes() {
    let msg = M3uaMessage::asp_up(None, None);
    let bytes = msg.encode();
    // Exact 8 bytes: 01 00 03 01 00 00 00 08
    assert_eq!(bytes, vec![0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08]);
}

/// M3UA ASPDN wire bytes.
#[test]
fn aspdn_exact_wire_bytes() {
    let msg = M3uaMessage::asp_down(None);
    let bytes = msg.encode();
    assert_eq!(bytes, vec![0x01, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08]);
}

/// M3UA BEAT with data — verify heartbeat data preserved.
#[test]
fn beat_with_data_wire() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let msg = M3uaMessage::heartbeat(Some(data.clone()));
    let bytes = msg.encode();

    // Decode and verify heartbeat data is preserved
    let decoded = M3uaMessage::decode(&bytes).unwrap();
    let hb_param = parameter::find_parameter(&decoded.parameters, tags::HEARTBEAT_DATA).unwrap();
    assert_eq!(hb_param.value, data);

    // Verify BEAT ACK echoes the same data
    let ack = M3uaMessage::heartbeat_ack(Some(data.clone()));
    let ack_bytes = ack.encode();
    let decoded_ack = M3uaMessage::decode(&ack_bytes).unwrap();
    let ack_data =
        parameter::find_parameter(&decoded_ack.parameters, tags::HEARTBEAT_DATA).unwrap();
    assert_eq!(ack_data.value, data);
}

/// TLV parameter padding — odd-length value gets padded to 4-byte boundary.
#[test]
fn parameter_padding_alignment() {
    let param = Parameter::new(0x1234, vec![1, 2, 3]); // 3 bytes → pad to 4
    let encoded = param.encode();
    assert_eq!(encoded.len(), 8); // 4 header + 3 value + 1 pad
    assert_eq!(encoded.len() % 4, 0); // 4-byte aligned

    let param2 = Parameter::new(0x1234, vec![1, 2, 3, 4, 5]); // 5 bytes → pad to 8
    let encoded2 = param2.encode();
    assert_eq!(encoded2.len(), 12); // 4 header + 5 value + 3 pad
    assert_eq!(encoded2.len() % 4, 0);
}

/// DAVA / DAUD round-trip and their affected-point-code accessor.
#[test]
fn dava_daud_affected_point_codes() {
    for msg in [
        M3uaMessage::dava(Some(7), vec![0x0000_0201, 0x0000_0202]),
        M3uaMessage::daud(Some(7), vec![0x0000_0201, 0x0000_0202]),
    ] {
        let decoded = M3uaMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.routing_context(), Some(7));
        assert_eq!(
            decoded.affected_point_codes(),
            vec![0x0000_0201, 0x0000_0202]
        );
    }
}

/// ASP-INACTIVE and its ACK round-trip, preserving the routing context.
#[test]
fn asp_inactive_round_trip() {
    let msg = M3uaMessage::asp_inactive(Some(100));
    let decoded = M3uaMessage::decode(&msg.encode()).unwrap();
    assert_eq!(decoded.message_type, MessageType::AspInactive);
    assert_eq!(decoded.routing_context(), Some(100));

    let ack = M3uaMessage::asp_inactive_ack(Some(100));
    let decoded_ack = M3uaMessage::decode(&ack.encode()).unwrap();
    assert_eq!(decoded_ack.message_type, MessageType::AspInactiveAck);
    assert_eq!(decoded_ack.routing_context(), Some(100));
}

/// Message-class / message-type mapping validation via the header decoder.
#[test]
fn header_rejects_unknown_class_and_type() {
    // Unknown class 0x08 (only 0..=4 and 9 are defined).
    let unknown_class = [0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x08];
    assert!(M3uaMessage::decode(&unknown_class).is_err());

    // Known class (ASPSM=3) but undefined type 0x09.
    let unknown_type = [0x01, 0x00, 0x03, 0x09, 0x00, 0x00, 0x00, 0x08];
    assert!(M3uaMessage::decode(&unknown_type).is_err());
}

/// Decoding a truncated message (fewer than the 8 header bytes) errors cleanly.
#[test]
fn decode_truncated_message() {
    assert!(M3uaMessage::decode(&[0x01, 0x00, 0x03]).is_err());
}

/// A DATA accessor on a message lacking Protocol Data reports the missing tag.
#[test]
fn missing_protocol_data_is_reported() {
    // ASP-UP carries no Protocol Data parameter.
    let msg = M3uaMessage::asp_up(None, None);
    assert!(msg.protocol_data().is_err());
}

/// A parameter whose declared length is below the 4-byte minimum is rejected.
#[test]
fn parameter_invalid_length_rejected() {
    // tag=0x0006, length=0x0002 (illegal: < 4).
    let bad = [0x00, 0x06, 0x00, 0x02];
    assert!(Parameter::decode(&bad).is_err());
}

/// A parameter whose declared length runs past the buffer is rejected.
#[test]
fn parameter_length_past_buffer_rejected() {
    // tag=0x0006, length=0x0010 (16) but only 4 bytes present.
    let bad = [0x00, 0x06, 0x00, 0x10];
    assert!(Parameter::decode(&bad).is_err());
}

/// `wire_length` reports the padded on-wire size.
#[test]
fn parameter_wire_length_matches_encoding() {
    let p = Parameter::new(tags::INFO_STRING, b"abc".to_vec()); // 3 → pad to 4
    assert_eq!(p.wire_length(), p.encode().len());
    assert_eq!(p.wire_length(), 8);
}

//! Integration tests — M3UA message encoding with known byte patterns.

use m3ua::*;

/// Verify ASPUP message has correct wire format.
#[test]
fn aspup_wire_format() {
    let msg = M3uaMessage::asp_up(None, None);
    let bytes = msg.encode();

    // Header: version=1, reserved=0, class=3 (ASPSM), type=1 (ASPUP), length=8
    assert_eq!(bytes[0], 1);  // version
    assert_eq!(bytes[1], 0);  // reserved
    assert_eq!(bytes[2], 3);  // class ASPSM
    assert_eq!(bytes[3], 1);  // type ASPUP
    assert_eq!(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 8); // length
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
        100, 200,
        3,   // SI = SCCP
        2,   // NI = National
        0,   // MP
        5,   // SLS
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
    let ack_data = parameter::find_parameter(&decoded_ack.parameters, tags::HEARTBEAT_DATA).unwrap();
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

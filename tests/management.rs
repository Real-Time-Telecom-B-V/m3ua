//! Known-answer tests for the management side of M3UA: the messages and
//! parameters of RFC 4666 3.4 (SSNM), 3.7 (ASPTM) and 3.8 (MGMT).
//!
//! Every octet string here is written out by hand from the figure of the
//! clause named beside it, never produced by the encoder under test: the
//! builders are compared with it, and the accessors read it.

use m3ua::{error_code, status, traffic_mode, M3uaMessage, MessageType};

/// The common header of 3.1: version 1, reserved, class, type, length.
fn header(class: u8, kind: u8, length: u32) -> Vec<u8> {
    let mut out = vec![0x01, 0x00, class, kind];
    out.extend_from_slice(&length.to_be_bytes());
    out
}

fn message(class: u8, kind: u8, parameters: &[u8]) -> Vec<u8> {
    let mut out = header(class, kind, 8 + parameters.len() as u32);
    out.extend_from_slice(parameters);
    out
}

#[test]
fn scon_is_the_figure_of_3_4_4() {
    // Routing Context 100, Affected PC 2000 (mask 0), Concerned DPC 3000,
    // Congestion Level 2.
    let wire = message(
        2,
        4,
        &[
            0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, // Routing Context
            0x00, 0x12, 0x00, 0x08, 0x00, 0x00, 0x07, 0xD0, // Affected Point Code
            0x02, 0x06, 0x00, 0x08, 0x00, 0x00, 0x0B, 0xB8, // Concerned Destination
            0x02, 0x05, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, // Congestion Indications
        ],
    );
    let built = M3uaMessage::scon(Some(100), vec![2000], Some(3000), Some(2));
    assert_eq!(built.encode(), wire);

    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.message_type, MessageType::Scon);
    assert_eq!(read.routing_contexts(), [100]);
    assert_eq!(read.affected_destinations(), [(0, 2000)]);
    assert_eq!(read.concerned_destination(), Some(3000));
    assert_eq!(read.congestion_level(), Some(2));
}

#[test]
fn scon_without_the_optional_parameters() {
    // "For MTP congestion methods without multiple congestion levels (e.g.,
    // the ITU international method) the parameter is not included."
    let wire = message(2, 4, &[0x00, 0x12, 0x00, 0x08, 0x00, 0x00, 0x07, 0xD0]);
    assert_eq!(
        M3uaMessage::scon(None, vec![2000], None, None).encode(),
        wire
    );
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.concerned_destination(), None);
    assert_eq!(read.congestion_level(), None);
    assert!(read.routing_contexts().is_empty());
}

#[test]
fn dupu_is_the_figure_of_3_4_5() {
    // Affected PC 2000, cause 1 (unequipped remote user), user 3 (SCCP).
    let wire = message(
        2,
        5,
        &[
            0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, // Routing Context
            0x00, 0x12, 0x00, 0x08, 0x00, 0x00, 0x07, 0xD0, // Affected Point Code
            0x02, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0x03, // User/Cause
        ],
    );
    assert_eq!(M3uaMessage::dupu(Some(100), 2000, 1, 3).encode(), wire);
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.message_type, MessageType::Dupu);
    assert_eq!(read.user_cause(), Some((1, 3)));
    assert_eq!(read.affected_destinations(), [(0, 2000)]);
}

#[test]
fn drst_has_the_parameters_of_duna() {
    // 3.4.6: "The format and description of the ... parameters are the same
    // as for the DUNA message". Two affected point codes.
    let wire = message(
        2,
        6,
        &[
            0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, // Routing Context
            0x00, 0x12, 0x00, 0x0C, 0x00, 0x00, 0x07, 0xD0, // Affected PC 2000
            0x00, 0x00, 0x08, 0x98, // Affected PC 2200
        ],
    );
    assert_eq!(
        M3uaMessage::drst(Some(100), vec![2000, 2200]).encode(),
        wire
    );
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.message_type, MessageType::Drst);
    assert_eq!(read.affected_destinations(), [(0, 2000), (0, 2200)]);
}

#[test]
fn an_affected_point_code_has_a_mask_octet() {
    // 3.4.1: "| Mask | Affected PC 1 |". A mask of 3 over point code 2000.
    let wire = message(2, 1, &[0x00, 0x12, 0x00, 0x08, 0x03, 0x00, 0x07, 0xD0]);
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.affected_destinations(), [(3, 2000)]);
    // The older accessor keeps the mask in the top octet.
    assert_eq!(read.affected_point_codes(), [0x0300_07D0]);
    // A parameter that is not a whole number of entries yields the whole ones.
    let odd = message(
        2,
        1,
        &[
            0x00, 0x12, 0x00, 0x0A, 0x00, 0x00, 0x07, 0xD0, 0x00, 0x01, 0x00, 0x00,
        ],
    );
    let read = M3uaMessage::decode(&odd).unwrap();
    assert_eq!(read.affected_destinations(), [(0, 2000)]);
    assert_eq!(read.affected_point_code_octets(), Some(6));
}

#[test]
fn notify_is_the_figure_of_3_8_2() {
    // AS-State_Change (1), AS-ACTIVE (3), Routing Context 100.
    let wire = message(
        0,
        1,
        &[
            0x00, 0x0D, 0x00, 0x08, 0x00, 0x01, 0x00, 0x03, // Status
            0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, // Routing Context
        ],
    );
    let built =
        M3uaMessage::notify_status(status::AS_STATE_CHANGE, status::AS_ACTIVE, None, Some(100));
    assert_eq!(built.encode(), wire);
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.status(), Some((1, 3)));
    assert_eq!(read.asp_identifier(), None);

    // Other (2), Alternate ASP Active (2), ASP Identifier 7.
    let wire = message(
        0,
        1,
        &[
            0x00, 0x0D, 0x00, 0x08, 0x00, 0x02, 0x00, 0x02, // Status
            0x00, 0x11, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07, // ASP Identifier
            0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, // Routing Context
        ],
    );
    let built = M3uaMessage::notify_status(
        status::OTHER,
        status::ALTERNATE_ASP_ACTIVE,
        Some(7),
        Some(100),
    );
    assert_eq!(built.encode(), wire);
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.status(), Some((2, 2)));
    assert_eq!(read.asp_identifier(), Some(7));
}

#[test]
fn the_status_values_are_those_of_3_8_2() {
    assert_eq!((status::AS_STATE_CHANGE, status::OTHER), (1, 2));
    assert_eq!(
        (status::AS_INACTIVE, status::AS_ACTIVE, status::AS_PENDING),
        (2, 3, 4)
    );
    assert_eq!(
        (
            status::INSUFFICIENT_ASP_RESOURCES,
            status::ALTERNATE_ASP_ACTIVE,
            status::ASP_FAILURE
        ),
        (1, 2, 3)
    );
}

#[test]
fn error_is_the_figure_of_3_8_1() {
    // Invalid Routing Context (0x19) naming two contexts, with the offending
    // octets as Diagnostic Information (three of them: one of padding).
    let wire = message(
        0,
        0,
        &[
            0x00, 0x0C, 0x00, 0x08, 0x00, 0x00, 0x00, 0x19, // Error Code
            0x00, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x07, // Routing Context 7
            0x00, 0x00, 0x00, 0x09, // and 9
            0x00, 0x07, 0x00, 0x07, 0xAA, 0xBB, 0xCC, 0x00, // Diagnostic Information
        ],
    );
    let built = M3uaMessage::error(
        error_code::INVALID_ROUTING_CONTEXT,
        None,
        Some(vec![0xAA, 0xBB, 0xCC]),
    )
    .with_routing_contexts(&[7, 9]);
    assert_eq!(built.encode(), wire);
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.message_type, MessageType::Error);
    assert_eq!(read.error_code(), Some(0x19));
    assert_eq!(read.routing_contexts(), [7, 9]);
    assert_eq!(read.diagnostic_info(), Some(&[0xAA, 0xBB, 0xCC][..]));
}

#[test]
fn the_error_codes_are_those_of_3_8_1() {
    let table = [
        (error_code::INVALID_VERSION, 0x01),
        (error_code::UNSUPPORTED_MESSAGE_CLASS, 0x03),
        (error_code::UNSUPPORTED_MESSAGE_TYPE, 0x04),
        (error_code::UNSUPPORTED_TRAFFIC_MODE_TYPE, 0x05),
        (error_code::UNEXPECTED_MESSAGE, 0x06),
        (error_code::PROTOCOL_ERROR, 0x07),
        (error_code::INVALID_STREAM_IDENTIFIER, 0x09),
        (error_code::REFUSED_MANAGEMENT_BLOCKING, 0x0d),
        (error_code::ASP_IDENTIFIER_REQUIRED, 0x0e),
        (error_code::INVALID_ASP_IDENTIFIER, 0x0f),
        (error_code::INVALID_PARAMETER_VALUE, 0x11),
        (error_code::PARAMETER_FIELD_ERROR, 0x12),
        (error_code::UNEXPECTED_PARAMETER, 0x13),
        (error_code::DESTINATION_STATUS_UNKNOWN, 0x14),
        (error_code::INVALID_NETWORK_APPEARANCE, 0x15),
        (error_code::MISSING_PARAMETER, 0x16),
        (error_code::INVALID_ROUTING_CONTEXT, 0x19),
        (error_code::NO_CONFIGURED_AS_FOR_ASP, 0x1a),
    ];
    for (constant, value) in table {
        assert_eq!(constant, value);
    }
}

#[test]
fn asp_active_carries_a_mode_and_a_list_of_contexts() {
    // 3.7.1: Traffic Mode Type 1 (Override), Routing Contexts 100 and 200.
    let wire = message(
        4,
        1,
        &[
            0x00, 0x0B, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, // Traffic Mode Type
            0x00, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x64, // Routing Context 100
            0x00, 0x00, 0x00, 0xC8, // and 200
        ],
    );
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.traffic_mode_type(), Some(traffic_mode::OVERRIDE));
    assert_eq!(read.routing_contexts(), [100, 200]);
    // The older accessor reads the first one.
    assert_eq!(read.routing_context(), Some(100));

    let built = M3uaMessage::asp_active(Some(traffic_mode::OVERRIDE), None)
        .with_routing_contexts(&[100, 200]);
    assert_eq!(built.encode(), wire);
    assert_eq!(
        (
            traffic_mode::OVERRIDE,
            traffic_mode::LOADSHARE,
            traffic_mode::BROADCAST
        ),
        (1, 2, 3)
    );
}

#[test]
fn with_routing_contexts_replaces_and_removes() {
    let ack = M3uaMessage::asp_active_ack(Some(2), Some(5)).with_routing_contexts(&[6]);
    assert_eq!(ack.routing_contexts(), [6]);
    assert_eq!(ack.traffic_mode_type(), Some(2));
    let none = ack.with_routing_contexts(&[]);
    assert!(none.routing_contexts().is_empty());
    assert_eq!(none.routing_context(), None);
}

#[test]
fn heartbeat_data_and_asp_identifier_are_read_back() {
    // 3.5.5: Heartbeat Data of five octets, three of padding.
    let wire = message(
        3,
        3,
        &[
            0x00, 0x09, 0x00, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x00,
        ],
    );
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.heartbeat_data(), Some(&[1, 2, 3, 4, 5][..]));
    assert_eq!(M3uaMessage::heartbeat(None).heartbeat_data(), None);

    // 3.5.1: ASP Identifier 7.
    let wire = message(3, 1, &[0x00, 0x11, 0x00, 0x08, 0x00, 0x00, 0x00, 0x07]);
    assert_eq!(
        M3uaMessage::decode(&wire).unwrap().asp_identifier(),
        Some(7)
    );
}

#[test]
fn accessors_do_not_read_a_parameter_that_is_too_short() {
    // Status, Error Code, Traffic Mode Type, User/Cause, Congestion
    // Indications and Concerned Destination of two octets each: syntactically
    // a parameter, not a value.
    for (class, kind, tag) in [
        (0u8, 1u8, 0x000Du16),
        (0, 0, 0x000C),
        (4, 1, 0x000B),
        (2, 5, 0x0204),
        (2, 4, 0x0205),
        (2, 4, 0x0206),
        (3, 1, 0x0011),
    ] {
        let mut parameters = tag.to_be_bytes().to_vec();
        parameters.extend_from_slice(&[0x00, 0x06, 0xFF, 0xFF, 0x00, 0x00]);
        let read = M3uaMessage::decode(&message(class, kind, &parameters)).unwrap();
        assert_eq!(read.status(), None);
        assert_eq!(read.error_code(), None);
        assert_eq!(read.traffic_mode_type(), None);
        assert_eq!(read.user_cause(), None);
        assert_eq!(read.congestion_level(), None);
        assert_eq!(read.concerned_destination(), None);
        assert_eq!(read.asp_identifier(), None);
    }
    // A Routing Context of six octets has one whole context.
    let wire = message(
        4,
        1,
        &[
            0x00, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00,
        ],
    );
    let read = M3uaMessage::decode(&wire).unwrap();
    assert_eq!(read.routing_contexts(), [100]);
    assert_eq!(read.routing_context_octets(), Some(6));
}

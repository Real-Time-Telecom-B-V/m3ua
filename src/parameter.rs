use std::fmt;

use crate::error::M3uaError;

/// Well-known M3UA parameter tags (RFC 4666 Section 3.2).
pub mod tags {
    /// Info String (common) — a human-readable diagnostic string.
    pub const INFO_STRING: u16 = 0x0004;
    /// Routing Context — identifies the Application Server / routing key.
    pub const ROUTING_CONTEXT: u16 = 0x0006;
    /// Diagnostic Information (common) — carried in ERR / NTFY.
    pub const DIAGNOSTIC_INFO: u16 = 0x0007;
    /// Heartbeat Data — opaque data echoed in BEAT / BEAT-ACK.
    pub const HEARTBEAT_DATA: u16 = 0x0009;
    /// Traffic Mode Type — Override / Loadshare / Broadcast.
    pub const TRAFFIC_MODE_TYPE: u16 = 0x000B;
    /// Error Code — carried in ERR.
    pub const ERROR_CODE: u16 = 0x000C;
    /// Status — status type + status information, carried in NTFY.
    pub const STATUS: u16 = 0x000D;
    /// ASP Identifier — a unique value identifying the ASP.
    pub const ASP_IDENTIFIER: u16 = 0x0011;
    /// Affected Point Code — one or more affected point codes (SSNM).
    pub const AFFECTED_POINT_CODE: u16 = 0x0012;
    /// Correlation Id — correlates DATA messages during a changeover.
    pub const CORRELATION_ID: u16 = 0x0013;
    /// Network Appearance — distinguishes SS7 network contexts at the SG.
    pub const NETWORK_APPEARANCE: u16 = 0x0200;
    /// User / Cause — the unavailable user part and cause (DUPU).
    pub const USER_CAUSE: u16 = 0x0204;
    /// Congestion Indications — congestion level (SCON).
    pub const CONGESTION_INDICATIONS: u16 = 0x0205;
    /// Concerned Destination — the point code concerned by a DUPU.
    pub const CONCERNED_DESTINATION: u16 = 0x0206;
    /// Routing Key — the routing key registered via RKM.
    pub const ROUTING_KEY: u16 = 0x0207;
    /// Registration Result — the result of a REG-REQ.
    pub const REGISTRATION_RESULT: u16 = 0x0208;
    /// Deregistration Result — the result of a DEREG-REQ.
    pub const DEREGISTRATION_RESULT: u16 = 0x0209;
    /// Local Routing Key Identifier — an ASP-local routing-key handle.
    pub const LOCAL_ROUTING_KEY_ID: u16 = 0x020A;
    /// Destination Point Code — part of a routing key.
    pub const DESTINATION_POINT_CODE: u16 = 0x020B;
    /// Service Indicators — the SIs matched by a routing key.
    pub const SERVICE_INDICATORS: u16 = 0x020C;
    /// Originating Point Code List — OPCs matched by a routing key.
    pub const ORIGINATING_POINT_CODE_LIST: u16 = 0x020E;
    /// Protocol Data — the MTP3-User payload carried by DATA (see [`ProtocolData`](crate::ProtocolData)).
    pub const PROTOCOL_DATA: u16 = 0x0210;
    /// Registration Status — per-routing-key status in a REG-RSP.
    pub const REGISTRATION_STATUS: u16 = 0x0212;
    /// Deregistration Status — per-routing-context status in a DEREG-RSP.
    pub const DEREGISTRATION_STATUS: u16 = 0x0213;
}

/// A TLV (Tag-Length-Value) parameter.
///
/// M3UA parameters are encoded as:
/// ```ignore
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Parameter Tag        |       Parameter Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                       Parameter Value                         /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length includes the 4-byte tag+length header.
/// Value is padded to a 4-byte boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// The parameter tag (see the [`tags`] module for well-known values).
    pub tag: u16,
    /// The parameter value, unpadded (padding is applied only on the wire).
    pub value: Vec<u8>,
}

impl Parameter {
    /// Build a parameter from a tag and its (unpadded) value bytes.
    pub fn new(tag: u16, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Create a parameter with a 4-byte u32 value.
    pub fn from_u32(tag: u16, value: u32) -> Self {
        Self {
            tag,
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// Read the value as a u32 (for 4-byte parameters).
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }

    /// Decode a single parameter from bytes, returning the parameter and bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), M3uaError> {
        if bytes.len() < 4 {
            return Err(M3uaError::TooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }

        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let length = u16::from_be_bytes([bytes[2], bytes[3]]);

        if (length as usize) < 4 {
            return Err(M3uaError::InvalidParameter { tag, length });
        }

        let value_len = (length as usize) - 4;
        if bytes.len() < 4 + value_len {
            return Err(M3uaError::ParameterTooShort {
                tag,
                expected: 4 + value_len,
                actual: bytes.len(),
            });
        }

        let value = bytes[4..4 + value_len].to_vec();

        // Padded length (round up to 4-byte boundary)
        let padded_len = (4 + value_len + 3) & !3;
        let consumed = padded_len.min(bytes.len());

        Ok((Self { tag, value }, consumed))
    }

    /// Encode to bytes with padding.
    pub fn encode(&self) -> Vec<u8> {
        let length = (4 + self.value.len()) as u16;
        let mut buf = Vec::with_capacity((4 + self.value.len() + 3) & !3);
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&self.value);
        // Pad to 4-byte boundary
        let pad = (4 - (self.value.len() % 4)) % 4;
        buf.resize(buf.len() + pad, 0u8);
        buf
    }

    /// The wire length of this parameter (including padding).
    pub fn wire_length(&self) -> usize {
        (4 + self.value.len() + 3) & !3
    }
}

impl fmt::Display for Parameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag_name = match self.tag {
            tags::INFO_STRING => "Info String",
            tags::ROUTING_CONTEXT => "Routing Context",
            tags::DIAGNOSTIC_INFO => "Diagnostic Info",
            tags::HEARTBEAT_DATA => "Heartbeat Data",
            tags::TRAFFIC_MODE_TYPE => "Traffic Mode Type",
            tags::ERROR_CODE => "Error Code",
            tags::STATUS => "Status",
            tags::ASP_IDENTIFIER => "ASP Identifier",
            tags::AFFECTED_POINT_CODE => "Affected Point Code",
            tags::CORRELATION_ID => "Correlation ID",
            tags::NETWORK_APPEARANCE => "Network Appearance",
            tags::PROTOCOL_DATA => "Protocol Data",
            _ => "Unknown",
        };
        write!(
            f,
            "Parameter [tag=0x{:04x} ({}), len={}]",
            self.tag,
            tag_name,
            self.value.len()
        )
    }
}

/// Decode all parameters from a byte slice.
pub fn decode_parameters(bytes: &[u8]) -> Result<Vec<Parameter>, M3uaError> {
    let mut params = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            break; // Not enough for another parameter header
        }
        let (param, consumed) = Parameter::decode(&bytes[offset..])?;
        params.push(param);
        offset += consumed;
    }

    Ok(params)
}

/// Find a parameter by tag in a list.
pub fn find_parameter(params: &[Parameter], tag: u16) -> Option<&Parameter> {
    params.iter().find(|p| p.tag == tag)
}

/// Encode a list of parameters to bytes.
pub fn encode_parameters(params: &[Parameter]) -> Vec<u8> {
    let mut buf = Vec::new();
    for param in params {
        buf.extend_from_slice(&param.encode());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_round_trip() {
        let param = Parameter::new(tags::ROUTING_CONTEXT, vec![0, 0, 0, 1]);
        let encoded = param.encode();
        let (decoded, consumed) = Parameter::decode(&encoded).unwrap();
        assert_eq!(decoded, param);
        assert_eq!(consumed, 8); // 4 header + 4 value, no padding needed
    }

    #[test]
    fn parameter_padding() {
        // Value with 3 bytes needs 1 byte padding
        let param = Parameter::new(0x1234, vec![1, 2, 3]);
        let encoded = param.encode();
        assert_eq!(encoded.len(), 8); // 4 header + 3 value + 1 padding
        assert_eq!(encoded[7], 0); // padding byte
    }

    #[test]
    fn parameter_from_u32() {
        let param = Parameter::from_u32(tags::ROUTING_CONTEXT, 42);
        assert_eq!(param.as_u32(), Some(42));
    }

    #[test]
    fn multiple_parameters() {
        let params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, 1),
            Parameter::new(tags::INFO_STRING, b"hello".to_vec()),
        ];
        let encoded = encode_parameters(&params);
        let decoded = decode_parameters(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tag, tags::ROUTING_CONTEXT);
        assert_eq!(decoded[1].tag, tags::INFO_STRING);
        assert_eq!(decoded[1].value, b"hello");
    }

    #[test]
    fn find_parameter_works() {
        let params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, 1),
            Parameter::from_u32(tags::TRAFFIC_MODE_TYPE, 2),
        ];
        let found = find_parameter(&params, tags::TRAFFIC_MODE_TYPE);
        assert!(found.is_some());
        assert_eq!(found.unwrap().as_u32(), Some(2));

        assert!(find_parameter(&params, tags::ERROR_CODE).is_none());
    }

    #[test]
    fn display() {
        let param = Parameter::from_u32(tags::ROUTING_CONTEXT, 1);
        let s = format!("{param}");
        assert!(s.contains("Routing Context"));
    }

    #[test]
    fn as_u32_none_when_too_short() {
        // A 3-byte value cannot yield a u32.
        let param = Parameter::new(tags::ROUTING_CONTEXT, vec![1, 2, 3]);
        assert_eq!(param.as_u32(), None);
    }

    #[test]
    fn decode_rejects_short_and_bad_length() {
        // Fewer than 4 bytes: no room for a tag+length header.
        assert!(Parameter::decode(&[0x00, 0x06]).is_err());
        // Declared length < 4 is illegal.
        assert!(Parameter::decode(&[0x00, 0x06, 0x00, 0x02]).is_err());
        // Declared length overruns the buffer.
        assert!(Parameter::decode(&[0x00, 0x06, 0x00, 0x10]).is_err());
    }

    #[test]
    fn decode_parameters_ignores_trailing_stray_bytes() {
        // One well-formed 8-byte parameter, then 2 stray bytes (< a header).
        let mut bytes = Parameter::from_u32(tags::ROUTING_CONTEXT, 1).encode();
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let params = decode_parameters(&bytes).unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].as_u32(), Some(1));
    }
}

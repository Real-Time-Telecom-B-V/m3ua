use std::fmt;

use crate::error::M3uaError;
use crate::header::{CommonHeader, MessageType};
use crate::parameter::{self, tags, Parameter};
use crate::protocol_data::ProtocolData;

/// A decoded M3UA message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M3uaMessage {
    pub message_type: MessageType,
    pub parameters: Vec<Parameter>,
}

impl M3uaMessage {
    pub fn new(message_type: MessageType, parameters: Vec<Parameter>) -> Self {
        Self {
            message_type,
            parameters,
        }
    }

    /// Create an ASPUP message (optionally with ASP Identifier and Info String).
    pub fn asp_up(asp_id: Option<u32>, info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(id) = asp_id {
            params.push(Parameter::from_u32(tags::ASP_IDENTIFIER, id));
        }
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(MessageType::AspUp, params)
    }

    /// Create an ASPUP ACK message.
    pub fn asp_up_ack(info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(MessageType::AspUpAck, params)
    }

    /// Create an ASPDN message.
    pub fn asp_down(info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(MessageType::AspDown, params)
    }

    /// Create an ASPDN ACK message.
    pub fn asp_down_ack(info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(MessageType::AspDownAck, params)
    }

    /// Create an ASPAC message (optionally with traffic mode and routing context).
    pub fn asp_active(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(tm) = traffic_mode {
            params.push(Parameter::from_u32(tags::TRAFFIC_MODE_TYPE, tm));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::AspActive, params)
    }

    /// Create an ASPAC ACK message.
    pub fn asp_active_ack(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(tm) = traffic_mode {
            params.push(Parameter::from_u32(tags::TRAFFIC_MODE_TYPE, tm));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::AspActiveAck, params)
    }

    /// Create an ASPIA message.
    pub fn asp_inactive(routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::AspInactive, params)
    }

    /// Create an ASPIA ACK message.
    pub fn asp_inactive_ack(routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::AspInactiveAck, params)
    }

    /// Create a BEAT (heartbeat) message.
    pub fn heartbeat(data: Option<Vec<u8>>) -> Self {
        let mut params = Vec::new();
        if let Some(d) = data {
            params.push(Parameter::new(tags::HEARTBEAT_DATA, d));
        }
        Self::new(MessageType::Heartbeat, params)
    }

    /// Create a BEAT ACK (heartbeat ack) message.
    pub fn heartbeat_ack(data: Option<Vec<u8>>) -> Self {
        let mut params = Vec::new();
        if let Some(d) = data {
            params.push(Parameter::new(tags::HEARTBEAT_DATA, d));
        }
        Self::new(MessageType::HeartbeatAck, params)
    }

    /// Create a DATA message carrying MTP3-User data.
    pub fn data(
        network_appearance: Option<u32>,
        routing_context: Option<u32>,
        protocol_data: ProtocolData,
        correlation_id: Option<u32>,
    ) -> Self {
        let mut params = Vec::new();
        if let Some(na) = network_appearance {
            params.push(Parameter::from_u32(tags::NETWORK_APPEARANCE, na));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        params.push(Parameter::new(tags::PROTOCOL_DATA, protocol_data.encode()));
        if let Some(ci) = correlation_id {
            params.push(Parameter::from_u32(tags::CORRELATION_ID, ci));
        }
        Self::new(MessageType::Data, params)
    }

    /// Create a DUNA (Destination Unavailable) message.
    pub fn duna(routing_context: Option<u32>, affected_pcs: Vec<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        let mut apc_value = Vec::new();
        for pc in &affected_pcs {
            apc_value.extend_from_slice(&pc.to_be_bytes());
        }
        params.push(Parameter::new(tags::AFFECTED_POINT_CODE, apc_value));
        Self::new(MessageType::Duna, params)
    }

    /// Create a DAVA (Destination Available) message.
    pub fn dava(routing_context: Option<u32>, affected_pcs: Vec<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        let mut apc_value = Vec::new();
        for pc in &affected_pcs {
            apc_value.extend_from_slice(&pc.to_be_bytes());
        }
        params.push(Parameter::new(tags::AFFECTED_POINT_CODE, apc_value));
        Self::new(MessageType::Dava, params)
    }

    /// Create an ERR message.
    pub fn error(error_code: u32, routing_context: Option<u32>, diagnostic_info: Option<Vec<u8>>) -> Self {
        let mut params = Vec::new();
        params.push(Parameter::from_u32(tags::ERROR_CODE, error_code));
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        if let Some(di) = diagnostic_info {
            params.push(Parameter::new(tags::DIAGNOSTIC_INFO, di));
        }
        Self::new(MessageType::Error, params)
    }

    /// Create a NTFY (Notify) message.
    pub fn notify(status: u32, asp_id: Option<u32>, routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        params.push(Parameter::from_u32(tags::STATUS, status));
        if let Some(id) = asp_id {
            params.push(Parameter::from_u32(tags::ASP_IDENTIFIER, id));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::Notify, params)
    }

    /// Extract the Protocol Data from a DATA message.
    pub fn protocol_data(&self) -> Result<ProtocolData, M3uaError> {
        let param = parameter::find_parameter(&self.parameters, tags::PROTOCOL_DATA)
            .ok_or(M3uaError::MissingParameter(tags::PROTOCOL_DATA))?;
        ProtocolData::decode(&param.value)
    }

    /// Extract the Routing Context value, if present.
    pub fn routing_context(&self) -> Option<u32> {
        parameter::find_parameter(&self.parameters, tags::ROUTING_CONTEXT)
            .and_then(|p| p.as_u32())
    }

    /// Decode a complete M3UA message from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, M3uaError> {
        let header = CommonHeader::decode(bytes)?;
        let param_bytes = &bytes[CommonHeader::SIZE..];
        let parameters = parameter::decode_parameters(param_bytes)?;

        Ok(Self {
            message_type: header.message_type,
            parameters,
        })
    }

    /// Encode to bytes (header + parameters).
    pub fn encode(&self) -> Vec<u8> {
        let param_bytes = parameter::encode_parameters(&self.parameters);
        let total_len = (CommonHeader::SIZE + param_bytes.len()) as u32;
        let header = CommonHeader::new(self.message_type, total_len);

        let mut buf = Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&param_bytes);
        buf
    }
}

impl fmt::Display for M3uaMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "M3UA {} [{} parameters]",
            self.message_type,
            self.parameters.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aspup_round_trip() {
        let msg = M3uaMessage::asp_up(Some(1), Some("test"));
        let encoded = msg.encode();
        let decoded = M3uaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::AspUp);
        assert_eq!(decoded.parameters.len(), 2);
    }

    #[test]
    fn aspup_no_params() {
        let msg = M3uaMessage::asp_up(None, None);
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 8); // header only
        let decoded = M3uaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::AspUp);
        assert!(decoded.parameters.is_empty());
    }

    #[test]
    fn data_message() {
        let pd = ProtocolData::new(100, 200, 3, 2, 0, 5, vec![0x09, 0x01, 0x03]);
        let msg = M3uaMessage::data(None, Some(1), pd.clone(), None);
        let encoded = msg.encode();
        let decoded = M3uaMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.message_type, MessageType::Data);
        assert_eq!(decoded.routing_context(), Some(1));

        let decoded_pd = decoded.protocol_data().unwrap();
        assert_eq!(decoded_pd, pd);
    }

    #[test]
    fn asp_lifecycle() {
        // Test the full ASP lifecycle message creation
        let aspup = M3uaMessage::asp_up(Some(42), None);
        assert_eq!(aspup.message_type, MessageType::AspUp);

        let aspup_ack = M3uaMessage::asp_up_ack(None);
        assert_eq!(aspup_ack.message_type, MessageType::AspUpAck);

        let aspac = M3uaMessage::asp_active(Some(1), Some(100));
        assert_eq!(aspac.message_type, MessageType::AspActive);

        let aspac_ack = M3uaMessage::asp_active_ack(Some(1), Some(100));
        assert_eq!(aspac_ack.message_type, MessageType::AspActiveAck);
    }

    #[test]
    fn heartbeat_round_trip() {
        let msg = M3uaMessage::heartbeat(Some(vec![1, 2, 3, 4]));
        let encoded = msg.encode();
        let decoded = M3uaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::Heartbeat);

        let hb_data = parameter::find_parameter(&decoded.parameters, tags::HEARTBEAT_DATA);
        assert_eq!(hb_data.unwrap().value, vec![1, 2, 3, 4]);
    }

    #[test]
    fn duna_message() {
        let msg = M3uaMessage::duna(Some(1), vec![100, 200, 300]);
        let encoded = msg.encode();
        let decoded = M3uaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::Duna);

        let apc = parameter::find_parameter(&decoded.parameters, tags::AFFECTED_POINT_CODE).unwrap();
        assert_eq!(apc.value.len(), 12); // 3 point codes × 4 bytes
    }

    #[test]
    fn error_message() {
        let msg = M3uaMessage::error(0x01, Some(1), None);
        let encoded = msg.encode();
        let decoded = M3uaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::Error);
    }

    #[test]
    fn display() {
        let msg = M3uaMessage::asp_up(Some(1), None);
        let s = format!("{msg}");
        assert!(s.contains("ASPUP"));
    }
}

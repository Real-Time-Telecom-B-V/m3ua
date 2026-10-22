use std::fmt;

use crate::error::M3uaError;
use crate::header::{CommonHeader, MessageType};
use crate::parameter::{self, tags, Parameter};
use crate::protocol_data::ProtocolData;

/// A decoded M3UA message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M3uaMessage {
    /// The message type (which implies the message class).
    pub message_type: MessageType,
    /// The message's TLV parameters, in wire order.
    pub parameters: Vec<Parameter>,
}

impl M3uaMessage {
    /// Build a message directly from a type and a list of parameters.
    ///
    /// Prefer the typed builders (`asp_up`, `data`, `duna`, …) where one exists.
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

    /// Create a DAUD (Destination Audit) message — an ASP asking the SG
    /// whether the listed point codes are reachable.
    pub fn daud(routing_context: Option<u32>, affected_pcs: Vec<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        let mut apc_value = Vec::new();
        for pc in &affected_pcs {
            apc_value.extend_from_slice(&pc.to_be_bytes());
        }
        params.push(Parameter::new(tags::AFFECTED_POINT_CODE, apc_value));
        Self::new(MessageType::Daud, params)
    }

    /// Affected point codes carried in an SSNM message (DUNA/DAVA/DAUD/…),
    /// decoded from the Affected Point Code parameter (4 octets each).
    pub fn affected_point_codes(&self) -> Vec<u32> {
        match parameter::find_parameter(&self.parameters, tags::AFFECTED_POINT_CODE) {
            Some(p) => p
                .value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Create a SCON (Signalling Congestion) message (RFC 4666 3.4.4).
    ///
    /// `concerned_destination` is only used from an ASP to an SGP: the point
    /// code of the originator of the message that triggered the SCON.
    /// `congestion_level` is left out for congestion methods without levels
    /// (the ITU international method).
    pub fn scon(
        routing_context: Option<u32>,
        affected_pcs: Vec<u32>,
        concerned_destination: Option<u32>,
        congestion_level: Option<u8>,
    ) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        params.push(Self::affected(&affected_pcs));
        if let Some(pc) = concerned_destination {
            params.push(Parameter::from_u32(
                tags::CONCERNED_DESTINATION,
                pc & 0x00FF_FFFF,
            ));
        }
        if let Some(level) = congestion_level {
            params.push(Parameter::from_u32(
                tags::CONGESTION_INDICATIONS,
                u32::from(level),
            ));
        }
        Self::new(MessageType::Scon, params)
    }

    /// Create a DUPU (Destination User Part Unavailable) message (RFC 4666
    /// 3.4.5): one affected point code, the unavailability cause and the
    /// MTP3-User identity.
    pub fn dupu(routing_context: Option<u32>, affected_pc: u32, cause: u16, user: u16) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        // "the Mask field is not used and only a single Affected DPC is
        // included".
        params.push(Self::affected(&[affected_pc & 0x00FF_FFFF]));
        params.push(Parameter::from_u32(
            tags::USER_CAUSE,
            (u32::from(cause) << 16) | u32::from(user),
        ));
        Self::new(MessageType::Dupu, params)
    }

    /// Create a DRST (Destination Restricted) message (RFC 4666 3.4.6).
    pub fn drst(routing_context: Option<u32>, affected_pcs: Vec<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        params.push(Self::affected(&affected_pcs));
        Self::new(MessageType::Drst, params)
    }

    /// The Affected Point Code parameter for a list of entries, each a mask
    /// octet above a 24-bit point code.
    fn affected(entries: &[u32]) -> Parameter {
        let mut value = Vec::with_capacity(entries.len() * 4);
        for entry in entries {
            value.extend_from_slice(&entry.to_be_bytes());
        }
        Parameter::new(tags::AFFECTED_POINT_CODE, value)
    }

    /// The entries of the Affected Point Code parameter as `(mask, point
    /// code)` (RFC 4666 3.4.1): the mask says how many low bits of the point
    /// code are wildcarded. Octets after the last whole entry are left out;
    /// see [`affected_point_code_octets`](Self::affected_point_code_octets).
    pub fn affected_destinations(&self) -> Vec<(u8, u32)> {
        match parameter::find_parameter(&self.parameters, tags::AFFECTED_POINT_CODE) {
            Some(p) => p
                .value
                .chunks_exact(4)
                .map(|c| (c[0], u32::from_be_bytes([0, c[1], c[2], c[3]])))
                .collect(),
            None => Vec::new(),
        }
    }

    /// The length in octets of the Affected Point Code value, if the
    /// parameter is present. A value that is not a multiple of 4 is a
    /// parameter with a wrong length field.
    pub fn affected_point_code_octets(&self) -> Option<usize> {
        parameter::find_parameter(&self.parameters, tags::AFFECTED_POINT_CODE)
            .map(|p| p.value.len())
    }

    /// Every value of the Routing Context parameter, which is a list (RFC
    /// 4666 3.7.1: "n X 32-bit integers"). Empty when the parameter is absent.
    pub fn routing_contexts(&self) -> Vec<u32> {
        match parameter::find_parameter(&self.parameters, tags::ROUTING_CONTEXT) {
            Some(p) => p
                .value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
            None => Vec::new(),
        }
    }

    /// The length in octets of the Routing Context value, if the parameter is
    /// present. A value that is not a multiple of 4 is a parameter with a
    /// wrong length field.
    pub fn routing_context_octets(&self) -> Option<usize> {
        parameter::find_parameter(&self.parameters, tags::ROUTING_CONTEXT).map(|p| p.value.len())
    }

    /// Replace the Routing Context parameter with this list of contexts, in
    /// the place the parameter had, or after the other parameters when there
    /// was none. An empty list removes the parameter.
    pub fn with_routing_contexts(mut self, contexts: &[u32]) -> Self {
        let place = self
            .parameters
            .iter()
            .position(|p| p.tag == tags::ROUTING_CONTEXT);
        self.parameters.retain(|p| p.tag != tags::ROUTING_CONTEXT);
        if contexts.is_empty() {
            return self;
        }
        let mut value = Vec::with_capacity(contexts.len() * 4);
        for context in contexts {
            value.extend_from_slice(&context.to_be_bytes());
        }
        let parameter = Parameter::new(tags::ROUTING_CONTEXT, value);
        // Diagnostic Information and INFO String stay last, as the figures
        // have them.
        let place = place.unwrap_or_else(|| {
            self.parameters
                .iter()
                .position(|p| p.tag == tags::DIAGNOSTIC_INFO || p.tag == tags::INFO_STRING)
                .unwrap_or(self.parameters.len())
        });
        self.parameters
            .insert(place.min(self.parameters.len()), parameter);
        self
    }

    /// A 32-bit parameter value, when the parameter is present and four
    /// octets long.
    fn exact_u32(&self, tag: u16) -> Option<u32> {
        parameter::find_parameter(&self.parameters, tag)
            .filter(|p| p.value.len() == 4)
            .and_then(|p| p.as_u32())
    }

    /// The Traffic Mode Type of an ASP Active or its acknowledgement (RFC
    /// 4666 3.7.1); see [`traffic_mode`](crate::traffic_mode).
    pub fn traffic_mode_type(&self) -> Option<u32> {
        self.exact_u32(tags::TRAFFIC_MODE_TYPE)
    }

    /// The ASP Identifier of an ASP Up or a Notify (RFC 4666 3.5.1).
    pub fn asp_identifier(&self) -> Option<u32> {
        self.exact_u32(tags::ASP_IDENTIFIER)
    }

    /// The Heartbeat Data of a BEAT or BEAT Ack (RFC 4666 3.5.5), which the
    /// acknowledgement returns unchanged.
    pub fn heartbeat_data(&self) -> Option<&[u8]> {
        parameter::find_parameter(&self.parameters, tags::HEARTBEAT_DATA)
            .map(|p| p.value.as_slice())
    }

    /// The Error Code of an Error message (RFC 4666 3.8.1); see
    /// [`error_code`](crate::error_code).
    pub fn error_code(&self) -> Option<u32> {
        self.exact_u32(tags::ERROR_CODE)
    }

    /// The Diagnostic Information of an Error message (RFC 4666 3.8.1).
    pub fn diagnostic_info(&self) -> Option<&[u8]> {
        parameter::find_parameter(&self.parameters, tags::DIAGNOSTIC_INFO)
            .map(|p| p.value.as_slice())
    }

    /// The Status of a Notify as `(status type, status information)` (RFC
    /// 4666 3.8.2); see [`status`](crate::status).
    pub fn status(&self) -> Option<(u16, u16)> {
        self.exact_u32(tags::STATUS)
            .map(|v| ((v >> 16) as u16, v as u16))
    }

    /// The Congestion Level of a SCON (RFC 4666 3.4.4), 0 to 3.
    pub fn congestion_level(&self) -> Option<u8> {
        self.exact_u32(tags::CONGESTION_INDICATIONS)
            .map(|v| v as u8)
    }

    /// The Concerned Destination of a SCON sent by an ASP (RFC 4666 3.4.4):
    /// the point code the resulting transfer-controlled goes to.
    pub fn concerned_destination(&self) -> Option<u32> {
        self.exact_u32(tags::CONCERNED_DESTINATION)
            .map(|v| v & 0x00FF_FFFF)
    }

    /// The User/Cause of a DUPU as `(cause, user)` (RFC 4666 3.4.5).
    pub fn user_cause(&self) -> Option<(u16, u16)> {
        self.exact_u32(tags::USER_CAUSE)
            .map(|v| ((v >> 16) as u16, v as u16))
    }

    /// Create a NTFY message from the two halves of its Status (RFC 4666
    /// 3.8.2); see [`status`](crate::status).
    pub fn notify_status(
        status_type: u16,
        status_information: u16,
        asp_id: Option<u32>,
        routing_context: Option<u32>,
    ) -> Self {
        Self::notify(
            (u32::from(status_type) << 16) | u32::from(status_information),
            asp_id,
            routing_context,
        )
    }

    /// Create an ERR message.
    pub fn error(
        error_code: u32,
        routing_context: Option<u32>,
        diagnostic_info: Option<Vec<u8>>,
    ) -> Self {
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
        parameter::find_parameter(&self.parameters, tags::ROUTING_CONTEXT).and_then(|p| p.as_u32())
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

        let apc =
            parameter::find_parameter(&decoded.parameters, tags::AFFECTED_POINT_CODE).unwrap();
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

    #[test]
    fn protocol_data_missing_errors() {
        // A NTFY has no Protocol Data parameter.
        let msg = M3uaMessage::notify(0, None, None);
        assert!(matches!(
            msg.protocol_data(),
            Err(M3uaError::MissingParameter(tags::PROTOCOL_DATA))
        ));
    }

    #[test]
    fn affected_point_codes_empty_when_absent() {
        // ASP-UP carries no Affected Point Code parameter.
        let msg = M3uaMessage::asp_up(None, None);
        assert!(msg.affected_point_codes().is_empty());
    }

    #[test]
    fn routing_context_none_when_absent() {
        let msg = M3uaMessage::asp_up(None, None);
        assert_eq!(msg.routing_context(), None);
    }
}

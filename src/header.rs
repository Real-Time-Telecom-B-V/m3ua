use std::fmt;

use crate::error::M3uaError;

/// M3UA protocol version.
pub const VERSION: u8 = 1;
/// SCTP Payload Protocol Identifier for M3UA.
pub const SCTP_PPID: u32 = 3;

/// M3UA Message Classes (RFC 4666 Section 3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageClass {
    /// Management (MGMT) messages.
    Management = 0,
    /// Transfer messages (DATA).
    Transfer = 1,
    /// SS7 Signaling Network Management (SSNM).
    Ssnm = 2,
    /// ASP State Maintenance (ASPSM).
    Aspsm = 3,
    /// ASP Traffic Maintenance (ASPTM).
    Asptm = 4,
    /// Routing Key Management (RKM).
    Rkm = 9,
}

impl MessageClass {
    /// Map the raw message-class octet to a [`MessageClass`].
    ///
    /// Returns [`M3uaError::InvalidMessageClass`] for an unknown value.
    pub fn from_u8(value: u8) -> Result<Self, M3uaError> {
        match value {
            0 => Ok(Self::Management),
            1 => Ok(Self::Transfer),
            2 => Ok(Self::Ssnm),
            3 => Ok(Self::Aspsm),
            4 => Ok(Self::Asptm),
            9 => Ok(Self::Rkm),
            other => Err(M3uaError::InvalidMessageClass(other)),
        }
    }
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Management => write!(f, "MGMT(0)"),
            Self::Transfer => write!(f, "Transfer(1)"),
            Self::Ssnm => write!(f, "SSNM(2)"),
            Self::Aspsm => write!(f, "ASPSM(3)"),
            Self::Asptm => write!(f, "ASPTM(4)"),
            Self::Rkm => write!(f, "RKM(9)"),
        }
    }
}

/// M3UA Message Types per class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    // Management (class 0)
    /// Error (ERR) — MGMT.
    Error,
    /// Notify (NTFY) — MGMT.
    Notify,
    // Transfer (class 1)
    /// Payload data (DATA) — Transfer.
    Data,
    // SSNM (class 2)
    /// Destination Unavailable (DUNA) — SSNM.
    Duna,
    /// Destination Available (DAVA) — SSNM.
    Dava,
    /// Destination State Audit (DAUD) — SSNM.
    Daud,
    /// Signalling Congestion (SCON) — SSNM.
    Scon,
    /// Destination User Part Unavailable (DUPU) — SSNM.
    Dupu,
    /// Destination Restricted (DRST) — SSNM.
    Drst,
    // ASPSM (class 3)
    /// ASP Up (ASP-UP) — ASPSM.
    AspUp,
    /// ASP Down (ASP-DOWN) — ASPSM.
    AspDown,
    /// Heartbeat (BEAT) — ASPSM.
    Heartbeat,
    /// ASP Up Acknowledgement (ASP-UP-ACK) — ASPSM.
    AspUpAck,
    /// ASP Down Acknowledgement (ASP-DOWN-ACK) — ASPSM.
    AspDownAck,
    /// Heartbeat Acknowledgement (BEAT-ACK) — ASPSM.
    HeartbeatAck,
    // ASPTM (class 4)
    /// ASP Active (ASP-ACTIVE) — ASPTM.
    AspActive,
    /// ASP Inactive (ASP-INACTIVE) — ASPTM.
    AspInactive,
    /// ASP Active Acknowledgement (ASP-ACTIVE-ACK) — ASPTM.
    AspActiveAck,
    /// ASP Inactive Acknowledgement (ASP-INACTIVE-ACK) — ASPTM.
    AspInactiveAck,
    // RKM (class 9)
    /// Registration Request (REG-REQ) — RKM.
    RegReq,
    /// Registration Response (REG-RSP) — RKM.
    RegRsp,
    /// Deregistration Request (DEREG-REQ) — RKM.
    DeregReq,
    /// Deregistration Response (DEREG-RSP) — RKM.
    DeregRsp,
}

impl MessageType {
    /// Get (class, type) pair for this message type.
    pub fn class_and_type(&self) -> (u8, u8) {
        match self {
            Self::Error => (0, 0),
            Self::Notify => (0, 1),
            Self::Data => (1, 1),
            Self::Duna => (2, 1),
            Self::Dava => (2, 2),
            Self::Daud => (2, 3),
            Self::Scon => (2, 4),
            Self::Dupu => (2, 5),
            Self::Drst => (2, 6),
            Self::AspUp => (3, 1),
            Self::AspDown => (3, 2),
            Self::Heartbeat => (3, 3),
            Self::AspUpAck => (3, 4),
            Self::AspDownAck => (3, 5),
            Self::HeartbeatAck => (3, 6),
            Self::AspActive => (4, 1),
            Self::AspInactive => (4, 2),
            Self::AspActiveAck => (4, 3),
            Self::AspInactiveAck => (4, 4),
            Self::RegReq => (9, 1),
            Self::RegRsp => (9, 2),
            Self::DeregReq => (9, 3),
            Self::DeregRsp => (9, 4),
        }
    }

    /// Map a raw `(class, type)` header pair to a [`MessageType`].
    ///
    /// Returns [`M3uaError::InvalidMessageType`] for an unknown pair.
    pub fn from_class_type(class: u8, msg_type: u8) -> Result<Self, M3uaError> {
        match (class, msg_type) {
            (0, 0) => Ok(Self::Error),
            (0, 1) => Ok(Self::Notify),
            (1, 1) => Ok(Self::Data),
            (2, 1) => Ok(Self::Duna),
            (2, 2) => Ok(Self::Dava),
            (2, 3) => Ok(Self::Daud),
            (2, 4) => Ok(Self::Scon),
            (2, 5) => Ok(Self::Dupu),
            (2, 6) => Ok(Self::Drst),
            (3, 1) => Ok(Self::AspUp),
            (3, 2) => Ok(Self::AspDown),
            (3, 3) => Ok(Self::Heartbeat),
            (3, 4) => Ok(Self::AspUpAck),
            (3, 5) => Ok(Self::AspDownAck),
            (3, 6) => Ok(Self::HeartbeatAck),
            (4, 1) => Ok(Self::AspActive),
            (4, 2) => Ok(Self::AspInactive),
            (4, 3) => Ok(Self::AspActiveAck),
            (4, 4) => Ok(Self::AspInactiveAck),
            (9, 1) => Ok(Self::RegReq),
            (9, 2) => Ok(Self::RegRsp),
            (9, 3) => Ok(Self::DeregReq),
            (9, 4) => Ok(Self::DeregRsp),
            _ => Err(M3uaError::InvalidMessageType { class, msg_type }),
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Error => "ERR",
            Self::Notify => "NTFY",
            Self::Data => "DATA",
            Self::Duna => "DUNA",
            Self::Dava => "DAVA",
            Self::Daud => "DAUD",
            Self::Scon => "SCON",
            Self::Dupu => "DUPU",
            Self::Drst => "DRST",
            Self::AspUp => "ASPUP",
            Self::AspDown => "ASPDN",
            Self::Heartbeat => "BEAT",
            Self::AspUpAck => "ASPUP_ACK",
            Self::AspDownAck => "ASPDN_ACK",
            Self::HeartbeatAck => "BEAT_ACK",
            Self::AspActive => "ASPAC",
            Self::AspInactive => "ASPIA",
            Self::AspActiveAck => "ASPAC_ACK",
            Self::AspInactiveAck => "ASPIA_ACK",
            Self::RegReq => "REG_REQ",
            Self::RegRsp => "REG_RSP",
            Self::DeregReq => "DEREG_REQ",
            Self::DeregRsp => "DEREG_RSP",
        };
        write!(f, "{name}")
    }
}

/// Common Message Header (8 bytes).
///
/// ```ignore
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Version    |   Reserved    | Message Class | Message Type  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Message Length                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// Protocol version (always [`VERSION`] = 1).
    pub version: u8,
    /// The message type (which implies the message class).
    pub message_type: MessageType,
    /// Total message length in octets, including this 8-byte header.
    pub message_length: u32,
}

impl CommonHeader {
    /// Size of the common header in octets.
    pub const SIZE: usize = 8;

    /// Build a header for the given message type and total message length.
    pub fn new(message_type: MessageType, message_length: u32) -> Self {
        Self {
            version: VERSION,
            message_type,
            message_length,
        }
    }

    /// Decode a common header from the first [`SIZE`](Self::SIZE) bytes.
    ///
    /// Validates the version and the `(class, type)` pair; returns an
    /// [`M3uaError`] on a short buffer, unknown version, or unknown type.
    pub fn decode(bytes: &[u8]) -> Result<Self, M3uaError> {
        if bytes.len() < Self::SIZE {
            return Err(M3uaError::TooShort {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        if version != VERSION {
            return Err(M3uaError::InvalidVersion(version));
        }

        let class = bytes[2];
        let msg_type = bytes[3];
        let message_type = MessageType::from_class_type(class, msg_type)?;

        let message_length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Ok(Self {
            version,
            message_type,
            message_length,
        })
    }

    /// Encode the header to its 8-byte wire representation.
    pub fn encode(&self) -> [u8; 8] {
        let (class, msg_type) = self.message_type.class_and_type();
        let len_bytes = self.message_length.to_be_bytes();
        [
            self.version,
            0, // reserved
            class,
            msg_type,
            len_bytes[0],
            len_bytes[1],
            len_bytes[2],
            len_bytes[3],
        ]
    }
}

impl fmt::Display for CommonHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "M3UA Header [version={}, type={}, length={}]",
            self.version, self.message_type, self.message_length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let hdr = CommonHeader::new(MessageType::Data, 100);
        let encoded = hdr.encode();
        let decoded = CommonHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn header_aspup() {
        let hdr = CommonHeader::new(MessageType::AspUp, 8);
        let encoded = hdr.encode();
        assert_eq!(encoded[0], 1); // version
        assert_eq!(encoded[1], 0); // reserved
        assert_eq!(encoded[2], 3); // class ASPSM
        assert_eq!(encoded[3], 1); // type ASPUP
    }

    #[test]
    fn invalid_version() {
        let bytes = [2, 0, 1, 1, 0, 0, 0, 8];
        assert!(CommonHeader::decode(&bytes).is_err());
    }

    #[test]
    fn invalid_class() {
        let bytes = [1, 0, 99, 1, 0, 0, 0, 8];
        assert!(CommonHeader::decode(&bytes).is_err());
    }

    #[test]
    fn message_type_display() {
        assert_eq!(format!("{}", MessageType::Data), "DATA");
        assert_eq!(format!("{}", MessageType::AspUp), "ASPUP");
        assert_eq!(format!("{}", MessageType::AspActiveAck), "ASPAC_ACK");
    }

    #[test]
    fn message_class_round_trips() {
        for (raw, class) in [
            (0u8, MessageClass::Management),
            (1, MessageClass::Transfer),
            (2, MessageClass::Ssnm),
            (3, MessageClass::Aspsm),
            (4, MessageClass::Asptm),
            (9, MessageClass::Rkm),
        ] {
            assert_eq!(MessageClass::from_u8(raw).unwrap(), class);
        }
        assert!(MessageClass::from_u8(7).is_err());
    }

    #[test]
    fn message_type_class_type_round_trips() {
        // Every variant maps to a (class, type) that maps back to itself.
        for mt in [
            MessageType::Error,
            MessageType::Notify,
            MessageType::Data,
            MessageType::Duna,
            MessageType::Dava,
            MessageType::Daud,
            MessageType::Scon,
            MessageType::Dupu,
            MessageType::Drst,
            MessageType::AspUp,
            MessageType::AspDown,
            MessageType::Heartbeat,
            MessageType::AspUpAck,
            MessageType::AspDownAck,
            MessageType::HeartbeatAck,
            MessageType::AspActive,
            MessageType::AspInactive,
            MessageType::AspActiveAck,
            MessageType::AspInactiveAck,
            MessageType::RegReq,
            MessageType::RegRsp,
            MessageType::DeregReq,
            MessageType::DeregRsp,
        ] {
            let (class, ty) = mt.class_and_type();
            assert_eq!(MessageType::from_class_type(class, ty).unwrap(), mt);
        }
        assert!(MessageType::from_class_type(3, 9).is_err());
    }

    #[test]
    fn header_display() {
        let hdr = CommonHeader::new(MessageType::Data, 100);
        let s = format!("{hdr}");
        assert!(s.contains("DATA"));
        assert!(s.contains("length=100"));
    }

    #[test]
    fn decode_too_short() {
        assert!(CommonHeader::decode(&[1, 0, 3]).is_err());
    }
}

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
    Error,
    Notify,
    // Transfer (class 1)
    Data,
    // SSNM (class 2)
    Duna,
    Dava,
    Daud,
    Scon,
    Dupu,
    Drst,
    // ASPSM (class 3)
    AspUp,
    AspDown,
    Heartbeat,
    AspUpAck,
    AspDownAck,
    HeartbeatAck,
    // ASPTM (class 4)
    AspActive,
    AspInactive,
    AspActiveAck,
    AspInactiveAck,
    // RKM (class 9)
    RegReq,
    RegRsp,
    DeregReq,
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
            _ => Err(M3uaError::InvalidMessageType {
                class,
                msg_type,
            }),
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
    pub version: u8,
    pub message_type: MessageType,
    pub message_length: u32,
}

impl CommonHeader {
    pub const SIZE: usize = 8;

    pub fn new(message_type: MessageType, message_length: u32) -> Self {
        Self {
            version: VERSION,
            message_type,
            message_length,
        }
    }

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
}

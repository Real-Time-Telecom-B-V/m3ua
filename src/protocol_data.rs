use std::fmt;

use crate::error::M3uaError;

/// Protocol Data parameter (tag 0x0210) — carries MTP3-User payload.
///
/// ```ignore
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     OPC (Originating Point Code)              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     DPC (Destination Point Code)              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       SI      |       NI      |      MP       |      SLS     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                        User Protocol Data                     /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolData {
    /// Originating Point Code (32-bit, network-dependent).
    pub opc: u32,
    /// Destination Point Code (32-bit, network-dependent).
    pub dpc: u32,
    /// Service Indicator (SI).
    pub si: u8,
    /// Network Indicator (NI).
    pub ni: u8,
    /// Message Priority (MP).
    pub mp: u8,
    /// Signaling Link Selection (SLS).
    pub sls: u8,
    /// Upper-layer user data (SCCP, ISUP, etc.).
    pub user_data: Vec<u8>,
}

impl ProtocolData {
    /// Fixed-header size in octets: OPC(4) + DPC(4) + SI+NI+MP+SLS(4).
    pub const HEADER_SIZE: usize = 12;

    /// Build a Protocol Data payload from its routing label and user data.
    pub fn new(opc: u32, dpc: u32, si: u8, ni: u8, mp: u8, sls: u8, user_data: Vec<u8>) -> Self {
        Self {
            opc,
            dpc,
            si,
            ni,
            mp,
            sls,
            user_data,
        }
    }

    /// Decode from the Protocol Data parameter value (after tag+length).
    pub fn decode(bytes: &[u8]) -> Result<Self, M3uaError> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(M3uaError::TooShort {
                expected: Self::HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let opc = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let dpc = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let si = bytes[8];
        let ni = bytes[9];
        let mp = bytes[10];
        let sls = bytes[11];
        let user_data = bytes[Self::HEADER_SIZE..].to_vec();

        Ok(Self {
            opc,
            dpc,
            si,
            ni,
            mp,
            sls,
            user_data,
        })
    }

    /// Encode to bytes (for use as Parameter value).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.user_data.len());
        buf.extend_from_slice(&self.opc.to_be_bytes());
        buf.extend_from_slice(&self.dpc.to_be_bytes());
        buf.push(self.si);
        buf.push(self.ni);
        buf.push(self.mp);
        buf.push(self.sls);
        buf.extend_from_slice(&self.user_data);
        buf
    }
}

impl fmt::Display for ProtocolData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProtocolData [opc={}, dpc={}, si={}, ni={}, mp={}, sls={}, data_len={}]",
            self.opc,
            self.dpc,
            self.si,
            self.ni,
            self.mp,
            self.sls,
            self.user_data.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pd = ProtocolData::new(100, 200, 3, 2, 0, 5, vec![0x09, 0x01, 0x03]);
        let encoded = pd.encode();
        let decoded = ProtocolData::decode(&encoded).unwrap();
        assert_eq!(decoded, pd);
    }

    #[test]
    fn decode_header_only() {
        let pd = ProtocolData::new(1, 2, 3, 0, 0, 0, vec![]);
        let encoded = pd.encode();
        let decoded = ProtocolData::decode(&encoded).unwrap();
        assert_eq!(decoded.opc, 1);
        assert_eq!(decoded.dpc, 2);
        assert_eq!(decoded.si, 3);
        assert!(decoded.user_data.is_empty());
    }

    #[test]
    fn too_short() {
        assert!(ProtocolData::decode(&[0; 11]).is_err());
    }

    #[test]
    fn display() {
        let pd = ProtocolData::new(100, 200, 3, 2, 0, 5, vec![0; 20]);
        let s = format!("{pd}");
        assert!(s.contains("opc=100"));
        assert!(s.contains("dpc=200"));
        assert!(s.contains("data_len=20"));
    }
}

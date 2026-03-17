//! M3UA (MTP3 User Adaptation Layer) codec per RFC 4666.
//!
//! M3UA is used to transport MTP3-User signaling (e.g., SCCP, ISUP)
//! over IP networks using SCTP as the transport protocol.
//!
//! # Example
//!
//! ```
//! use m3ua::{M3uaMessage, ProtocolData};
//!
//! // Create an ASP Up message
//! let aspup = M3uaMessage::asp_up(Some(1), None);
//! let bytes = aspup.encode();
//! let decoded = M3uaMessage::decode(&bytes).unwrap();
//! assert_eq!(decoded.message_type, m3ua::MessageType::AspUp);
//!
//! // Create a DATA message with SCCP payload
//! let pd = ProtocolData::new(100, 200, 3, 2, 0, 5, vec![0x09, 0x01]);
//! let data = M3uaMessage::data(None, Some(1), pd, None);
//! let bytes = data.encode();
//! ```

pub mod error;
pub mod header;
pub mod message;
pub mod parameter;
pub mod protocol_data;

pub use error::M3uaError;
pub use header::{CommonHeader, MessageClass, MessageType, SCTP_PPID, VERSION};
pub use message::M3uaMessage;
pub use parameter::{tags, Parameter};
pub use protocol_data::ProtocolData;

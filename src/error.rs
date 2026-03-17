/// Errors that can occur during M3UA message processing.
#[derive(Debug, thiserror::Error)]
pub enum M3uaError {
    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid version: expected 1, got {0}")]
    InvalidVersion(u8),

    #[error("invalid message class: {0}")]
    InvalidMessageClass(u8),

    #[error("invalid message type: class={class}, type={msg_type}")]
    InvalidMessageType { class: u8, msg_type: u8 },

    #[error("invalid parameter: tag=0x{tag:04x}, length={length}")]
    InvalidParameter { tag: u16, length: u16 },

    #[error("parameter too short: tag=0x{tag:04x}, expected at least {expected} bytes, got {actual}")]
    ParameterTooShort {
        tag: u16,
        expected: usize,
        actual: usize,
    },

    #[error("missing required parameter: tag=0x{0:04x}")]
    MissingParameter(u16),
}

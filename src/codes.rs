//! The value tables of RFC 4666 for the parameters that carry a code: the
//! Error Code of 3.8.1, the Status of 3.8.2 and the Traffic Mode Type of 3.7.1.

/// Error Code values (RFC 4666 3.8.1). The values the RFC marks "Not Used in
/// M3UA" have no constant.
pub mod error_code {
    /// A message with an unsupported version was received.
    pub const INVALID_VERSION: u32 = 0x01;
    /// A message with an unexpected or unsupported Message Class was received.
    pub const UNSUPPORTED_MESSAGE_CLASS: u32 = 0x03;
    /// A message with an unexpected or unsupported Message Type was received.
    pub const UNSUPPORTED_MESSAGE_TYPE: u32 = 0x04;
    /// An ASP Active with a Traffic Mode Type that is unsupported, or
    /// inconsistent with the mode configured for the Application Server.
    pub const UNSUPPORTED_TRAFFIC_MODE_TYPE: u32 = 0x05;
    /// A defined and recognised message that is not expected in the current
    /// state.
    pub const UNEXPECTED_MESSAGE: u32 = 0x06;
    /// Any protocol anomaly.
    pub const PROTOCOL_ERROR: u32 = 0x07;
    /// A message received on an unexpected SCTP stream.
    pub const INVALID_STREAM_IDENTIFIER: u32 = 0x09;
    /// An ASP Up or ASP Active refused for management reasons.
    pub const REFUSED_MANAGEMENT_BLOCKING: u32 = 0x0d;
    /// An ASP Up without the ASP Identifier the SGP requires.
    pub const ASP_IDENTIFIER_REQUIRED: u32 = 0x0e;
    /// An ASP Up with an ASP Identifier that is not unique.
    pub const INVALID_ASP_IDENTIFIER: u32 = 0x0f;
    /// A parameter with an invalid value.
    pub const INVALID_PARAMETER_VALUE: u32 = 0x11;
    /// A parameter with a wrong length field.
    pub const PARAMETER_FIELD_ERROR: u32 = 0x12;
    /// A message that contains an invalid parameter.
    pub const UNEXPECTED_PARAMETER: u32 = 0x13;
    /// A DAUD about a destination whose status the SG does not provide.
    pub const DESTINATION_STATUS_UNKNOWN: u32 = 0x14;
    /// A message with an unconfigured Network Appearance.
    pub const INVALID_NETWORK_APPEARANCE: u32 = 0x15;
    /// A mandatory parameter, or a conditional one the context requires, was
    /// not included.
    pub const MISSING_PARAMETER: u32 = 0x16;
    /// A message with an unconfigured Routing Context value.
    pub const INVALID_ROUTING_CONTEXT: u32 = 0x19;
    /// A message without a Routing Context where configuration does not say
    /// which Application Servers are meant.
    pub const NO_CONFIGURED_AS_FOR_ASP: u32 = 0x1a;
}

/// Status Type and Status Information values of the Notify message (RFC 4666
/// 3.8.2).
pub mod status {
    /// Status Type: Application Server State Change.
    pub const AS_STATE_CHANGE: u16 = 1;
    /// Status Type: Other.
    pub const OTHER: u16 = 2;

    /// Status Information of [`AS_STATE_CHANGE`]: AS-INACTIVE.
    pub const AS_INACTIVE: u16 = 2;
    /// Status Information of [`AS_STATE_CHANGE`]: AS-ACTIVE.
    pub const AS_ACTIVE: u16 = 3;
    /// Status Information of [`AS_STATE_CHANGE`]: AS-PENDING.
    pub const AS_PENDING: u16 = 4;

    /// Status Information of [`OTHER`]: Insufficient ASP Resources Active in
    /// AS.
    pub const INSUFFICIENT_ASP_RESOURCES: u16 = 1;
    /// Status Information of [`OTHER`]: Alternate ASP Active.
    pub const ALTERNATE_ASP_ACTIVE: u16 = 2;
    /// Status Information of [`OTHER`]: ASP Failure.
    pub const ASP_FAILURE: u16 = 3;
}

/// Traffic Mode Type values (RFC 4666 3.7.1).
pub mod traffic_mode {
    /// The ASP takes over all traffic of the Application Server.
    pub const OVERRIDE: u32 = 1;
    /// The ASP shares the traffic with the other active ASPs.
    pub const LOADSHARE: u32 = 2;
    /// The ASP receives the same messages as every other active ASP.
    pub const BROADCAST: u32 = 3;
}

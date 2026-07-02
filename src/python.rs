//! PyO3 bindings — `pip install m3ua` gives a Rust-backed wheel exposing the
//! **same** M3UA (RFC 4666) codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add m3ua` / crates.io consumers pull zero pyo3. Two entry points share one
//! `add_contents()`:
//! * `#[pymodule] fn _m3ua` — the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)` — mount `m3ua` as a submodule of another
//!   extension, so a host can expose m3ua without a second shared object.
//!
//! The Python surface is a faithful mirror of the codec: [`M3uaMessage`] carries
//! typed constructors for the common messages (`asp_up`, `data`, `duna`, …),
//! `encode()` produces the wire form, and `m3ua.decode(...)` parses it back.
//! [`ProtocolData`] is the MTP3-User payload carried by DATA. The async ASP state
//! machine is not exposed here — the codec surface is self-contained.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::{
    tags, M3uaError as CoreM3uaError, M3uaMessage, MessageType as CoreMessageType,
    ProtocolData as CoreProtocolData, SCTP_PPID, VERSION,
};

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    m3ua,
    M3uaError,
    PyException,
    "M3UA protocol / codec error (RFC 4666)."
);

fn m3ua_err(e: CoreM3uaError) -> PyErr {
    M3uaError::new_err(e.to_string())
}

// ── MessageType (RFC 4666 §3.1) ─────────────────────────────────────────────
/// M3UA message types across all six classes (MGMT / Transfer / SSNM / ASPSM /
/// ASPTM / RKM). Carried on [`M3uaMessage.message_type`](M3uaMessage).
#[pyclass(name = "MessageType", module = "m3ua._m3ua", eq, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PyMessageType {
    Error,
    Notify,
    Data,
    Duna,
    Dava,
    Daud,
    Scon,
    Dupu,
    Drst,
    AspUp,
    AspDown,
    Heartbeat,
    AspUpAck,
    AspDownAck,
    HeartbeatAck,
    AspActive,
    AspInactive,
    AspActiveAck,
    AspInactiveAck,
    RegReq,
    RegRsp,
    DeregReq,
    DeregRsp,
}

impl PyMessageType {
    fn to_core(self) -> CoreMessageType {
        match self {
            PyMessageType::Error => CoreMessageType::Error,
            PyMessageType::Notify => CoreMessageType::Notify,
            PyMessageType::Data => CoreMessageType::Data,
            PyMessageType::Duna => CoreMessageType::Duna,
            PyMessageType::Dava => CoreMessageType::Dava,
            PyMessageType::Daud => CoreMessageType::Daud,
            PyMessageType::Scon => CoreMessageType::Scon,
            PyMessageType::Dupu => CoreMessageType::Dupu,
            PyMessageType::Drst => CoreMessageType::Drst,
            PyMessageType::AspUp => CoreMessageType::AspUp,
            PyMessageType::AspDown => CoreMessageType::AspDown,
            PyMessageType::Heartbeat => CoreMessageType::Heartbeat,
            PyMessageType::AspUpAck => CoreMessageType::AspUpAck,
            PyMessageType::AspDownAck => CoreMessageType::AspDownAck,
            PyMessageType::HeartbeatAck => CoreMessageType::HeartbeatAck,
            PyMessageType::AspActive => CoreMessageType::AspActive,
            PyMessageType::AspInactive => CoreMessageType::AspInactive,
            PyMessageType::AspActiveAck => CoreMessageType::AspActiveAck,
            PyMessageType::AspInactiveAck => CoreMessageType::AspInactiveAck,
            PyMessageType::RegReq => CoreMessageType::RegReq,
            PyMessageType::RegRsp => CoreMessageType::RegRsp,
            PyMessageType::DeregReq => CoreMessageType::DeregReq,
            PyMessageType::DeregRsp => CoreMessageType::DeregRsp,
        }
    }

    fn from_core(t: CoreMessageType) -> Self {
        match t {
            CoreMessageType::Error => PyMessageType::Error,
            CoreMessageType::Notify => PyMessageType::Notify,
            CoreMessageType::Data => PyMessageType::Data,
            CoreMessageType::Duna => PyMessageType::Duna,
            CoreMessageType::Dava => PyMessageType::Dava,
            CoreMessageType::Daud => PyMessageType::Daud,
            CoreMessageType::Scon => PyMessageType::Scon,
            CoreMessageType::Dupu => PyMessageType::Dupu,
            CoreMessageType::Drst => PyMessageType::Drst,
            CoreMessageType::AspUp => PyMessageType::AspUp,
            CoreMessageType::AspDown => PyMessageType::AspDown,
            CoreMessageType::Heartbeat => PyMessageType::Heartbeat,
            CoreMessageType::AspUpAck => PyMessageType::AspUpAck,
            CoreMessageType::AspDownAck => PyMessageType::AspDownAck,
            CoreMessageType::HeartbeatAck => PyMessageType::HeartbeatAck,
            CoreMessageType::AspActive => PyMessageType::AspActive,
            CoreMessageType::AspInactive => PyMessageType::AspInactive,
            CoreMessageType::AspActiveAck => PyMessageType::AspActiveAck,
            CoreMessageType::AspInactiveAck => PyMessageType::AspInactiveAck,
            CoreMessageType::RegReq => PyMessageType::RegReq,
            CoreMessageType::RegRsp => PyMessageType::RegRsp,
            CoreMessageType::DeregReq => PyMessageType::DeregReq,
            CoreMessageType::DeregRsp => PyMessageType::DeregRsp,
        }
    }
}

#[pymethods]
impl PyMessageType {
    /// The `(class, type)` header octet pair for this message type.
    fn class_and_type(&self) -> (u8, u8) {
        self.to_core().class_and_type()
    }

    fn __repr__(&self) -> String {
        format!("MessageType.{}", self.to_core())
    }
}

// ── ProtocolData (RFC 4666 §3.3.1) ──────────────────────────────────────────
/// The Protocol Data payload carried by a DATA message: the MTP3 routing label
/// (OPC/DPC/SI/NI/MP/SLS) plus the upper-layer user data (SCCP, ISUP, …).
#[pyclass(name = "ProtocolData", module = "m3ua._m3ua", from_py_object)]
#[derive(Clone)]
pub struct PyProtocolData {
    /// Originating Point Code (32-bit, network-dependent).
    #[pyo3(get)]
    pub opc: u32,
    /// Destination Point Code (32-bit, network-dependent).
    #[pyo3(get)]
    pub dpc: u32,
    /// Service Indicator (SI).
    #[pyo3(get)]
    pub si: u8,
    /// Network Indicator (NI).
    #[pyo3(get)]
    pub ni: u8,
    /// Message Priority (MP).
    #[pyo3(get)]
    pub mp: u8,
    /// Signaling Link Selection (SLS).
    #[pyo3(get)]
    pub sls: u8,
    user_data: Vec<u8>,
}

impl PyProtocolData {
    fn to_core(&self) -> CoreProtocolData {
        CoreProtocolData::new(
            self.opc,
            self.dpc,
            self.si,
            self.ni,
            self.mp,
            self.sls,
            self.user_data.clone(),
        )
    }

    fn from_core(pd: CoreProtocolData) -> Self {
        Self {
            opc: pd.opc,
            dpc: pd.dpc,
            si: pd.si,
            ni: pd.ni,
            mp: pd.mp,
            sls: pd.sls,
            user_data: pd.user_data,
        }
    }
}

#[pymethods]
impl PyProtocolData {
    #[new]
    #[pyo3(signature = (opc, dpc, si, ni, mp, sls, user_data = Vec::new()))]
    fn new(opc: u32, dpc: u32, si: u8, ni: u8, mp: u8, sls: u8, user_data: Vec<u8>) -> Self {
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

    /// The upper-layer user data (SCCP, ISUP, …) as `bytes`.
    #[getter]
    fn user_data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.user_data)
    }

    /// Encode just the Protocol Data payload (no TLV tag/length wrapper).
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.to_core().encode())
    }

    fn __repr__(&self) -> String {
        format!(
            "ProtocolData(opc={}, dpc={}, si={}, ni={}, mp={}, sls={}, user_data_len={})",
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

// ── M3uaMessage ─────────────────────────────────────────────────────────────
/// A complete M3UA message. Build one with a typed constructor
/// (`M3uaMessage.asp_up(...)`, `.data(...)`, `.duna(...)`, …), call `encode()`
/// for the wire form, and `m3ua.decode(...)` to parse bytes back.
#[pyclass(name = "M3uaMessage", module = "m3ua._m3ua", skip_from_py_object)]
#[derive(Clone)]
pub struct PyM3uaMessage {
    inner: M3uaMessage,
}

impl PyM3uaMessage {
    fn wrap(inner: M3uaMessage) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyM3uaMessage {
    /// The message type (which implies the message class).
    #[getter]
    fn message_type(&self) -> PyMessageType {
        PyMessageType::from_core(self.inner.message_type)
    }

    /// Create an ASP-UP message (optionally with ASP Identifier and Info String).
    #[staticmethod]
    #[pyo3(signature = (asp_id = None, info = None))]
    fn asp_up(asp_id: Option<u32>, info: Option<&str>) -> Self {
        Self::wrap(M3uaMessage::asp_up(asp_id, info))
    }

    /// Create an ASP-UP-ACK message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_up_ack(info: Option<&str>) -> Self {
        Self::wrap(M3uaMessage::asp_up_ack(info))
    }

    /// Create an ASP-DOWN message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_down(info: Option<&str>) -> Self {
        Self::wrap(M3uaMessage::asp_down(info))
    }

    /// Create an ASP-DOWN-ACK message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_down_ack(info: Option<&str>) -> Self {
        Self::wrap(M3uaMessage::asp_down_ack(info))
    }

    /// Create an ASP-ACTIVE message (optional traffic mode + routing context).
    #[staticmethod]
    #[pyo3(signature = (traffic_mode = None, routing_context = None))]
    fn asp_active(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::asp_active(traffic_mode, routing_context))
    }

    /// Create an ASP-ACTIVE-ACK message.
    #[staticmethod]
    #[pyo3(signature = (traffic_mode = None, routing_context = None))]
    fn asp_active_ack(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::asp_active_ack(traffic_mode, routing_context))
    }

    /// Create an ASP-INACTIVE message.
    #[staticmethod]
    #[pyo3(signature = (routing_context = None))]
    fn asp_inactive(routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::asp_inactive(routing_context))
    }

    /// Create an ASP-INACTIVE-ACK message.
    #[staticmethod]
    #[pyo3(signature = (routing_context = None))]
    fn asp_inactive_ack(routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::asp_inactive_ack(routing_context))
    }

    /// Create a BEAT (heartbeat) message.
    #[staticmethod]
    #[pyo3(signature = (data = None))]
    fn heartbeat(data: Option<Vec<u8>>) -> Self {
        Self::wrap(M3uaMessage::heartbeat(data))
    }

    /// Create a BEAT-ACK (heartbeat ack) message.
    #[staticmethod]
    #[pyo3(signature = (data = None))]
    fn heartbeat_ack(data: Option<Vec<u8>>) -> Self {
        Self::wrap(M3uaMessage::heartbeat_ack(data))
    }

    /// Create a DATA message carrying MTP3-User data.
    #[staticmethod]
    #[pyo3(signature = (protocol_data, *, network_appearance = None, routing_context = None, correlation_id = None))]
    fn data(
        protocol_data: PyProtocolData,
        network_appearance: Option<u32>,
        routing_context: Option<u32>,
        correlation_id: Option<u32>,
    ) -> Self {
        Self::wrap(M3uaMessage::data(
            network_appearance,
            routing_context,
            protocol_data.to_core(),
            correlation_id,
        ))
    }

    /// Create a DUNA (Destination Unavailable) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn duna(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::duna(routing_context, affected_pcs))
    }

    /// Create a DAVA (Destination Available) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn dava(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::dava(routing_context, affected_pcs))
    }

    /// Create a DAUD (Destination Audit) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn daud(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::daud(routing_context, affected_pcs))
    }

    /// Create an ERR message.
    #[staticmethod]
    #[pyo3(signature = (error_code, *, routing_context = None, diagnostic_info = None))]
    fn error(
        error_code: u32,
        routing_context: Option<u32>,
        diagnostic_info: Option<Vec<u8>>,
    ) -> Self {
        Self::wrap(M3uaMessage::error(
            error_code,
            routing_context,
            diagnostic_info,
        ))
    }

    /// Create a NTFY (Notify) message.
    #[staticmethod]
    #[pyo3(signature = (status, *, asp_id = None, routing_context = None))]
    fn notify(status: u32, asp_id: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(M3uaMessage::notify(status, asp_id, routing_context))
    }

    /// The Routing Context value, if present.
    fn routing_context(&self) -> Option<u32> {
        self.inner.routing_context()
    }

    /// The affected point codes carried in an SSNM message (DUNA/DAVA/DAUD/…).
    fn affected_point_codes(&self) -> Vec<u32> {
        self.inner.affected_point_codes()
    }

    /// The Protocol Data from a DATA message. Raises `M3uaError` if absent.
    fn protocol_data(&self) -> PyResult<PyProtocolData> {
        self.inner
            .protocol_data()
            .map(PyProtocolData::from_core)
            .map_err(m3ua_err)
    }

    /// The parameter tags present on this message, in wire order.
    fn parameter_tags(&self) -> Vec<u16> {
        self.inner.parameters.iter().map(|p| p.tag).collect()
    }

    /// Encode the complete M3UA message (common header + TLV parameters).
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    fn __repr__(&self) -> String {
        format!(
            "M3uaMessage(type={}, parameters={})",
            self.inner.message_type,
            self.inner.parameters.len()
        )
    }
}

// ── Point-code helpers ──────────────────────────────────────────────────────
/// Pack a list of affected point codes into the on-wire Affected Point Code
/// value (4 octets each, big-endian) — the layout used by SSNM messages.
#[pyfunction]
fn pack_affected_point_codes<'py>(py: Python<'py>, pcs: Vec<u32>) -> Bound<'py, PyBytes> {
    let mut buf = Vec::with_capacity(pcs.len() * 4);
    for pc in pcs {
        buf.extend_from_slice(&pc.to_be_bytes());
    }
    PyBytes::new(py, &buf)
}

/// Unpack an Affected Point Code value (4 octets each) back into point codes.
#[pyfunction]
fn unpack_affected_point_codes(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

// ── decode() ────────────────────────────────────────────────────────────────
/// Decode a complete M3UA message, returning an [`M3uaMessage`].
#[pyfunction]
fn decode(data: &[u8]) -> PyResult<PyM3uaMessage> {
    let msg = M3uaMessage::decode(data).map_err(m3ua_err)?;
    Ok(PyM3uaMessage::wrap(msg))
}

// ── Module wiring ───────────────────────────────────────────────────────────
fn add_tag(m: &Bound<'_, PyModule>, name: &str, tag: u16) -> PyResult<()> {
    m.add(name, tag)
}

fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("M3uaError", m.py().get_type::<M3uaError>())?;
    m.add_class::<PyMessageType>()?;
    m.add_class::<PyProtocolData>()?;
    m.add_class::<PyM3uaMessage>()?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(pack_affected_point_codes, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_affected_point_codes, m)?)?;

    // Protocol constants (RFC 4666 §1).
    m.add("VERSION", VERSION)?;
    m.add("SCTP_PPID", SCTP_PPID)?;

    // Well-known parameter tags (RFC 4666 §3.2), prefixed `TAG_`.
    add_tag(m, "TAG_INFO_STRING", tags::INFO_STRING)?;
    add_tag(m, "TAG_ROUTING_CONTEXT", tags::ROUTING_CONTEXT)?;
    add_tag(m, "TAG_DIAGNOSTIC_INFO", tags::DIAGNOSTIC_INFO)?;
    add_tag(m, "TAG_HEARTBEAT_DATA", tags::HEARTBEAT_DATA)?;
    add_tag(m, "TAG_TRAFFIC_MODE_TYPE", tags::TRAFFIC_MODE_TYPE)?;
    add_tag(m, "TAG_ERROR_CODE", tags::ERROR_CODE)?;
    add_tag(m, "TAG_STATUS", tags::STATUS)?;
    add_tag(m, "TAG_ASP_IDENTIFIER", tags::ASP_IDENTIFIER)?;
    add_tag(m, "TAG_AFFECTED_POINT_CODE", tags::AFFECTED_POINT_CODE)?;
    add_tag(m, "TAG_CORRELATION_ID", tags::CORRELATION_ID)?;
    add_tag(m, "TAG_NETWORK_APPEARANCE", tags::NETWORK_APPEARANCE)?;
    add_tag(m, "TAG_PROTOCOL_DATA", tags::PROTOCOL_DATA)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "m3ua._m3ua"`).
#[pymodule]
fn _m3ua(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build an `m3ua` submodule and attach it to `parent`,
/// so a host extension can expose m3ua without a second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "m3ua")?;
    add_contents(&m)?;
    parent.setattr("m3ua", &m)?;
    Ok(())
}

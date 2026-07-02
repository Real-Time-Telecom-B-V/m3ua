//! M3UA ASP/AS state machine (SG side).
//!
//! The STP acts as the Signalling Gateway (SG): peer Application Server
//! Processes (ASPs) connect over SCTP and run the ASPSM/ASPTM handshake
//! (ASP-UP → ASP-UP-ACK, ASP-ACTIVE → ASP-ACTIVE-ACK) before exchanging
//! DATA (RFC 4666 §4–5). This is the **pure** state machine: given an inbound
//! message it updates state and yields the action the transport must take.
//! No sockets here, so it is unit-tested in isolation; a transport layer that
//! owns the SCTP association drives it.

use crate::{M3uaMessage, MessageType};

/// ASP traffic-maintenance state from the SG's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AspState {
    /// No relationship yet (pre ASP-UP).
    #[default]
    Down,
    /// ASP is UP (ASPSM complete) but not carrying traffic.
    Inactive,
    /// ASP is ACTIVE — DATA may flow.
    Active,
}

/// What the transport should do in response to an inbound message.
#[derive(Debug, Clone)]
pub enum AspAction {
    /// Send this M3UA message back to the peer.
    Reply(M3uaMessage),
    /// A DATA MSU arrived in the Active state — hand it to the router.
    Deliver,
    /// Unexpected / out-of-state message — ignore.
    Ignore,
}

/// The SG-side ASP state machine for one association.
#[derive(Debug, Default)]
pub struct Asp {
    state: AspState,
}

impl Asp {
    /// Create a state machine in the initial [`AspState::Down`] state.
    pub fn new() -> Self {
        Self {
            state: AspState::Down,
        }
    }

    /// The current traffic-maintenance state.
    pub fn state(&self) -> AspState {
        self.state
    }

    /// Drive the state machine with one inbound message, returning the action
    /// the transport should perform.
    pub fn handle(&mut self, msg: &M3uaMessage) -> AspAction {
        match msg.message_type {
            MessageType::AspUp => {
                self.state = AspState::Inactive;
                AspAction::Reply(M3uaMessage::asp_up_ack(None))
            }
            MessageType::AspActive => {
                self.state = AspState::Active;
                AspAction::Reply(M3uaMessage::asp_active_ack(None, msg.routing_context()))
            }
            MessageType::AspInactive => {
                self.state = AspState::Inactive;
                AspAction::Reply(M3uaMessage::asp_inactive_ack(msg.routing_context()))
            }
            MessageType::AspDown => {
                self.state = AspState::Down;
                AspAction::Reply(M3uaMessage::asp_down_ack(None))
            }
            MessageType::Heartbeat => AspAction::Reply(M3uaMessage::heartbeat_ack(None)),
            MessageType::Data if self.state == AspState::Active => AspAction::Deliver,
            _ => AspAction::Ignore,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolData;

    fn is_reply(a: &AspAction, mt: MessageType) -> bool {
        matches!(a, AspAction::Reply(m) if m.message_type == mt)
    }

    #[test]
    fn handshake_progresses_down_inactive_active() {
        let mut asp = Asp::new();
        assert_eq!(asp.state(), AspState::Down);

        let a = asp.handle(&M3uaMessage::asp_up(None, None));
        assert!(is_reply(&a, MessageType::AspUpAck));
        assert_eq!(asp.state(), AspState::Inactive);

        let a = asp.handle(&M3uaMessage::asp_active(None, Some(100)));
        assert!(is_reply(&a, MessageType::AspActiveAck));
        assert_eq!(asp.state(), AspState::Active);
    }

    #[test]
    fn data_delivers_only_when_active() {
        let mut asp = Asp::new();
        let data = M3uaMessage::data(
            None,
            None,
            ProtocolData::new(1, 2, 3, 2, 0, 0, vec![]),
            None,
        );

        // Down → DATA is out of state, ignored.
        assert!(matches!(asp.handle(&data), AspAction::Ignore));

        asp.handle(&M3uaMessage::asp_up(None, None));
        asp.handle(&M3uaMessage::asp_active(None, None));
        assert!(matches!(asp.handle(&data), AspAction::Deliver));
    }

    #[test]
    fn heartbeat_is_acked() {
        let mut asp = Asp::new();
        assert!(is_reply(
            &asp.handle(&M3uaMessage::heartbeat(None)),
            MessageType::HeartbeatAck
        ));
    }

    #[test]
    fn down_returns_to_down() {
        let mut asp = Asp::new();
        asp.handle(&M3uaMessage::asp_up(None, None));
        asp.handle(&M3uaMessage::asp_active(None, None));
        let a = asp.handle(&M3uaMessage::asp_down(None));
        assert!(is_reply(&a, MessageType::AspDownAck));
        assert_eq!(asp.state(), AspState::Down);
    }
}

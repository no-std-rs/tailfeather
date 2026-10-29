//! Bounded actor mailbox with FIFO priority for state transitions.

use heapless::Deque;
use tailfeather::NodeAction;

/// Stateful actions can displace packet traffic but can never be silently lost.
/// Index queues move metadata rather than copying packet buffers on each pop.
pub struct Actions<const N: usize> {
    slots: [Option<NodeAction>; N],
    free: Deque<usize, N>,
    stateful: Deque<usize, N>,
    packets: Deque<usize, N>,
}

impl<const N: usize> Default for Actions<N> {
    fn default() -> Self {
        let mut free = Deque::new();
        for index in 0..N {
            let _ = free.push_back(index);
        }
        Self {
            slots: [const { None }; N],
            free,
            stateful: Deque::new(),
            packets: Deque::new(),
        }
    }
}

impl<const N: usize> Actions<N> {
    pub fn len(&self) -> usize {
        N - self.free.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a stateful action to its caller when capacity is exhausted.
    /// Packet traffic and redundant status notifications may be dropped.
    #[allow(clippy::result_large_err)]
    pub fn push(&mut self, action: NodeAction) -> Result<(), NodeAction> {
        if matches!(action, NodeAction::StatusChanged(_)) {
            return Ok(());
        }
        let packet = droppable(&action);
        let index = if let Some(index) = self.free.pop_front() {
            index
        } else if packet {
            return Ok(());
        } else if let Some(index) = self.packets.pop_front() {
            index
        } else {
            return Err(action);
        };
        self.slots[index] = Some(action);
        let queue = if packet {
            &mut self.packets
        } else {
            &mut self.stateful
        };
        let _ = queue.push_back(index);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<NodeAction> {
        self.pop_packet_if(|_| true)
    }

    /// Stateful work always has priority. A blocked packet retains its FIFO
    /// position while independent packet paths can continue. Scan only indices:
    /// packet ownership stays in its original slot until one is selected.
    pub(crate) fn pop_packet_if(
        &mut self,
        mut ready: impl FnMut(&NodeAction) -> bool,
    ) -> Option<NodeAction> {
        let index = if let Some(index) = self.stateful.pop_front() {
            index
        } else {
            let count = self.packets.len();
            let first = self.packets.pop_front()?;
            if ready(self.slots[first].as_ref().expect("queued action")) {
                first
            } else {
                let _ = self.packets.push_back(first);
                let mut selected = None;
                for _ in 1..count {
                    let index = self.packets.pop_front().expect("original packet count");
                    if selected.is_none()
                        && ready(self.slots[index].as_ref().expect("queued action"))
                    {
                        selected = Some(index);
                    } else {
                        let _ = self.packets.push_back(index);
                    }
                }
                selected?
            }
        };
        let action = self.slots[index].take();
        let _ = self.free.push_back(index);
        action
    }
}

fn droppable(action: &NodeAction) -> bool {
    matches!(
        action,
        NodeAction::DirectTransmit { .. }
            | NodeAction::DeliveredIpv4 { .. }
            | NodeAction::DeliveredIpv6 { .. }
            | NodeAction::Derp(tailfeather::DerpCommand::Send { .. })
    )
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use tailfeather::{DerpCommand, keys::NodePrivate, node::SecretBuffer};

    fn packet(id: u8) -> NodeAction {
        NodeAction::Derp(DerpCommand::Send {
            region: 999,
            peer: NodePrivate::from_bytes([7; 32]).public(),
            packet: SecretBuffer::try_from_slice(&[id]).unwrap(),
        })
    }
    fn id(action: &NodeAction) -> u8 {
        let NodeAction::Derp(DerpCommand::Send { packet, .. }) = action else {
            panic!("expected packet");
        };
        packet.as_slice()[0]
    }

    #[test]
    fn selecting_ready_packets_preserves_every_deferred_position_and_capacity() {
        let mut actions = Actions::<4>::default();
        for sequence in 0..4 {
            actions.push(packet(sequence)).unwrap();
        }
        for _ in 0..8 {
            assert!(actions.pop_packet_if(|_| false).is_none());
            assert_eq!(actions.len(), 4);
        }
        assert_eq!(
            id(&actions.pop_packet_if(|action| id(action) == 2).unwrap()),
            2
        );
        actions.push(packet(4)).unwrap();
        let mut checked = 0;
        assert_eq!(
            id(&actions
                .pop_packet_if(|_| {
                    checked += 1;
                    true
                })
                .unwrap()),
            0
        );
        assert_eq!(checked, 1, "ready FIFO front must remain constant-time");
        assert_eq!(id(&actions.pop().unwrap()), 1);
        assert_eq!(id(&actions.pop().unwrap()), 3);
        assert_eq!(id(&actions.pop().unwrap()), 4);
        assert!(actions.is_empty());
    }

    #[test]
    fn stateful_work_displaces_oldest_packet_and_never_waits_for_readiness() {
        let mut actions = Actions::<3>::default();
        for sequence in 0..3 {
            actions.push(packet(sequence)).unwrap();
        }
        actions
            .push(NodeAction::Derp(DerpCommand::Disconnect { region: 999 }))
            .unwrap();
        assert_eq!(actions.len(), 3);
        assert!(matches!(
            actions.pop_packet_if(|_| false),
            Some(NodeAction::Derp(DerpCommand::Disconnect { region: 999 }))
        ));
        assert_eq!(id(&actions.pop().unwrap()), 1);
        assert_eq!(id(&actions.pop().unwrap()), 2);
        assert!(actions.is_empty());
    }
}

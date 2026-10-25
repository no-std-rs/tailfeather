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
        let index = self
            .stateful
            .pop_front()
            .or_else(|| self.packets.pop_front())?;
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
            | NodeAction::Derp(tailfeather::DerpCommand::Send { .. })
    )
}

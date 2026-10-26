//! Bounded raw uplink progress without blocking the tunnel actor.

use core::cell::Cell;
use core::future::Future;

use embassy_futures::poll_once;
use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
use embassy_net::raw::{PacketMetadata, RawSocket, RecvError};
use embassy_net::{Stack, StaticConfigV4};
use embassy_time::{Duration, Instant, Timer};

/// SLAAC readiness must never substitute for the IPv4 lease used by control
/// and the WireGuard underlay. Return the snapshot, avoiding a second lookup
/// that could race DHCP deconfiguration.
pub(crate) async fn wait_ipv4(stack: Stack<'_>) -> StaticConfigV4 {
    loop {
        if let Some(config) = stack.config_v4() {
            return config;
        }
        Timer::after(Duration::from_millis(50)).await;
    }
}

pub(crate) struct Uplink<'a> {
    socket: RawSocket<'a>,
    enqueued_at: Cell<Option<Instant>>,
}

impl<'a> Uplink<'a> {
    pub(crate) fn new(
        stack: Stack<'a>,
        rx_meta: &'a mut [PacketMetadata],
        rx_buffer: &'a mut [u8],
        tx_meta: &'a mut [PacketMetadata],
        tx_buffer: &'a mut [u8],
    ) -> Self {
        Self {
            socket: RawSocket::new(stack, None, None, rx_meta, rx_buffer, tx_meta, tx_buffer),
            enqueued_at: Cell::new(None),
        }
    }

    /// A single-slot queue gives each newly accepted packet a fresh deadline:
    /// acceptance proves the previous head was dispatched. Yield on contention
    /// so an ordinary cooperative burst can progress, then bound the retry.
    pub(crate) async fn send(&self, packet: &[u8]) -> bool {
        let accepted = if poll_once(self.socket.send(packet)).is_ready() {
            true
        } else {
            yield_now().await;
            matches!(
                select(
                    self.socket.send(packet),
                    Timer::after(Duration::from_millis(25))
                )
                .await,
                Either::First(())
            )
        };
        if accepted {
            self.enqueued_at.set(Some(Instant::now()));
        }
        accepted
    }

    /// smoltcp retains a raw packet indefinitely when neighbor discovery fails.
    /// The caller drops this socket and reborrows its buffers on expiry, which
    /// clears the blocked head while retaining NAT and service state. Three
    /// seconds allow multiple one-second neighbor-discovery retries.
    pub(crate) fn stalled(&mut self) -> bool {
        if poll_once(self.socket.flush()).is_ready() {
            self.enqueued_at.set(None);
            false
        } else {
            self.enqueued_at
                .get()
                .is_some_and(|at| Instant::now() - at >= Duration::from_secs(3))
        }
    }

    pub(crate) fn wait_recv_ready(&self) -> impl Future<Output = ()> + '_ {
        self.socket.wait_recv_ready()
    }

    pub(crate) async fn recv(&self, packet: &mut [u8]) -> Result<usize, RecvError> {
        self.socket.recv(packet).await
    }
}

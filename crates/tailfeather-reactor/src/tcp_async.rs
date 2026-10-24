//! Allocation-free async TCP streams over authenticated inner IPv4 packets.
//!
//! [`Tcp::run`] is one cooperative task. A mesh adapter supplies [`PacketIo`]
//! after applying WireGuard source validation and ingress ACLs. Stream reads,
//! writes and listener changes wake the driver immediately; idle work sleeps
//! until smoltcp's next timer instead of polling at a fixed frequency.

use core::{
    cell::{Cell, RefCell},
    future::poll_fn,
    task::Poll,
};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, signal::Signal};
use heapless::Vec;
use smoltcp::socket::tcp::State;

use crate::{
    exec::{Clock, Either, Reactor},
    tcp::{MTU, NetStack, PacketQueue, TcpHandle, TcpListener},
};

/// Cancellation-safe ingress and backpressured egress for complete inner IPv4 packets.
/// Implementations authenticate and authorize ingress before returning it here.
pub trait PacketIo {
    type Error;
    async fn receive(&self, packet: &mut [u8]) -> Result<usize, Self::Error>;
    async fn send(&self, packet: &[u8]) -> Result<(), Self::Error>;
    /// Override to submit a bounded burst to a userspace ring or batched socket API.
    async fn send_batch<'p>(
        &self,
        packets: impl Iterator<Item = &'p [u8]>,
    ) -> Result<(), Self::Error> {
        for packet in packets {
            self.send(packet).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Reset,
    TimedOut,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "TCP capacity or endpoint unavailable",
            Self::Reset => "TCP connection reset",
            Self::TimedOut => "TCP deadline expired",
        })
    }
}

impl core::error::Error for Error {}

impl embedded_io_async::Error for Error {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        match self {
            Self::Unavailable => embedded_io_async::ErrorKind::Other,
            Self::Reset => embedded_io_async::ErrorKind::ConnectionReset,
            Self::TimedOut => embedded_io_async::ErrorKind::TimedOut,
        }
    }
}

pub struct Tcp<'a, const N: usize, const Q: usize, B: PacketQueue<Q>> {
    stack: RefCell<NetStack<'a, N, Q, B>>,
    changed: Signal<NoopRawMutex, ()>,
    now: Cell<u64>,
    closing: RefCell<Vec<(TcpHandle, u64), N>>,
    running: Cell<bool>,
    stopped: Cell<bool>,
    listeners: Cell<usize>,
    ports: RefCell<Vec<u16, N>>,
    capacity_waiters: RefCell<embassy_sync::waitqueue::MultiWakerRegistration<4>>,
}

impl<'a, const N: usize, const Q: usize, B: PacketQueue<Q>> Tcp<'a, N, Q, B> {
    pub fn new(stack: NetStack<'a, N, Q, B>) -> Self {
        Self {
            stack: RefCell::new(stack),
            changed: Signal::new(),
            now: Cell::new(0),
            closing: RefCell::new(Vec::new()),
            running: Cell::new(false),
            stopped: Cell::new(false),
            listeners: Cell::new(0),
            ports: RefCell::new(Vec::new()),
            capacity_waiters: RefCell::new(embassy_sync::waitqueue::MultiWakerRegistration::new()),
        }
    }

    pub fn set_address(&self, address: core::net::Ipv4Addr, now_ms: u64, seed: u64) {
        self.stack.borrow_mut().set_address(address, now_ms, seed);
        self.changed.signal(());
    }

    pub fn remote_addresses(&self) -> heapless::Vec<core::net::Ipv4Addr, N> {
        self.stack.borrow().remote_addresses()
    }

    /// A single live driver is required. Cancellation aborts sockets and wakes
    /// stream waiters; subsequent I/O reports a reset.
    pub async fn run<C: Clock, I: PacketIo>(
        &self,
        reactor: &Reactor<C>,
        io: &I,
    ) -> Result<core::convert::Infallible, I::Error> {
        assert!(!self.running.replace(true), "one driver per TCP stack");
        self.stopped.set(false);
        struct Guard<'r, 'a, const N: usize, const Q: usize, B: PacketQueue<Q>>(
            &'r Tcp<'a, N, Q, B>,
        );
        impl<const N: usize, const Q: usize, B: PacketQueue<Q>> Drop for Guard<'_, '_, N, Q, B> {
            fn drop(&mut self) {
                self.0.stack.borrow_mut().abort_all();
                self.0.closing.borrow_mut().clear();
                self.0.running.set(false);
                self.0.stopped.set(true);
                self.0.capacity_waiters.borrow_mut().wake();
            }
        }
        let _guard = Guard(self);
        let transmit = async {
            let mut burst = heapless::Vec::<crate::tcp::Packet, 8>::new();
            loop {
                let now = reactor.clock_millis();
                self.now.set(now);
                self.stack.borrow_mut().poll_stack(now);
                for _ in 0..8 {
                    let Some(packet) = self.stack.borrow_mut().take_transmit() else {
                        break;
                    };
                    let _ = burst.push(packet);
                }
                if !burst.is_empty() {
                    io.send_batch(burst.iter().map(|packet| packet.as_slice()))
                        .await?;
                    burst.clear();
                    self.finish_closing(reactor.clock_millis());
                    crate::exec::yield_now().await;
                    continue;
                }
                self.finish_closing(now);
                let closing = self
                    .closing
                    .borrow()
                    .iter()
                    .map(|(_, deadline)| *deadline)
                    .min();
                let deadline = match (self.stack.borrow_mut().deadline(now), closing) {
                    (Some(a), Some(b)) => a.min(b),
                    (Some(a), None) | (None, Some(a)) => a,
                    (None, None) => now.saturating_add(60_000),
                };
                crate::exec::select(self.changed.wait(), reactor.sleep_until(deadline)).await;
            }
            #[allow(unreachable_code)]
            Ok::<core::convert::Infallible, I::Error>(unreachable!())
        };
        let receive = async {
            let mut packet = [0; MTU];
            let mut budget = 0;
            loop {
                let len = io.receive(&mut packet).await?;
                if let Some(packet) = packet.get(..len) {
                    let now = reactor.clock_millis();
                    let mut stack = self.stack.borrow_mut();
                    stack.deliver(packet);
                    stack.poll_stack(now);
                    self.changed.signal(());
                }
                budget += 1;
                if budget == 8 {
                    budget = 0;
                    crate::exec::yield_now().await;
                }
            }
            #[allow(unreachable_code)]
            Ok::<core::convert::Infallible, I::Error>(unreachable!())
        };
        match crate::exec::select(transmit, receive).await {
            Either::First(result) | Either::Second(result) => result,
        }
    }

    fn finish_closing(&self, now: u64) {
        let mut freed = false;
        let mut stack = self.stack.borrow_mut();
        self.closing.borrow_mut().retain(|(handle, deadline)| {
            if let Some(success) = stack.close_outcome(*handle) {
                stack.close_failed |= !success;
                stack.remove(*handle);
                freed = true;
                false
            } else if now >= *deadline {
                stack.close_failed = true;
                stack.remove(*handle);
                freed = true;
                false
            } else {
                true
            }
        });
        drop(stack);
        if freed {
            self.capacity_waiters.borrow_mut().wake();
        }
    }

    pub async fn connect<C: Clock>(
        &self,
        reactor: &Reactor<C>,
        address: core::net::Ipv4Addr,
        port: u16,
        local_port: u16,
    ) -> Result<Stream<'_, 'a, N, Q, B>, Error> {
        let handle = self
            .stack
            .borrow_mut()
            .connect(address, port, local_port)
            .map_err(|_| Error::Unavailable)?;
        let stream = Stream { tcp: self, handle };
        self.changed.signal(());
        reactor
            .timeout(
                90_000,
                poll_fn(|cx| {
                    let mut stack = self.stack.borrow_mut();
                    let Some(socket) = stack.tcp(handle) else {
                        return Poll::Ready(Err(Error::Reset));
                    };
                    match socket.state() {
                        State::Established | State::CloseWait => Poll::Ready(Ok(())),
                        State::SynSent => {
                            socket.register_send_waker(cx.waker());
                            Poll::Pending
                        }
                        _ => Poll::Ready(Err(Error::Reset)),
                    }
                }),
            )
            .await
            .map_err(|_| Error::TimedOut)??;
        Ok(stream)
    }

    pub fn listen(&self, port: u16) -> Result<Listener<'_, 'a, N, Q, B>, Error> {
        if self.listeners.get() >= 4 || self.ports.borrow().contains(&port) {
            return Err(Error::Unavailable);
        }
        let listener = self
            .stack
            .borrow_mut()
            .listen_backlog(port)
            .map_err(|_| Error::Unavailable)?;
        self.changed.signal(());
        self.listeners.set(self.listeners.get() + 1);
        let _ = self.ports.borrow_mut().push(port);
        Ok(Listener {
            tcp: self,
            listener,
        })
    }

    /// Wait for dropped streams' final data and FIN to be acknowledged.
    /// Drop listeners and stop opening connections before draining.
    pub async fn drain<C: Clock>(&self, reactor: &Reactor<C>) -> Result<(), Error> {
        if self.listeners.get() != 0 {
            return Err(Error::Unavailable);
        }
        reactor
            .timeout(15_000, async {
                loop {
                    if self.stack.borrow().drained() {
                        return if core::mem::take(&mut self.stack.borrow_mut().close_failed) {
                            Err(Error::Reset)
                        } else {
                            Ok(())
                        };
                    }
                    reactor.sleep(10).await;
                }
            })
            .await
            .map_err(|_| Error::TimedOut)?
    }
}

pub struct Listener<'r, 'a, const N: usize, const Q: usize, B: PacketQueue<Q>> {
    tcp: &'r Tcp<'a, N, Q, B>,
    listener: TcpListener<N>,
}

impl<'r, 'a, const N: usize, const Q: usize, B: PacketQueue<Q>> Listener<'r, 'a, N, Q, B> {
    pub async fn accept(&mut self) -> Result<Stream<'r, 'a, N, Q, B>, Error> {
        let handle = poll_fn(|cx| {
            if self.tcp.stopped.get() {
                return Poll::Ready(Err(Error::Reset));
            }
            let mut stack = self.tcp.stack.borrow_mut();
            if let Some(handle) = stack.accept_one(&mut self.listener) {
                return Poll::Ready(Ok(handle));
            }
            stack.register_accept_waker(&self.listener, cx.waker());
            self.tcp.capacity_waiters.borrow_mut().register(cx.waker());
            Poll::Pending
        })
        .await?;
        self.tcp.changed.signal(());
        Ok(Stream {
            tcp: self.tcp,
            handle,
        })
    }
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> Drop for Listener<'_, '_, N, Q, B> {
    fn drop(&mut self) {
        self.tcp
            .stack
            .borrow_mut()
            .remove_listener(&mut self.listener);
        self.tcp.listeners.set(self.tcp.listeners.get() - 1);
        self.tcp
            .ports
            .borrow_mut()
            .retain(|port| *port != self.listener.port);
        self.tcp.capacity_waiters.borrow_mut().wake();
        self.tcp.changed.signal(());
    }
}

pub struct Stream<'r, 'a, const N: usize, const Q: usize, B: PacketQueue<Q>> {
    tcp: &'r Tcp<'a, N, Q, B>,
    handle: TcpHandle,
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> Stream<'_, '_, N, Q, B> {
    /// Close only the write direction, preserving responses from the peer.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.tcp
            .stack
            .borrow_mut()
            .tcp(self.handle)
            .ok_or(Error::Reset)?
            .close();
        self.tcp.changed.signal(());
        Ok(())
    }
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> embedded_io_async::ErrorType
    for Stream<'_, '_, N, Q, B>
{
    type Error = Error;
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> embedded_io_async::Read
    for Stream<'_, '_, N, Q, B>
{
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        if output.is_empty() {
            return Ok(0);
        }
        poll_fn(|cx| {
            let mut stack = self.tcp.stack.borrow_mut();
            let Some(socket) = stack.tcp(self.handle) else {
                return Poll::Ready(Err(Error::Reset));
            };
            if socket.can_recv() {
                let result = socket.recv_slice(output).map_err(|_| Error::Reset);
                self.tcp.changed.signal(());
                return Poll::Ready(result);
            }
            if !socket.may_recv() {
                return Poll::Ready(if socket.state() == State::Closed {
                    Err(Error::Reset)
                } else {
                    Ok(0)
                });
            }
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> embedded_io_async::Write
    for Stream<'_, '_, N, Q, B>
{
    async fn write(&mut self, input: &[u8]) -> Result<usize, Error> {
        if input.is_empty() {
            return Ok(0);
        }
        poll_fn(|cx| {
            let mut stack = self.tcp.stack.borrow_mut();
            let Some(socket) = stack.tcp(self.handle) else {
                return Poll::Ready(Err(Error::Reset));
            };
            if !socket.may_send() {
                return Poll::Ready(Err(Error::Reset));
            }
            if socket.can_send() {
                let result = socket.send_slice(input).map_err(|_| Error::Reset);
                self.tcp.changed.signal(());
                return Poll::Ready(result);
            }
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), Error> {
        poll_fn(|cx| {
            let mut stack = self.tcp.stack.borrow_mut();
            let Some(socket) = stack.tcp(self.handle) else {
                return Poll::Ready(Err(Error::Reset));
            };
            if socket.state() == State::Closed {
                return Poll::Ready(Err(Error::Reset));
            }
            if socket.send_queue() == 0 {
                return Poll::Ready(Ok(()));
            }
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl<const N: usize, const Q: usize, B: PacketQueue<Q>> Drop for Stream<'_, '_, N, Q, B> {
    fn drop(&mut self) {
        let mut stack = self.tcp.stack.borrow_mut();
        if let Some(socket) = stack.tcp(self.handle) {
            if matches!(socket.state(), State::SynSent | State::Closed) {
                stack.remove(self.handle);
                self.tcp.capacity_waiters.borrow_mut().wake();
            } else {
                socket.close();
                let _ = self
                    .tcp
                    .closing
                    .borrow_mut()
                    .push((self.handle, self.tcp.now.get().saturating_add(5_000)));
            }
        }
        self.tcp.changed.signal(());
    }
}

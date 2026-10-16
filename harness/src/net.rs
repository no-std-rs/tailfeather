//! Async sockets over the reactor.
//!
//! Deliberately thin. Every one of these is the same three steps: try the
//! syscall, and if it reports `EAGAIN`, await readiness and try again. `rustix`
//! owns the descriptors, so closing is a `Drop` we do not have to write, and
//! addresses are `core::net` types rather than a hand-rolled `sockaddr_in`.

use core::net::{Ipv4Addr, SocketAddrV4};

use rustix::event::PollFlags;
use rustix::fd::{AsRawFd, OwnedFd, RawFd};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, accept_with, bind, connect,
    getpeername, getsockname, ipproto, listen, recvfrom, sendto, socket_with, sockopt,
};

use crate::exec::Reactor;

/// Why a socket operation failed, distinguishing the cases a caller can do
/// something about from the ones it cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    Errno(Errno),
    /// The peer closed the connection.
    Closed,
    /// A datagram arrived from something that is not an IPv4 address, which
    /// this node has no way to reply to.
    NotIpv4,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Errno(e) => write!(f, "errno {}", e.raw_os_error()),
            Self::Closed => f.write_str("connection closed"),
            Self::NotIpv4 => f.write_str("peer is not IPv4"),
        }
    }
}

impl core::error::Error for NetError {}

/// Whether an error means "not ready yet" rather than "failed".
fn would_block(e: Errno) -> bool {
    e == Errno::AGAIN || e == Errno::WOULDBLOCK || e == Errno::INTR
}

fn new_socket(kind: SocketType) -> Result<OwnedFd, NetError> {
    new_socket_with_protocol(kind, None)
}

fn new_socket_with_protocol(
    kind: SocketType,
    protocol: Option<rustix::net::Protocol>,
) -> Result<OwnedFd, NetError> {
    socket_with(
        AddressFamily::INET,
        kind,
        // Always non-blocking: one blocking call would stall the whole
        // single-threaded executor, and everything above expects to be able to
        // wait on several things at once.
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        protocol,
    )
    .map_err(NetError::Errno)
}

/// Transport protocol selected by an IPv4 raw socket.
#[derive(Clone, Copy)]
pub enum RawProtocol {
    Udp,
    Tcp,
}

/// An asynchronous Linux raw IPv4 socket.
///
/// Packets sent and received include their complete IPv4 header. Creation is
/// privileged, but using the socket is otherwise the same readiness-driven,
/// memory-safe interface as the harness's datagram sockets.
pub struct RawIpv4Socket<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> RawIpv4Socket<'r> {
    pub fn bind(
        reactor: &'r Reactor,
        address: Ipv4Addr,
        protocol: RawProtocol,
    ) -> Result<Self, NetError> {
        let protocol = match protocol {
            RawProtocol::Udp => ipproto::UDP,
            RawProtocol::Tcp => ipproto::TCP,
        };
        let fd = new_socket_with_protocol(SocketType::RAW, Some(protocol))?;
        crate::rt::configure_raw_ipv4(fd.as_raw_fd()).map_err(NetError::Errno)?;
        bind(&fd, &SocketAddrV4::new(address, 0)).map_err(NetError::Errno)?;
        Ok(Self { fd, reactor })
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        loop {
            match recvfrom(&self.fd, &mut *buf, RecvFlags::empty()) {
                Ok((len, _truncated, _from)) => return Ok(len),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    pub async fn send(&self, packet: &[u8], destination: Ipv4Addr) -> Result<usize, NetError> {
        let destination = SocketAddrV4::new(destination, 0);
        loop {
            match sendto(&self.fd, packet, SendFlags::empty(), &destination) {
                Ok(len) => return Ok(len),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::OUT).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }
}

fn local_v4(fd: &OwnedFd) -> Result<SocketAddrV4, NetError> {
    getsockname(fd)
        .map_err(NetError::Errno)?
        .try_into()
        .map_err(|_| NetError::NotIpv4)
}

pub struct UdpSocket<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> UdpSocket<'r> {
    pub fn bind(reactor: &'r Reactor, address: Ipv4Addr, port: u16) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::DGRAM)?;
        bind(&fd, &SocketAddrV4::new(address, port)).map_err(NetError::Errno)?;
        Ok(Self { fd, reactor })
    }

    /// The address actually bound, which answers what port the kernel chose
    /// when the caller asked for zero.
    pub fn local_address(&self) -> Result<SocketAddrV4, NetError> {
        local_v4(&self.fd)
    }

    /// Which of this host's addresses would be used to reach `target`.
    ///
    /// A socket bound to `0.0.0.0` knows its port and nothing else, and an
    /// endpoint advertised as `0.0.0.0:41641` is useless to a peer. Connecting a
    /// throwaway datagram socket makes the kernel run its routing table and fill
    /// in the source address it would choose — without sending anything, because
    /// `connect` on UDP only sets a default destination.
    pub fn outbound_address(target: &SocketAddrV4) -> Result<Ipv4Addr, NetError> {
        let fd = new_socket(SocketType::DGRAM)?;
        connect(&fd, target).map_err(NetError::Errno)?;
        Ok(*local_v4(&fd)?.ip())
    }

    /// The address peers on other machines could reach this host at.
    ///
    /// Asking the routing table about the *control server* gives the wrong
    /// answer when the server is on this machine: the route is loopback, and an
    /// endpoint of `127.0.0.1` is one no peer can use. So the question is asked
    /// about a public address instead, which selects whatever the default route
    /// would use. Nothing is sent to it.
    ///
    /// This is not a substitute for STUN — it finds the address on *this* side
    /// of any NAT, and a peer across one still has to learn the translated
    /// address from the pong it sends back.
    pub fn advertisable_address(fallback: &SocketAddrV4) -> Result<Ipv4Addr, NetError> {
        const PUBLIC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443);
        match Self::outbound_address(&PUBLIC) {
            Ok(address) if !address.is_loopback() && !address.is_unspecified() => Ok(address),
            // No default route, or it is loopback: fall back to whatever reaches
            // the control server, which is at least somewhere real.
            _ => Self::outbound_address(fallback),
        }
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), NetError> {
        loop {
            match recvfrom(&self.fd, &mut *buf, RecvFlags::empty()) {
                Ok((len, _truncated, Some(from))) => {
                    let from = from.try_into().map_err(|_| NetError::NotIpv4)?;
                    return Ok((len, from));
                }
                // A datagram socket that has been `connect`ed reports no
                // address. This one never is, so this cannot happen — but
                // guessing an address would be worse than saying so.
                Ok((_, _, None)) => return Err(NetError::NotIpv4),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    /// Inspect the next datagram without removing it from the socket queue.
    pub async fn peek_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), NetError> {
        loop {
            match recvfrom(&self.fd, &mut *buf, RecvFlags::PEEK) {
                Ok((len, _truncated, Some(from))) => {
                    let from = from.try_into().map_err(|_| NetError::NotIpv4)?;
                    return Ok((len, from));
                }
                Ok((_, _, None)) => return Err(NetError::NotIpv4),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    /// Send one datagram.
    ///
    /// A datagram is sent whole or not at all, so unlike a stream there is no
    /// partial-write case to loop over — only the "no buffer space" retry.
    pub async fn send_to(&self, buf: &[u8], to: &SocketAddrV4) -> Result<usize, NetError> {
        loop {
            match sendto(&self.fd, buf, SendFlags::empty(), to) {
                Ok(n) => return Ok(n),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::OUT).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }
}

/// A listening socket. Exists so the self-test can prove [`TcpStream`] against
/// the kernel's own TCP rather than against a mock; a node never listens.
pub struct TcpListener<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> TcpListener<'r> {
    pub fn bind(reactor: &'r Reactor, address: Ipv4Addr, port: u16) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::STREAM)?;
        bind(&fd, &SocketAddrV4::new(address, port)).map_err(NetError::Errno)?;
        listen(&fd, 1).map_err(NetError::Errno)?;
        Ok(Self { fd, reactor })
    }

    pub fn local_address(&self) -> Result<SocketAddrV4, NetError> {
        local_v4(&self.fd)
    }

    pub async fn accept(&self) -> Result<TcpStream<'r>, NetError> {
        loop {
            // The accepted descriptor inherits non-blocking mode atomically;
            // setting it afterwards would leave a window in which a read blocks.
            match accept_with(&self.fd, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC) {
                Ok(fd) => {
                    return Ok(TcpStream {
                        fd,
                        reactor: self.reactor,
                    });
                }
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.fd.as_raw_fd(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }
}

pub struct TcpStream<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> TcpStream<'r> {
    pub fn peer_address(&self) -> Result<SocketAddrV4, NetError> {
        getpeername(&self.fd)
            .map_err(NetError::Errno)?
            .ok_or(NetError::NotIpv4)?
            .try_into()
            .map_err(|_| NetError::NotIpv4)
    }

    /// Connect, without blocking the executor while the handshake completes.
    ///
    /// A non-blocking `connect` returns `EINPROGRESS` and finishes later; the
    /// socket becoming writable only means the attempt *concluded*, so
    /// `SO_ERROR` must be read to find out whether it concluded successfully.
    /// Skipping that check is the classic way to get a "connected" socket that
    /// fails on first write with a connection refused from minutes earlier.
    pub async fn connect(
        reactor: &'r Reactor,
        address: Ipv4Addr,
        port: u16,
    ) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::STREAM)?;
        match connect(&fd, &SocketAddrV4::new(address, port)) {
            Ok(()) => {}
            Err(Errno::INPROGRESS) => {
                reactor.ready(fd.as_raw_fd(), PollFlags::OUT).await;
                match sockopt::socket_error(&fd).map_err(NetError::Errno)? {
                    Ok(()) => {}
                    Err(e) => return Err(NetError::Errno(e)),
                }
            }
            Err(e) => return Err(NetError::Errno(e)),
        }
        Ok(Self { fd, reactor })
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Read into `buf`, returning how many bytes arrived.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        loop {
            match rustix::io::read(&self.fd, &mut *buf) {
                Ok(0) => return Err(NetError::Closed),
                Ok(n) => return Ok(n),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    /// Read exactly `buf.len()` bytes, or fail.
    ///
    /// Every framed protocol above this — controlbase records, HTTP/2 frames —
    /// needs this rather than `read`, because a short read is the normal case on
    /// a stream and treating it as a complete message is how framing bugs start.
    pub async fn read_exact(&self, buf: &mut [u8]) -> Result<(), NetError> {
        let mut filled = 0;
        while filled < buf.len() {
            filled += self.read(&mut buf[filled..]).await?;
        }
        Ok(())
    }

    pub async fn write_all(&self, buf: &[u8]) -> Result<(), NetError> {
        let mut written = 0;
        while written < buf.len() {
            match rustix::io::write(&self.fd, &buf[written..]) {
                Ok(0) => return Err(NetError::Closed),
                Ok(n) => written += n,
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::OUT).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
        Ok(())
    }
}

/// `embedded-io-async` for the stream, so crates written against that ecosystem
/// — `embedded-tls` today, embassy-net's own sockets later — can drive it
/// without knowing anything about this reactor.
///
/// The mapping is exact rather than convenient: `Closed` becomes a zero-length
/// read, because that is what "the peer hung up" means to a reader, and every
/// other failure keeps its errno.
impl embedded_io_async::Error for NetError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        match self {
            Self::Closed => embedded_io_async::ErrorKind::BrokenPipe,
            Self::NotIpv4 => embedded_io_async::ErrorKind::InvalidInput,
            Self::Errno(e) if *e == Errno::CONNREFUSED => {
                embedded_io_async::ErrorKind::ConnectionRefused
            }
            Self::Errno(e) if *e == Errno::CONNRESET => {
                embedded_io_async::ErrorKind::ConnectionReset
            }
            Self::Errno(e) if *e == Errno::TIMEDOUT => embedded_io_async::ErrorKind::TimedOut,
            Self::Errno(_) => embedded_io_async::ErrorKind::Other,
        }
    }
}

impl embedded_io_async::ErrorType for TcpStream<'_> {
    type Error = NetError;
}

impl embedded_io_async::Read for TcpStream<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match TcpStream::read(self, buf).await {
            // A closed connection is end-of-stream to a reader, not an error.
            // Reporting it as one makes every well-behaved shutdown look like a
            // fault to the layer above.
            Err(NetError::Closed) => Ok(0),
            other => other,
        }
    }
}

impl embedded_io_async::Write for TcpStream<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TcpStream::write_all(self, buf).await.map(|()| buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        // Nothing is buffered here: `write_all` does not return until the
        // kernel has taken every byte.
        Ok(())
    }
}

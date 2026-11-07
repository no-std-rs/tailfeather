use super::Reactor;
use std::prelude::rust_2024::*;
#[cfg(test)]
use std::vec;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
};
pub struct TcpStream(pub tokio::net::TcpStream);
impl TcpStream {
    pub async fn connect_host(_: &Reactor, host: &str, port: u16) -> io::Result<Self> {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let addresses = resolve_v4(host).await?;
            connect_addresses(
                addresses
                    .into_iter()
                    .map(|ip| SocketAddrV4::new(ip, port))
                    .collect(),
            )
            .await
            .map(Self)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connection deadline"))?
    }
}
pub async fn resolve_v4(host: &str) -> io::Result<Vec<Ipv4Addr>> {
    let resolved = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host, 0)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS deadline"))??;
    let mut addresses = Vec::new();
    for address in resolved {
        if let std::net::IpAddr::V4(ip) = address.ip()
            && !addresses.contains(&ip)
        {
            addresses.push(ip);
            if addresses.len() == 16 {
                break;
            }
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::other("no IPv4 addresses"));
    }
    Ok(addresses)
}
async fn connect_addresses(addresses: Vec<SocketAddrV4>) -> io::Result<tokio::net::TcpStream> {
    let mut attempts = tokio::task::JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        attempts.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(index as u64 * 250)).await;
            tokio::net::TcpStream::connect(address).await
        });
    }
    while let Some(result) = attempts.join_next().await {
        if let Ok(Ok(stream)) = result {
            // Relay and control traffic is many small frames; as in Go (and
            // so the official client), never hold one back for a delayed ACK.
            stream.set_nodelay(true)?;
            return Ok(stream);
        }
    }
    Err(io::Error::other("all resolved addresses failed"))
}
impl embedded_io_async::ErrorType for TcpStream {
    type Error = io::Error;
}
impl embedded_io_async::Read for TcpStream {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        tokio::io::AsyncReadExt::read(&mut self.0, out).await
    }
}
impl embedded_io_async::Write for TcpStream {
    async fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        tokio::io::AsyncWriteExt::write(&mut self.0, input).await
    }
    async fn flush(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.0).await
    }
}
/// The data socket's kernel buffers, as wireguard-go sizes them. The default
/// (about 200 KiB) holds only ~150 datagrams, so a burst from a fast peer is
/// dropped before the runtime reads it and TCP inside the tunnel backs off.
const SOCKET_BUFFER: usize = 7 << 20;

/// Best effort: with CAP_NET_ADMIN the forced variants pass `rmem_max`;
/// otherwise the kernel clamps the request to its configured maximum.
fn grow_buffers(socket: &tokio::net::UdpSocket) {
    #[cfg(unix)]
    {
        use rustix::net::sockopt;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let forced = (
            sockopt::set_socket_recv_buffer_size_force(socket, SOCKET_BUFFER).is_ok(),
            sockopt::set_socket_send_buffer_size_force(socket, SOCKET_BUFFER).is_ok(),
        );
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let forced = (false, false);
        if !forced.0 {
            let _ = sockopt::set_socket_recv_buffer_size(socket, SOCKET_BUFFER);
        }
        if !forced.1 {
            let _ = sockopt::set_socket_send_buffer_size(socket, SOCKET_BUFFER);
        }
    }
    #[cfg(not(unix))]
    let _ = socket;
}

/// Bytes one receive slot holds: a UDP GRO batch is at most 64 KiB.
const RECEIVE_SLOT: usize = 1 << 16;
/// Receive slots filled by one `recvmmsg`.
const RECEIVE_SLOTS: usize = 4;
/// Contiguous bytes gathered for one GSO send.
const GSO_BYTES: usize = 1 << 16;

/// Datagrams already read from the kernel and not yet handed out. A GRO slot
/// holds `len` bytes of datagrams spaced `stride` apart (the last may be
/// shorter).
struct Received {
    slots: Vec<u8>,
    meta: [quinn_udp::RecvMeta; RECEIVE_SLOTS],
    /// Filled slots, the current slot and the read offset within it.
    filled: usize,
    slot: usize,
    offset: usize,
}

impl Received {
    fn next(&mut self, output: &mut [u8]) -> Option<(usize, std::net::SocketAddr)> {
        while self.slot < self.filled {
            let meta = &self.meta[self.slot];
            if self.offset < meta.len {
                let stride = if meta.stride == 0 {
                    meta.len
                } else {
                    meta.stride
                };
                let len = stride.min(meta.len - self.offset);
                let base = self.slot * RECEIVE_SLOT + self.offset;
                self.offset += len;
                // A datagram longer than the caller's buffer cannot be a
                // tunnel packet; skip it as a short read would.
                let datagram = &self.slots[base..base + len];
                if let Some(output) = output.get_mut(..len) {
                    output.copy_from_slice(datagram);
                    return Some((len, meta.addr));
                }
                continue;
            }
            self.slot += 1;
            self.offset = 0;
        }
        None
    }
}

/// The data socket. On Linux it receives with `recvmmsg` and UDP GRO and
/// sends equal-sized runs to one peer with UDP GSO, as wireguard-go does;
/// segmentation happens in the local kernel or NIC, so the wire carries
/// ordinary, individually addressed datagrams. Other platforms fall back to
/// one datagram per system call.
pub struct UdpSocket {
    socket: tokio::net::UdpSocket,
    state: quinn_udp::UdpSocketState,
    received: core::cell::RefCell<Received>,
    gather: core::cell::RefCell<Vec<u8>>,
}
impl UdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddrV4> {
        match self.socket.local_addr()? {
            std::net::SocketAddr::V4(v) => Ok(v),
            _ => Err(io::Error::other("IPv6 unsupported")),
        }
    }
    pub async fn bind(_: &Reactor, ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind((ip, port)).await?;
        grow_buffers(&socket);
        // quinn-udp forbids fragmentation (IP_PMTUDISC_PROBE) for QUIC's own
        // path MTU discovery. Keep the operating system's default instead,
        // so oversized tunnel datagrams behave exactly as before.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let discovery = rustix::net::sockopt::ip_mtu_discover(&socket).ok();
        let state = quinn_udp::UdpSocketState::new((&socket).into())?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(discovery) = discovery {
            let _ = rustix::net::sockopt::set_ip_mtu_discover(&socket, discovery);
        }
        Ok(Self {
            socket,
            state,
            received: core::cell::RefCell::new(Received {
                slots: vec![0; RECEIVE_SLOT * RECEIVE_SLOTS],
                meta: [quinn_udp::RecvMeta::default(); RECEIVE_SLOTS],
                filled: 0,
                slot: 0,
                offset: 0,
            }),
            gather: core::cell::RefCell::new(Vec::with_capacity(GSO_BYTES)),
        })
    }
    pub async fn send_to(&self, data: &[u8], to: &SocketAddrV4) -> io::Result<usize> {
        self.transmit(data, None, *to).await?;
        Ok(data.len())
    }
    async fn transmit(
        &self,
        contents: &[u8],
        segment: Option<usize>,
        to: SocketAddrV4,
    ) -> io::Result<()> {
        let transmit = quinn_udp::Transmit {
            destination: to.into(),
            ecn: None,
            contents,
            segment_size: segment,
            src_ip: None,
        };
        self.socket
            .async_io(tokio::io::Interest::WRITABLE, || {
                self.state.try_send((&self.socket).into(), &transmit)
            })
            .await
    }
    /// Submit a burst in order with as few system calls as the OS allows:
    /// consecutive datagrams to one peer, all of one size except a shorter
    /// last one, leave as a single GSO send.
    pub async fn send_batch<'p>(
        &self,
        packets: impl Iterator<Item = (&'p [u8], SocketAddrV4)>,
    ) -> io::Result<()> {
        let segments = self.state.max_gso_segments();
        // The open run: destination, segment size and segments gathered.
        let mut run: Option<(SocketAddrV4, usize, usize)> = None;
        let mut packets = packets.peekable();
        while let Some((packet, to)) = packets.next() {
            if segments <= 1 {
                self.transmit(packet, None, to).await?;
                continue;
            }
            let joins = run.is_some_and(|(run_to, size, count)| {
                run_to == to
                    && packet.len() <= size
                    && count < segments
                    && self.gather.borrow().len() + packet.len() <= GSO_BYTES
            });
            if !joins {
                self.flush(&mut run).await?;
                run = Some((to, packet.len(), 0));
            }
            self.gather.borrow_mut().extend_from_slice(packet);
            let (_, size, count) = run.as_mut().expect("run started");
            *count += 1;
            // A shorter datagram must be the last of its run.
            if packet.len() < *size || packets.peek().is_none() {
                self.flush(&mut run).await?;
            }
        }
        self.flush(&mut run).await
    }
    async fn flush(&self, run: &mut Option<(SocketAddrV4, usize, usize)>) -> io::Result<()> {
        let Some((to, size, count)) = run.take() else {
            return Ok(());
        };
        let contents = core::mem::take(&mut *self.gather.borrow_mut());
        let result = self
            .transmit(&contents, (count > 1).then_some(size), to)
            .await;
        let mut contents = contents;
        contents.clear();
        *self.gather.borrow_mut() = contents;
        result
    }
    pub async fn recv_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        loop {
            if let Some((len, from)) = self.received.borrow_mut().next(data) {
                match from {
                    std::net::SocketAddr::V4(v) => return Ok((len, v)),
                    _ => continue,
                }
            }
            let result = self
                .socket
                .async_io(tokio::io::Interest::READABLE, || {
                    let mut received = self.received.borrow_mut();
                    let Received {
                        slots,
                        meta,
                        filled,
                        slot,
                        offset,
                    } = &mut *received;
                    let mut buffers: heapless::Vec<std::io::IoSliceMut<'_>, RECEIVE_SLOTS> = slots
                        .chunks_mut(RECEIVE_SLOT)
                        .map(std::io::IoSliceMut::new)
                        .collect();
                    *filled = self.state.recv((&self.socket).into(), &mut buffers, meta)?;
                    *slot = 0;
                    *offset = 0;
                    Ok(())
                })
                .await;
            match result {
                Ok(()) => {}
                // ICMP from an unreachable discovery/STUN peer is not a
                // failure of the shared data socket (notably WSAECONNRESET).
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_uses_a_healthy_alternate_address() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let good = match listener.local_addr().unwrap() {
                    std::net::SocketAddr::V4(v) => v,
                    _ => unreachable!(),
                };
                let bad = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), good.port());
                let connected = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    connect_addresses(vec![bad, good]),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    connected.peer_addr().unwrap(),
                    std::net::SocketAddr::V4(good)
                );
            });
    }

    #[test]
    fn batched_sends_arrive_as_the_original_datagrams_in_order() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let reactor = Reactor::new();
                let sender = UdpSocket::bind(&reactor, Ipv4Addr::LOCALHOST, 0)
                    .await
                    .unwrap();
                let first = UdpSocket::bind(&reactor, Ipv4Addr::LOCALHOST, 0)
                    .await
                    .unwrap();
                let second = UdpSocket::bind(&reactor, Ipv4Addr::LOCALHOST, 0)
                    .await
                    .unwrap();
                let (a, b) = (first.local_addr().unwrap(), second.local_addr().unwrap());
                // Equal-sized runs (GSO candidates), a shorter tail ending a
                // run, a destination switch, and a run longer than one GSO
                // message can hold.
                let mut burst: Vec<(Vec<u8>, SocketAddrV4)> = Vec::new();
                for index in 0..70u8 {
                    burst.push((vec![index; 1200], a));
                }
                burst.push((vec![70; 300], a));
                burst.push((vec![71; 1200], a));
                burst.push((vec![72; 1200], b));
                burst.push((vec![73; 40], b));
                sender
                    .send_batch(burst.iter().map(|(packet, to)| (packet.as_slice(), *to)))
                    .await
                    .unwrap();
                let mut datagram = [0; 2048];
                for (packet, to) in &burst {
                    let socket = if *to == a { &first } else { &second };
                    let (len, from) = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        socket.recv_from(&mut datagram),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!(from, sender.local_addr().unwrap());
                    assert_eq!(&datagram[..len], packet.as_slice());
                }
            });
    }
}

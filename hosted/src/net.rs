use crate::exec::Reactor;
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
pub struct UdpSocket(tokio::net::UdpSocket);
impl UdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddrV4> {
        match self.0.local_addr()? {
            std::net::SocketAddr::V4(v) => Ok(v),
            _ => Err(io::Error::other("IPv6 unsupported")),
        }
    }
    pub async fn bind(_: &Reactor, ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        tokio::net::UdpSocket::bind((ip, port)).await.map(Self)
    }
    pub async fn send_to(&self, data: &[u8], to: &SocketAddrV4) -> io::Result<usize> {
        self.0.send_to(data, to).await
    }
    pub async fn recv_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        loop {
            let (len, from) = match self.0.recv_from(data).await {
                Ok(value) => value,
                // ICMP from an unreachable discovery/STUN peer is not a
                // failure of the shared data socket (notably WSAECONNRESET).
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            match from {
                std::net::SocketAddr::V4(v) => return Ok((len, v)),
                _ => continue,
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
}

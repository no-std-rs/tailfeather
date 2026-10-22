use crate::exec::Reactor;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
};
pub struct TcpStream(pub tokio::net::TcpStream);
impl TcpStream {
    pub async fn connect(_: &Reactor, ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        tokio::net::TcpStream::connect((ip, port)).await.map(Self)
    }
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
    pub async fn bind(_: &Reactor, ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        tokio::net::UdpSocket::bind((ip, port)).await.map(Self)
    }
    pub async fn send_to(&self, data: &[u8], to: &SocketAddrV4) -> io::Result<usize> {
        self.0.send_to(data, to).await
    }
    pub async fn recv_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let (len, from) = self.0.recv_from(data).await?;
        match from {
            std::net::SocketAddr::V4(v) => Ok((len, v)),
            _ => Err(io::Error::other("IPv6 unsupported")),
        }
    }
}

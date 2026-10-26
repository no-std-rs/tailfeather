//! Embassy-net platform adapter. The application supplies the UDP socket, HAL
//! RNG factory, a trusted wall clock, and the Embassy network runner task.

use crate::{
    exec::Clock,
    runtime::{Error, LinkBuffers, Network},
};
use core::{
    marker::PhantomData,
    net::{Ipv4Addr, SocketAddrV4},
};
use embassy_net::{Stack, dns::DnsQueryType, tcp::TcpSocket, udp::UdpSocket};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_tls::{TlsClock, TlsConfig, TlsConnection, TlsContext};
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};
use tailfeather::control::tls::{Suite, VerifyingProvider};

pub struct Random<G>(pub G);
macro_rules! rng {
    ($trait:path) => {
        impl<G: RngCore> $trait for Random<G> {
            fn fill_bytes(&mut self, bytes: &mut [u8]) {
                self.0.fill_bytes(bytes);
            }
        }
    };
}
rng!(tailfeather::keys::Rng);
rng!(tailfeather::tunnel::Rng);
rng!(tailfeather::disco::packet::Rng);
rng!(tailfeather::derp::client::Rng);

pub struct EmbassyNetwork<'a, F, C> {
    stack: Stack<'a>,
    udp: UdpSocket<'a>,
    rng: F,
    clock: PhantomData<C>,
}
impl<'a, F, C> EmbassyNetwork<'a, F, C> {
    pub fn new(stack: Stack<'a>, udp: UdpSocket<'a>, rng: F) -> Self {
        Self {
            stack,
            udp,
            rng,
            clock: PhantomData,
        }
    }
}
impl<F, C> Clock for EmbassyNetwork<'_, F, C> {
    fn now_millis(&self) -> u64 {
        Instant::now().as_millis()
    }
    async fn sleep_until(&self, deadline_ms: u64) {
        Timer::at(Instant::from_millis(deadline_ms)).await;
    }
}
impl<F, C, G> Network for EmbassyNetwork<'_, F, C>
where
    F: Fn() -> G,
    G: RngCore + CryptoRng,
    C: TlsClock,
{
    type Stream<'a>
        = TlsConnection<'a, TcpSocket<'a>, Suite>
    where
        Self: 'a;
    type Rng = Random<G>;
    fn rng(&self) -> Self::Rng {
        Random((self.rng)())
    }
    fn unix_millis(&self) -> Result<u64, Error> {
        C::now()
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or("trusted wall clock required")
    }
    fn local_endpoint(&self) -> Result<SocketAddrV4, Error> {
        let endpoint = self.udp.endpoint();
        let address = self
            .interface_address()
            .ok_or("network address unavailable")?;
        Ok(SocketAddrV4::new(address, endpoint.port))
    }
    fn interface_address(&self) -> Option<Ipv4Addr> {
        self.stack
            .config_v4()
            .map(|config| config.address.address())
    }
    fn validate_ca(&self, ca: &[u8]) -> Result<(), Error> {
        if ca.is_empty() {
            return Ok(());
        }
        tailfeather::control::tls::validate_trust_anchor(ca).map_err(|_| "invalid control CA")
    }
    async fn resolve(&self, host: &str) -> Result<Vec<Ipv4Addr, 16>, Error> {
        if let Ok(address) = host.parse() {
            let mut result = Vec::new();
            let _ = result.push(address);
            return Ok(result);
        }
        let addresses = with_timeout(
            Duration::from_secs(10),
            self.stack.dns_query(host, DnsQueryType::A),
        )
        .await
        .map_err(|_| "DNS deadline")?
        .map_err(|_| "DNS lookup")?;
        let mut result = Vec::new();
        for address in addresses {
            #[allow(unreachable_patterns)]
            let address = match address {
                embassy_net::IpAddress::Ipv4(address) => address,
                _ => continue,
            };
            if !result.contains(&address) {
                let _ = result.push(address);
            }
        }
        if result.is_empty() {
            return Err("DNS has no IPv4 addresses");
        }
        Ok(result)
    }
    async fn connect<'a>(
        &'a self,
        host: &str,
        port: u16,
        tls_name: &str,
        ca: &[u8],
        buffers: &'a mut LinkBuffers,
    ) -> Result<Self::Stream<'a>, Error> {
        let LinkBuffers {
            tcp_rx,
            tcp_tx,
            tls_rx,
            tls_tx,
            rsa,
        } = buffers;
        let mut socket = TcpSocket::new(self.stack, tcp_rx, tcp_tx);
        with_timeout(Duration::from_secs(15), async {
            for address in self.resolve(host).await? {
                match with_timeout(Duration::from_secs(3), socket.connect((address, port))).await {
                    Ok(Ok(())) => return Ok(()),
                    _ => socket.abort(),
                }
            }
            Err("all resolved TCP addresses failed")
        })
        .await
        .map_err(|_| "TCP connection deadline")??;
        let config = TlsConfig::new().with_server_name(tls_name);
        let mut tls = TlsConnection::new(socket, tls_rx, tls_tx);
        with_timeout(
            Duration::from_secs(20),
            tls.open(TlsContext::new(
                &config,
                VerifyingProvider::<_, C>::new((self.rng)(), (!ca.is_empty()).then_some(ca), rsa),
            )),
        )
        .await
        .map_err(|_| "TLS deadline")?
        .map_err(|_| "TLS authentication")?;
        Ok(tls)
    }
    async fn receive(&self, bytes: &mut [u8]) -> Result<(usize, SocketAddrV4), Error> {
        let (len, metadata) = self.udp.recv_from(bytes).await.map_err(|_| "UDP receive")?;
        #[allow(unreachable_patterns)]
        match metadata.endpoint.addr {
            embassy_net::IpAddress::Ipv4(address) => {
                Ok((len, SocketAddrV4::new(address, metadata.endpoint.port)))
            }
            _ => Err("IPv6 unsupported"),
        }
    }
    async fn send(&self, bytes: &[u8], to: SocketAddrV4) -> Result<(), Error> {
        self.udp
            .send_to(bytes, (*to.ip(), to.port()))
            .await
            .map_err(|_| "UDP send")
    }
}

impl crate::runtime::SplitStream for TcpSocket<'_> {
    type Reader<'a>
        = embassy_net::tcp::TcpReader<'a>
    where
        Self: 'a;
    type Writer<'a>
        = embassy_net::tcp::TcpWriter<'a>
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Reader<'_>, Self::Writer<'_>) {
        TcpSocket::split(self)
    }
}

//! Local packet-engine benchmark: complete TCP flows, optionally sealed/opened
//! by WireGuard for every data packet and ACK. No NIC, coordinator or relay.
//! Initial fixture keys are deliberately deterministic and never used on a network.
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embedded_io_async::{Read, Write};
use std::{
    cell::{Cell, RefCell},
    time::Instant,
};
use tailfeather::tunnel::{self, noise::TransportKeys, transport::Session};
use tailfeather_reactor::{
    exec::{Clock, Reactor},
    tcp::{NetStack, PacketQueue, Storage},
    tcp_async::{PacketIo, Tcp},
};
use zeroize::Zeroizing;

type Datagram = heapless::Vec<u8, { tunnel::MAX_DATAGRAM_LEN }>;
struct Link<'a> {
    incoming: &'a Channel<NoopRawMutex, Datagram, 128>,
    outgoing: &'a Channel<NoopRawMutex, Datagram, 128>,
    session: RefCell<Session>,
    encrypted: bool,
    packets: Cell<u64>,
    wire_bytes: Cell<u64>,
}
impl PacketIo for Link<'_> {
    type Error = core::convert::Infallible;
    async fn receive(&self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let packet = self.incoming.receive().await;
        if self.encrypted {
            self.session.borrow_mut().open(&packet, output).unwrap();
            Ok(usize::from(u16::from_be_bytes([output[2], output[3]])))
        } else {
            output[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }
    async fn send(&self, packet: &[u8]) -> Result<(), Self::Error> {
        let mut datagram = Datagram::new();
        if self.encrypted {
            datagram.resize_default(tunnel::MAX_DATAGRAM_LEN).unwrap();
            let len = self
                .session
                .borrow_mut()
                .seal(packet, &mut datagram)
                .unwrap();
            datagram.truncate(len);
        } else {
            datagram.extend_from_slice(packet).unwrap();
        }
        self.packets.set(self.packets.get() + 1);
        self.wire_bytes
            .set(self.wire_bytes.get() + datagram.len() as u64);
        self.outgoing.send(datagram).await;
        Ok(())
    }
}

async fn transfer<'a, C: Clock, B: PacketQueue<64>>(
    clock: &Reactor<C>,
    local: &Tcp<'a, 8, 64, B>,
    remote: &Tcp<'a, 8, 64, B>,
    bytes: usize,
    on_ready: impl FnOnce(),
) -> f64 {
    let mut listener = remote.listen(2222).unwrap();
    let (source, sink) = tokio::join!(
        local.connect(clock, "100.64.0.2".parse().unwrap(), 2222, 49152),
        listener.accept()
    );
    let mut source = source.unwrap();
    let mut sink = sink.unwrap();
    on_ready();
    let started = Instant::now();
    let sender = async {
        let buffer = [0x5a; 65536];
        let mut remaining = bytes;
        while remaining != 0 {
            let len = remaining.min(buffer.len());
            source.write_all(&buffer[..len]).await.unwrap();
            remaining -= len;
        }
        source.shutdown().unwrap();
    };
    let receiver = async {
        let mut buffer = [0; 65536];
        let mut total = 0;
        let mut checksum = 0u64;
        loop {
            let len = sink.read(&mut buffer).await.unwrap();
            if len == 0 {
                break;
            }
            total += len;
            checksum += buffer[..len]
                .iter()
                .map(|byte| u64::from(*byte))
                .sum::<u64>();
        }
        assert_eq!(total, bytes);
        assert_eq!(checksum, bytes as u64 * 0x5a);
    };
    tokio::join!(sender, receiver);
    started.elapsed().as_secs_f64()
}

async fn measure<'a, C: Clock, B: PacketQueue<64>>(
    clock: C,
    local: NetStack<'a, 8, 64, B>,
    remote: NetStack<'a, 8, 64, B>,
    bytes: usize,
    encrypted: bool,
) -> (f64, u64, u64) {
    let clock = Reactor::with_clock(clock);
    let local = Tcp::new(local);
    let remote = Tcp::new(remote);
    local.set_address("100.64.0.1".parse().unwrap(), clock.clock_millis(), 1);
    remote.set_address("100.64.0.2".parse().unwrap(), clock.clock_millis(), 2);
    let a = Channel::new();
    let b = Channel::new();
    let keys = |sending, receiving| TransportKeys {
        sending: Zeroizing::new([sending; 32]),
        receiving: Zeroizing::new([receiving; 32]),
    };
    let local_io = Link {
        incoming: &a,
        outgoing: &b,
        session: RefCell::new(Session::new(keys(1, 2), 1, 2, tunnel::Instant(0))),
        encrypted,
        packets: Cell::new(0),
        wire_bytes: Cell::new(0),
    };
    let remote_io = Link {
        incoming: &b,
        outgoing: &a,
        session: RefCell::new(Session::new(keys(2, 1), 2, 1, tunnel::Instant(0))),
        encrypted,
        packets: Cell::new(0),
        wire_bytes: Cell::new(0),
    };
    let traffic = async {
        let seconds = transfer(&clock, &local, &remote, bytes, || {
            local_io.packets.set(0);
            remote_io.packets.set(0);
            local_io.wire_bytes.set(0);
            remote_io.wire_bytes.set(0);
        })
        .await;
        (
            seconds,
            local_io.packets.get() + remote_io.packets.get(),
            local_io.wire_bytes.get() + remote_io.wire_bytes.get(),
        )
    };
    tokio::select! {
        result = traffic => result,
        result = local.run(&clock, &local_io) => panic!("driver stopped: {result:?}"),
        result = remote.run(&clock, &remote_io) => panic!("driver stopped: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => panic!("benchmark deadline"),
    }
}

#[cfg(feature = "std")]
fn clock() -> impl Clock {
    tailfeather_reactor::exec::TokioClock::default()
}
#[cfg(not(feature = "std"))]
fn clock() -> impl Clock {
    tailfeather_reactor::exec::EmbassyClock
}

#[path = "throughput/mesh.rs"]
mod mesh;

fn main() {
    eprintln!(
        "AEAD provider: {}",
        tailfeather::tunnel::crypto::aead_backend()
    );
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|index| args.get(index + 1))
    };
    let mesh = args.iter().any(|arg| arg == "--mesh");
    let owned = arg("--buffers").is_some_and(|value| value == "owned");
    let bytes = arg("--bytes").map_or(64 * 1024 * 1024, |value| {
        value.parse::<usize>().expect("byte count")
    });
    assert!(bytes > 0);
    std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            for encrypted in [false, true].into_iter().filter(|encrypted| !mesh || *encrypted) {
                for round in 0..4 {
                    let sample_bytes = if round == 0 { bytes.min(8 * 1024 * 1024) } else { bytes };
                    let result = if owned {
                        #[cfg(feature = "std")]
                        { type Stack = NetStack<'static, 8, 64, std::collections::VecDeque<tailfeather_reactor::tcp::Packet>>;
                          if mesh { mesh::measure(clock(), Stack::new(1), Stack::new(2), sample_bytes).await } else { measure(clock(), Stack::new(1), Stack::new(2), sample_bytes, encrypted).await } }
                        #[cfg(not(feature = "std"))]
                        { panic!("owned buffers require the std feature"); }
                    } else {
                        let mut a = Storage::<8, 65536>::new(); let mut b = Storage::<8, 65536>::new();
                        if mesh { mesh::measure(clock(), NetStack::<8, 64>::with_storage(1, &mut a), NetStack::<8, 64>::with_storage(2, &mut b), sample_bytes).await } else { measure(clock(), NetStack::<8, 64>::with_storage(1, &mut a), NetStack::<8, 64>::with_storage(2, &mut b), sample_bytes, encrypted).await }
                    };
                    if round != 0 {
                        let (seconds, packets, wire_bytes) = result;
                        println!("{{\"layer\":\"{}\",\"provider\":\"{}\",\"buffers\":\"{}\",\"std\":{},\"wireguard\":{},\"round\":{},\"bytes\":{},\"seconds\":{:.6},\"payload_gbps\":{:.3},\"packet_gbps\":{:.3},\"packets_per_second\":{:.0}}}", if mesh { "mesh" } else { "transport" }, tailfeather::tunnel::crypto::aead_backend(), if owned { "owned" } else { "fixed" }, cfg!(feature = "std"), encrypted, round, bytes, seconds, bytes as f64 * 8.0 / seconds / 1e9, wire_bytes as f64 * 8.0 / seconds / 1e9, packets as f64 / seconds);
                    }
                }
            }
        });
    }).unwrap().join().unwrap();
}

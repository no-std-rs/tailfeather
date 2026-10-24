//! Compile/link archive probe only: deterministic fixtures, no allocator.
//! A board application supplies Embassy's time driver and critical sections.
#![no_std]
use embassy_executor::Executor;
use embassy_net::{
    Stack,
    udp::{PacketMetadata, UdpSocket},
};
use static_cell::StaticCell;
use tailfeather_reactor::{
    embassy::EmbassyNetwork,
    runtime::{self, Buffers, Config, Runtime, State},
    tcp::{NetStack, Storage},
    tcp_async::Tcp,
};

struct FixtureRng;
impl rand_core::RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        0x42424242
    }
    fn next_u64(&mut self) -> u64 {
        0x4242424242424242
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(0x42);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl rand_core::CryptoRng for FixtureRng {}
struct WallClock;
impl embedded_tls::TlsClock for WallClock {
    fn now() -> Option<u64> {
        Some(1_700_000_000)
    }
}
struct FixtureState;
impl State for FixtureState {
    fn load(&self, _: &mut [u8]) -> Result<Option<usize>, &'static str> {
        Ok(None)
    }
    fn save(&self, _: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
    fn load_timestamp(&self, _: &mut [u8; 12]) -> Result<bool, &'static str> {
        Ok(false)
    }
    fn save_timestamp(&self, _: &[u8; 12]) -> Result<(), &'static str> {
        Ok(())
    }
}
static EXECUTOR: StaticCell<Executor> = StaticCell::new();
static TCP: StaticCell<Storage<'static, 4, 1024>> = StaticCell::new();
static NODE: StaticCell<tailfeather::Node<3>> = StaticCell::new();
static BUFFERS: StaticCell<Buffers<3>> = StaticCell::new();
static UDP_RX: StaticCell<[u8; 2 * tailfeather::tunnel::MAX_DATAGRAM_LEN]> = StaticCell::new();
static UDP_TX: StaticCell<[u8; tailfeather::tunnel::MAX_DATAGRAM_LEN]> = StaticCell::new();
static UDP_RX_META: StaticCell<[PacketMetadata; 2]> = StaticCell::new();
static UDP_TX_META: StaticCell<[PacketMetadata; 1]> = StaticCell::new();

#[embassy_executor::task]
async fn client(stack: Stack<'static>) {
    let mut udp = UdpSocket::new(
        stack,
        UDP_RX_META.init([PacketMetadata::EMPTY; 2]),
        UDP_RX.init([0; 2 * tailfeather::tunnel::MAX_DATAGRAM_LEN]),
        UDP_TX_META.init([PacketMetadata::EMPTY; 1]),
        UDP_TX.init([0; tailfeather::tunnel::MAX_DATAGRAM_LEN]),
    );
    udp.bind(51820).unwrap();
    let network = EmbassyNetwork::<_, WallClock>::new(stack, udp, || FixtureRng);
    let config = Config {
        control_url: "https://control.invalid",
        hostname: "compile-probe",
        auth_key: "compile-only",
        control_ca_der: &[],
        relay_only: false,
        ephemeral: true,
        os: "probe",
    };
    let node = NODE.init_with(|| runtime::restore(&config, &network, &FixtureState).unwrap());
    let runtime = Runtime::<_, _, 3, 4>::new(config, node, &network, &FixtureState).unwrap();
    let tcp = Tcp::new(NetStack::<4, 2>::with_storage(1, TCP.init(Storage::new())));
    let buffers = BUFFERS.init_with(Buffers::new);
    let _ = runtime.run(&tcp, buffers).await;
}

pub fn start(stack: Stack<'static>) -> ! {
    EXECUTOR.init(Executor::new()).run(|spawner| {
        spawner.spawn(client(stack).unwrap());
    })
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

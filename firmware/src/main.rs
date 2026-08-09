//! ESP32-C6 tailfeather gateway.
//!
//! Milestone M1 is what runs here end to end: join a Wi-Fi network as a
//! station, take an address by DHCP, then hand the stack to the tunnel task
//! which drives one [`tailfeather::Node`] actor over UDP.

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

mod inner;
mod nat;
mod tunnel;
mod wifi;

use embassy_executor::Spawner;
use embassy_net::{Runner, StackResources};
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::wifi::Interface;
use log::info;
use static_cell::StaticCell;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

/// Configuration baked in at compile time from `.cargo/config.toml`. Reading it
/// with `env!` keeps credentials out of the source tree and out of any runtime
/// storage the firmware would otherwise have to manage.
pub const WIFI_SSID: &str = env!("WIFI_SSID");
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
pub const WG_PRIVATE_KEY: [u8; 32] = hex32(env!("WG_PRIVATE_KEY"));
pub const MACHINE_PRIVATE_KEY: [u8; 32] = hex32(env!("MACHINE_PRIVATE_KEY"));
pub const DISCO_PRIVATE_KEY: [u8; 32] = hex32(env!("DISCO_PRIVATE_KEY"));
pub const WG_PEER_PUBLIC_KEY: [u8; 32] = hex32(env!("WG_PEER_PUBLIC_KEY"));
pub const WG_TUNNEL_IP: [u8; 4] = ipv4(env!("WG_TUNNEL_IP"));

/// Decode 64 hex characters into a key. `const` so that a malformed key is a
/// build failure rather than a panic on a device with no console attached.
const fn hex32(text: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("key must be hexadecimal"),
        }
    }

    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "key must be 32 bytes of hex");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// Parse dotted-quad IPv4, likewise at build time.
const fn ipv4(text: &str) -> [u8; 4] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 4];
    let mut octet = 0;
    let mut value = 0u16;
    let mut digits = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                assert!(digits > 0, "empty octet in tunnel IP");
                assert!(octet < 3, "too many octets in tunnel IP");
                out[octet] = value as u8;
                octet += 1;
                value = 0;
                digits = 0;
            }
            c @ b'0'..=b'9' => {
                value = value * 10 + (c - b'0') as u16;
                assert!(value <= 255, "octet out of range in tunnel IP");
                digits += 1;
            }
            _ => panic!("tunnel IP must be dotted-quad IPv4"),
        }
        i += 1;
    }
    assert!(octet == 3 && digits > 0, "tunnel IP must have four octets");
    out[3] = value as u8;
    out
}

/// Backs the smoltcp sockets owned by the stack: one for DHCP, one for the
/// tunnel, one per NAT slot, and a spare for the control-plane work of P1
/// onwards.
static STACK_RESOURCES: StaticCell<StackResources<{ 4 + nat::SLOTS }>> = StaticCell::new();

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // The only consumer of this heap is the esp-radio C blob, which allocates
    // its own buffers. Nothing in this firmware allocates.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 65536);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    let (wifi_controller, interfaces) = esp_radio::wifi::new(peripherals.WIFI, Default::default())
        .expect("Failed to initialize Wi-Fi controller");

    let rng = Rng::new();
    // smoltcp randomizes ephemeral ports and the DHCP transaction ID from this.
    let mut seed = [0u8; 8];
    rng.read(&mut seed);

    let (stack, runner) = embassy_net::new(
        interfaces.station,
        embassy_net::Config::dhcpv4(Default::default()),
        STACK_RESOURCES.init(StackResources::new()),
        u64::from_le_bytes(seed),
    );

    spawner.spawn(wifi::connection(wifi_controller).expect("each task is spawned once"));
    spawner.spawn(net_task(runner).expect("each task is spawned once"));

    stack.wait_config_up().await;
    let address = stack
        .config_v4()
        .expect("the stack reports a v4 config once it is up")
        .address;
    info!("DHCP lease: {address}");

    spawner.spawn(tunnel::tunnel(stack).expect("each task is spawned once"));

    core::future::pending().await
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) -> ! {
    runner.run().await
}

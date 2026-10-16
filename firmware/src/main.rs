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

#[cfg(all(feature = "test-insecure-control", not(debug_assertions)))]
compile_error!("test-insecure-control cannot be compiled in a release build");

mod control;
mod derp;
mod flash;
mod inner;
mod nat;
mod stack;
mod tunnel;
mod wifi;

use embassy_executor::Spawner;
use embassy_net::{Runner, StackResources};
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::wifi::Interface;
use log::{LevelFilter, info};
use static_cell::StaticCell;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

/// Provisioning baked in at compile time. Secret values are never logged or
/// copied into the persistent state slots.
pub const WIFI_SSID: &str = env!("WIFI_SSID");
pub const WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
pub const TS_AUTH_KEY: &str = env!("TS_AUTH_KEY");
pub const TS_CONTROL_URL: &str = env!("TS_CONTROL_URL");
pub const TS_HOSTNAME: &str = env!("TS_HOSTNAME");
pub const TS_CONTROL_CA_DER: &[u8] = include_bytes!(env!("TS_CONTROL_CA_DER"));
pub const BUILD_TIME_FLOOR: u64 = decimal_u64(env!("TS_BUILD_TIME_FLOOR"));

const fn decimal_u64(text: &str) -> u64 {
    let bytes = text.as_bytes();
    assert!(!bytes.is_empty(), "build time floor must not be empty");
    let mut value = 0u64;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(byte.is_ascii_digit(), "build time floor must be decimal");
        value = match value.checked_mul(10) {
            Some(value) => match value.checked_add((byte - b'0') as u64) {
                Some(value) => value,
                None => panic!("build time floor must fit u64"),
            },
            None => panic!("build time floor must fit u64"),
        };
        index += 1;
    }
    value
}

/// Backs the smoltcp sockets owned by the stack: DHCP, WireGuard, shared UDP,
/// TCP and ICMP raw forwarding (peer-API DNS shares raw UDP), control, two DERP
/// connections, and transient bootstrap DNS/STUN/NTP use. NAT table capacity
/// no longer consumes socket handles.
static STACK_RESOURCES: StaticCell<StackResources<12>> = StaticCell::new();

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger(LevelFilter::Info);

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // The only consumer of this heap is the esp-radio C blob, which allocates
    // its own buffers. Nothing in this firmware allocates; reclaimed RAM is a
    // fixed 64 KiB bank on ESP32-C6, so this is also its maximum size.
    // `esp_hal::ram(reclaimed)` expands to this section plus a compile-time
    // trait assertion. The assertion's proc macro relies on Cargo metadata
    // which Bazel does not expose, while the section is the actual ABI
    // contract for reclaimed bootloader RAM.
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".dram2_uninit")] size: 61184);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    // The default five-frame host RX queue is smaller than a complete TCP
    // receive-window burst once an encrypted ACK or control packet arrives at
    // the same time. Keep the radio driver's bounded buffer pools unchanged,
    // but let their host-side queues absorb both traffic classes without
    // discarding a frame before smoltcp can apply its own backpressure.
    let radio_config = esp_radio::wifi::ControllerConfig::default()
        .with_rx_queue_size(10)
        .with_tx_queue_size(6);
    let (wifi_controller, interfaces) = esp_radio::wifi::new(peripherals.WIFI, radio_config)
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

    spawner.spawn(
        tunnel::tunnel(stack, peripherals.FLASH, spawner).expect("each task is spawned once"),
    );

    core::future::pending().await
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) -> ! {
    runner.run().await
}

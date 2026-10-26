//! Runs the project's library crates on the development machine, with no
//! hardware and no operating system underneath them.
//!
//! This targets `x86_64-unknown-linux-none`: the Linux syscall ABI, but no
//! libc, no `std`, and no allocator. That combination is the point. The
//! firmware's library crates are `no_std` and allocation-free, and the only way
//! to be confident they *stay* that way — and that they behave identically off
//! the chip — is to run them somewhere just as bare. A `std` test binary would
//! hide an accidental dependence on the hosted environment; this does not.
//!
//! ```text
//! harness respond  <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4>
//! harness initiate <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4> \
//!                  <peer ip> <peer port>
//! harness initiate-rekey <same arguments as initiate>
//! harness gateway <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4> \
//!                 <uplink ipv4>
//! harness selftest <state dir>
//! ```
//!
//! `respond` is milestone M2, verified by `scripts/interop-wireguard.sh`.
//! `initiate` is its mirror: we start the handshake and kernel WireGuard
//! answers. `selftest` exercises the runtime this binary is built on, which no
//! host test can reach.

#![no_std]
#![no_main]

// Declared first and with `#[macro_use]` so `println!` and `evt!` are in scope
// for every module below without each one importing them.
#[macro_use]
mod rt;

mod compiler_builtins;
mod control;
mod derp;
mod disco;
mod dns;
mod doh;
mod exec;
mod gateway;
mod gateway6;
mod h2;
mod inner;
mod net;
mod probe;
mod selftest;
mod store;
mod time;
mod tls;
mod wg;

// The no-libc harness has one OS thread and its executor polls one future at a
// time. A critical section therefore needs only compiler fences: synchronous
// TLS verification cannot be preempted by another harness task while it holds
// tailfeather's shared fixed RSA workspace.
struct HarnessCriticalSection;
critical_section::set_impl!(HarnessCriticalSection);

unsafe impl critical_section::Impl for HarnessCriticalSection {
    unsafe fn acquire() -> critical_section::RawRestoreState {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    unsafe fn release(_: critical_section::RawRestoreState) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

use core::net::{Ipv4Addr, SocketAddrV4};

use wirefeather::Rng;

/// The kernel's entropy pool, via `getrandom`.
pub struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rt::getrandom(dest);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {}", info.message());
    rt::exit(101)
}

/// The process entry point.
///
/// The kernel enters `_start` with `rsp` pointing at `argc`, and with no
/// guarantee of the 16-byte stack alignment the C ABI requires. A naked
/// function is the only way to capture that pointer and fix the alignment
/// before calling anything compiled normally.
///
/// # Safety
///
/// Only the kernel may call this, and only as the process entry point. It reads
/// the argument vector from the stack pointer it was entered with, which is
/// meaningful nowhere else.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {main}",
        main = sym rust_start,
    )
}

/// Arguments as the kernel lays them out: `argc`, then `argc` pointers to
/// NUL-terminated strings.
struct Args {
    stack: *const usize,
}

impl Args {
    fn count(&self) -> usize {
        unsafe { *self.stack }
    }

    fn get(&self, index: usize) -> Option<&'static str> {
        if index >= self.count() {
            return None;
        }
        unsafe {
            let ptr = *self.stack.add(1 + index) as *const u8;
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(ptr, len)).ok()
        }
    }
}

const USAGE: &str = "usage:
  harness respond  <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4>
  harness initiate <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4> \
<peer ip> <peer port>
  harness selftest <state dir>
  harness wg-selftest
  harness gateway-selftest
  harness gateway  <bind ip> <port> <private hex> <peer public hex> <tunnel ipv4> \
<uplink ipv4> [resolver ipv4] [open|internet]
  harness dns-server <bind ip> <port> [answer delay ms]
  harness doh-client <gateway ipv4> <port> <get|post> <name> <expected ipv4>
  harness probe-server <udp|tcp> <bind ip> <port>
  harness probe-client <udp|tcp> <server ip> <port> <expected source ip>
  harness ts2021   <state dir> <server ip> <port>
  harness register <state dir> <server ip> <port> <preauth key> \
[--exit-node|--rotate] [--hostname <name>]
  harness map      <state dir> <server ip> <port> [responses] [--hostname <name>]
  harness map-bound <server ip> <port>
  harness disco    <state dir> <server ip> <port> [seconds] [--hostname <name>]
  harness tls      <server ip> <port> <server name> <ca der path> [trusted unix time]
  harness derp     <server ip> <port> <state dir a> <state dir b>";

extern "C" fn rust_start(stack: *const usize) -> ! {
    let args = Args { stack };
    match args.get(1) {
        Some("respond") => wg::run_responder(tunnel_config(&args)),
        Some("initiate" | "initiate-rekey") => {
            let accelerated_rekey = args.get(1) == Some("initiate-rekey");
            let config = tunnel_config(&args);
            let (Some(peer_ip), Some(peer_port)) = (args.get(7), args.get(8)) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let peer_ip = parse_ipv4(peer_ip).expect("peer address must be IPv4");
            let peer_port = parse_u16(peer_port).expect("peer port must be a number");
            wg::run_initiator(
                config,
                SocketAddrV4::new(peer_ip, peer_port),
                accelerated_rekey,
            )
        }
        Some("selftest") => selftest::run(args.get(2).unwrap_or("/tmp/harness-selftest")),
        Some("wg-selftest") => selftest::wg(),
        Some("gateway-selftest") => selftest::gateway(),
        Some("gateway6") => {
            let config = tunnel_config(&args);
            let uplink = args
                .get(7)
                .expect("gateway6 requires an IPv6 uplink")
                .parse()
                .expect("IPv6 uplink");
            let client = args
                .get(8)
                .expect("gateway6 requires the authenticated peer IPv6 address")
                .parse()
                .expect("IPv6 client");
            let tunnel = args
                .get(9)
                .expect("gateway6 requires the gateway tunnel IPv6 address")
                .parse()
                .expect("IPv6 tunnel");
            gateway6::run(config, uplink, client, tunnel)
        }
        Some("gateway") => {
            let config = tunnel_config(&args);
            let Some(uplink) = args.get(7) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            // Both or neither: a resolver with no policy could never answer,
            // and a policy with nowhere to ask is not a configuration.
            let dns = match (args.get(8), args.get(9)) {
                (Some(resolver), Some(filter)) => Some(gateway::Dns {
                    resolver: parse_ipv4(resolver).expect("resolver address must be IPv4"),
                    policy: gateway::policy(filter)
                        .expect("packet filter must be open or internet"),
                }),
                (None, _) => None,
                (Some(_), None) => {
                    println!("{USAGE}");
                    rt::exit(2)
                }
            };
            gateway::run(
                config,
                parse_ipv4(uplink).expect("gateway uplink address must be IPv4"),
                dns,
            )
        }
        Some("dns-server") => {
            let (Some(bind), Some(port)) = (args.get(2), args.get(3)) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            doh::dns_server(
                parse_ipv4(bind).expect("DNS bind address must be IPv4"),
                parse_u16(port).expect("DNS port must be a number"),
                args.get(4).and_then(parse_u64).unwrap_or(0),
            )
        }
        Some("doh-client") => {
            let (Some(gateway), Some(port), Some(method), Some(name), Some(expected)) = (
                args.get(2),
                args.get(3),
                args.get(4),
                args.get(5),
                args.get(6),
            ) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            doh::doh_client(
                parse_ipv4(gateway).expect("gateway address must be IPv4"),
                parse_u16(port).expect("port must be a number"),
                method,
                name,
                parse_ipv4(expected).expect("expected address must be IPv4"),
            )
        }
        Some("probe-server") => {
            let (Some(protocol), Some(bind), Some(port)) = (args.get(2), args.get(3), args.get(4))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            probe::server(
                protocol,
                parse_ipv4(bind).expect("probe bind address must be IPv4"),
                parse_u16(port).expect("probe port must be a number"),
            )
        }
        Some("probe-client") => {
            let (Some(protocol), Some(server), Some(port), Some(expected)) =
                (args.get(2), args.get(3), args.get(4), args.get(5))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            probe::client(
                protocol,
                parse_ipv4(server).expect("probe server address must be IPv4"),
                parse_u16(port).expect("probe port must be a number"),
                parse_ipv4(expected).expect("expected source address must be IPv4"),
            )
        }
        Some("ts2021") => {
            let (Some(state_dir), Some(ip), Some(port)) = (args.get(2), args.get(3), args.get(4))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            control::run(state_dir, ip, port)
        }
        Some("map") => {
            let (Some(state_dir), Some(ip), Some(port)) = (args.get(2), args.get(3), args.get(4))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            let wanted = args.get(5).and_then(parse_u16).unwrap_or(1) as usize;
            control::run_map(state_dir, ip, port, hostname(&args), wanted.max(1))
        }
        Some("map-bound") => {
            let (Some(ip), Some(port)) = (args.get(2), args.get(3)) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            control::run_map_bound(
                parse_ipv4(ip).expect("server address must be IPv4"),
                parse_u16(port).expect("port must be a number"),
            )
        }
        Some("derp") => {
            let (Some(ip), Some(port)) = (args.get(2), args.get(3)) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let (Some(sender), Some(receiver)) = (args.get(4), args.get(5)) else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            derp::run(ip, port, sender, receiver)
        }
        Some("tls") => {
            let (Some(ip), Some(port), Some(name), Some(ca)) =
                (args.get(2), args.get(3), args.get(4), args.get(5))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            tls::run(ip, port, name, ca, args.get(6).and_then(parse_u64))
        }
        Some("disco") => {
            let (Some(state_dir), Some(ip), Some(port)) = (args.get(2), args.get(3), args.get(4))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            let seconds = args.get(5).and_then(parse_u16).map(u64::from);
            disco::run(state_dir, ip, port, hostname(&args), seconds)
        }
        Some("register") => {
            let (Some(state_dir), Some(ip), Some(port), Some(auth_key)) =
                (args.get(2), args.get(3), args.get(4), args.get(5))
            else {
                println!("{USAGE}");
                rt::exit(2)
            };
            let ip = parse_ipv4(ip).expect("server address must be IPv4");
            let port = parse_u16(port).expect("port must be a number");
            let mut exit_node = false;
            let mut rotate = false;
            for index in 6..10 {
                match args.get(index) {
                    Some("--exit-node") => exit_node = true,
                    Some("--rotate") => rotate = true,
                    _ => {}
                }
            }
            control::run_register(
                state_dir,
                ip,
                port,
                auth_key,
                hostname(&args),
                exit_node,
                rotate,
            )
        }
        _ => {
            println!("{USAGE}");
            rt::exit(2)
        }
    }
}

/// The `--hostname <name>` this run should register under.
///
/// Defaults to the plain product name, which is what a real device sends. The
/// conformance suite overrides it with `esp-gateway-<runid>` so that it can
/// delete exactly the nodes it created — see `ts-conformance`'s `runscope`
/// module for why leaving them behind breaks later runs.
fn hostname(args: &Args) -> &'static str {
    let mut index = 2;
    while let Some(arg) = args.get(index) {
        if arg == "--hostname"
            && let Some(name) = args.get(index + 1)
        {
            return name;
        }
        index += 1;
    }
    tailfeather::control::Hostinfo::DEFAULT_HOSTNAME
}

/// The five arguments both tunnel modes share.
fn tunnel_config(args: &Args) -> wg::Config {
    let (Some(bind_ip), Some(port), Some(private_hex), Some(peer_hex), Some(tunnel_ip)) = (
        args.get(2),
        args.get(3),
        args.get(4),
        args.get(5),
        args.get(6),
    ) else {
        println!("{USAGE}");
        rt::exit(2)
    };
    wg::Config {
        bind: parse_ipv4(bind_ip).expect("bind address must be IPv4"),
        port: parse_u16(port).expect("port must be a number"),
        private_key: parse_key(private_hex),
        peer_key: parse_key(peer_hex),
        tunnel_ip: parse_octets(tunnel_ip).expect("tunnel address must be IPv4"),
    }
}

/// Formats bytes as lowercase hex without allocating.
pub struct HexBytes<'a>(pub &'a [u8]);

impl core::fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn parse_key(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "a key must be 64 hex characters");
    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = nibble(bytes[i * 2]) << 4 | nibble(bytes[i * 2 + 1]);
    }
    key
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

fn parse_u16(s: &str) -> Option<u16> {
    let mut value: u32 = 0;
    if s.is_empty() {
        return None;
    }
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (c - b'0') as u32;
        if value > u16::MAX as u32 {
            return None;
        }
    }
    Some(value as u16)
}

fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(value)
}

fn parse_octets(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in octets.iter_mut() {
        let part = parts.next()?;
        *slot = u8::try_from(parse_u16(part)?).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    parse_octets(s).map(Ipv4Addr::from)
}

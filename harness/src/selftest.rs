//! Exercises the runtime itself, with no peer and no network.
//!
//! The library crates are covered by `cargo test` on the host. What that cannot
//! reach is this binary's own foundations — the reactor, the raw syscalls, the
//! atomic file write — because none of them exist in a `std` build. So they get
//! a self-test, run as a subcommand, that the conformance suite can invoke.
//!
//! Everything here is checked against the kernel's own behaviour rather than
//! against our expectations of it: the timer is measured with `CLOCK_MONOTONIC`,
//! the loopback datagram must actually traverse the network stack, and the
//! corrupted blob is corrupted on disk.

use core::net::Ipv4Addr;

use rustix::fs::{Mode, OFlags};

use crate::exec::{Either, Reactor, block_on, select};
use crate::net::{TcpListener, TcpStream, UdpSocket};
use crate::rt;
use crate::store::{FileStore, Path, StoreError};
use crate::time::{Clock, monotonic_millis, tai64n};

pub fn run(state_dir: &str) -> ! {
    let mut failures = 0;

    failures += check("timer sleeps for at least the requested time", timers());
    failures += check("a datagram round-trips over loopback", loopback());
    failures += check(
        "select returns the branch that is ready",
        select_picks_ready(),
    );
    failures += check("a TCP stream connects and carries bytes", tcp_roundtrip());
    failures += check(
        "a refused connection is reported, not hidden",
        tcp_refused(),
    );
    failures += check("stored state survives a reload", store_roundtrip(state_dir));
    failures += check(
        "a corrupted blob is refused",
        store_rejects_corruption(state_dir),
    );
    failures += check("tai64n is monotonic and correctly shaped", timestamps());

    if failures == 0 {
        evt!("{{\"event\":\"selftest\",\"result\":\"pass\"}}");
        rt::exit(0)
    }
    evt!("{{\"event\":\"selftest\",\"result\":\"fail\",\"failures\":{failures}}}");
    rt::exit(1)
}

fn check(name: &str, result: Result<(), &'static str>) -> u32 {
    match result {
        Ok(()) => {
            println!("ok   {name}");
            0
        }
        Err(reason) => {
            println!("FAIL {name}: {reason}");
            1
        }
    }
}

fn timers() -> Result<(), &'static str> {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    let before = monotonic_millis();
    block_on(&reactor, reactor.sleep(120));
    let elapsed = monotonic_millis() - before;
    // A sleep may overshoot — the scheduler owes us nothing — but undershooting
    // means the reactor returned without waiting, which would turn every timer
    // in the program into a busy loop.
    if elapsed < 120 {
        return Err("returned early");
    }
    if elapsed > 2_000 {
        return Err("slept far longer than asked");
    }
    Ok(())
}

fn loopback() -> Result<(), &'static str> {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    block_on(&reactor, async {
        let receiver = UdpSocket::bind(&reactor, LOCALHOST, 0).map_err(|_| "bind receiver")?;
        let sender = UdpSocket::bind(&reactor, LOCALHOST, 0).map_err(|_| "bind sender")?;
        let to = receiver.local_address().map_err(|_| "getsockname")?;

        sender
            .send_to(b"harness selftest", &to)
            .await
            .map_err(|_| "send")?;

        let mut buf = [0u8; 64];
        // Bounded, so a lost datagram fails the test rather than hanging it.
        match select(receiver.recv_from(&mut buf), reactor.sleep(2_000)).await {
            Either::First(Ok((len, _))) if &buf[..len] == b"harness selftest" => Ok(()),
            Either::First(Ok(_)) => Err("received the wrong bytes"),
            Either::First(Err(_)) => Err("recv failed"),
            Either::Second(()) => Err("timed out waiting for the datagram"),
        }
    })
}

fn select_picks_ready() -> Result<(), &'static str> {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    block_on(&reactor, async {
        match select(reactor.sleep(10), reactor.sleep(5_000)).await {
            Either::First(()) => Ok(()),
            Either::Second(()) => Err("the later deadline fired first"),
        }
    })
}

/// The loopback address, which every test here talks to.
const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

fn tcp_roundtrip() -> Result<(), &'static str> {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    block_on(&reactor, async {
        let listener = TcpListener::bind(&reactor, LOCALHOST, 0).map_err(|_| "listen")?;
        let address = listener.local_address().map_err(|_| "getsockname")?;

        // The connect and the accept have to make progress against each other
        // on one thread, which is precisely what the reactor is for: `connect`
        // parks on writability and `accept` on readability, and the kernel
        // completes the handshake between them.
        let (client, server) = match select(
            async {
                let client = TcpStream::connect(&reactor, LOCALHOST, address.port()).await?;
                let server = listener.accept().await?;
                Ok::<_, crate::net::NetError>((client, server))
            },
            reactor.sleep(2_000),
        )
        .await
        {
            Either::First(Ok(pair)) => pair,
            Either::First(Err(_)) => return Err("connect or accept failed"),
            Either::Second(()) => return Err("timed out establishing the connection"),
        };

        client
            .write_all(b"ping over tcp")
            .await
            .map_err(|_| "write")?;
        let mut buf = [0u8; 13];
        // `read_exact` is the one everything above depends on, so it is the one
        // worth proving: a short read here would be indistinguishable from a
        // framing bug much later.
        match select(server.read_exact(&mut buf), reactor.sleep(2_000)).await {
            Either::First(Ok(())) if &buf == b"ping over tcp" => Ok(()),
            Either::First(Ok(())) => Err("read back the wrong bytes"),
            Either::First(Err(_)) => Err("read failed"),
            Either::Second(()) => Err("timed out reading"),
        }
    })
}

fn tcp_refused() -> Result<(), &'static str> {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    block_on(&reactor, async {
        // Bind a listener only to learn a port nothing is listening on, then
        // drop it. Connecting there must fail — and the failure arrives through
        // `SO_ERROR` after the socket reports writable, which is exactly the
        // path a naive implementation skips and then reports success.
        let port = {
            let listener = TcpListener::bind(&reactor, LOCALHOST, 0).map_err(|_| "listen")?;
            listener.local_address().map_err(|_| "getsockname")?.port()
        };

        match select(
            TcpStream::connect(&reactor, LOCALHOST, port),
            reactor.sleep(2_000),
        )
        .await
        {
            Either::First(Ok(_)) => Err("a connection to a closed port reported success"),
            Either::First(Err(_)) => Ok(()),
            Either::Second(()) => Err("timed out instead of being refused"),
        }
    })
}

fn store_roundtrip(state_dir: &str) -> Result<(), &'static str> {
    let store = FileStore::new(state_dir, "selftest.bin").map_err(|_| "open store")?;
    let written = [0xab; 96];
    store.save(&written).map_err(|_| "save")?;

    let mut read = [0u8; 128];
    match store.load(&mut read) {
        Ok(Some(len)) if len == written.len() && read[..len] == written => {}
        Ok(Some(_)) => return Err("read back different bytes"),
        Ok(None) => return Err("nothing was stored"),
        Err(_) => return Err("load failed"),
    }

    // A fresh handle sees the same thing, which is what "survives a reboot"
    // reduces to when there is no process left to remember anything.
    let reopened = FileStore::new(state_dir, "selftest.bin").map_err(|_| "reopen store")?;
    let mut again = [0u8; 128];
    match reopened.load(&mut again) {
        Ok(Some(len)) if again[..len] == written => Ok(()),
        _ => Err("a reopened store disagreed"),
    }
}

fn store_rejects_corruption(state_dir: &str) -> Result<(), &'static str> {
    let store = FileStore::new(state_dir, "corrupt.bin").map_err(|_| "open store")?;
    store.save(&[0x11; 32]).map_err(|_| "save")?;

    // Flip one byte of the payload on disk. The checksum must catch it: a store
    // that reported this as valid would hand out an identity that is one bit
    // away from the one the server knows, and the failure would surface much
    // later as an unexplained authentication error.
    let separator = if state_dir.ends_with('/') { "" } else { "/" };
    let path = Path::new(&[state_dir, separator, "corrupt.bin"]).map_err(|_| "path")?;

    let file = rustix::fs::open(path.as_c_str(), OFlags::RDONLY, Mode::empty())
        .map_err(|_| "open for read")?;
    let mut blob = [0u8; 128];
    let len = rustix::io::read(&file, &mut blob).map_err(|_| "read")?;
    drop(file);
    blob[len / 2] ^= 0x01;

    let file = rustix::fs::open(
        path.as_c_str(),
        OFlags::WRONLY | OFlags::TRUNC,
        Mode::empty(),
    )
    .map_err(|_| "open for write")?;
    rustix::io::write(&file, &blob[..len]).map_err(|_| "write")?;
    drop(file);

    let mut out = [0u8; 128];
    match store.load(&mut out) {
        Err(StoreError::Corrupt) => Ok(()),
        Ok(Some(_)) => Err("a corrupted blob was accepted"),
        Ok(None) => Err("a corrupted blob was reported as absent"),
        Err(_) => Err("the wrong error was reported"),
    }
}

fn timestamps() -> Result<(), &'static str> {
    let first = tai64n();
    let second = tai64n();
    if second < first {
        return Err("went backwards");
    }
    // The top two bits are TAI64's 2^62 origin, and stay set for every date
    // between 1970 and long past when this code will matter. A zero here means
    // the realtime clock was not read at all.
    if first[0] != 0x40 {
        return Err("not a TAI64 external-format label");
    }
    let nanoseconds = u32::from_be_bytes([first[8], first[9], first[10], first[11]]);
    if nanoseconds >= 1_000_000_000 {
        return Err("nanoseconds out of range");
    }
    Ok(())
}

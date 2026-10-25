//! The same traffic contract runs over borrowed and owned storage, with both clocks.
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use embedded_io_async::{Read, Write};
use tailfeather_reactor::{
    exec::{Clock, Reactor},
    tcp::{NetStack, Packet, PacketQueue, Storage},
    tcp_async::{PacketIo, Tcp},
};

struct Link<'a> {
    incoming: &'a Channel<NoopRawMutex, Packet, 8>,
    outgoing: &'a Channel<NoopRawMutex, Packet, 8>,
}
impl PacketIo for Link<'_> {
    type Error = core::convert::Infallible;
    async fn receive(&self, packet: &mut [u8]) -> Result<usize, Self::Error> {
        let bytes = self.incoming.receive().await;
        packet[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    async fn send(&self, packet: &[u8]) -> Result<(), Self::Error> {
        self.outgoing
            .send(Packet::from_slice(packet).unwrap())
            .await;
        Ok(())
    }
}

async fn exchange<'a, C: Clock, B: PacketQueue<8>>(
    clock: C,
    local: NetStack<'a, 8, 8, B>,
    remote: NetStack<'a, 8, 8, B>,
) {
    let clock = Reactor::with_clock(clock);
    let local = Tcp::new(local);
    let remote = Tcp::new(remote);
    local.set_address("100.64.0.1".parse().unwrap(), clock.clock_millis(), 1);
    remote.set_address("100.64.0.2".parse().unwrap(), clock.clock_millis(), 2);
    let a = Channel::new();
    let b = Channel::new();
    let local_io = Link {
        incoming: &a,
        outgoing: &b,
    };
    let remote_io = Link {
        incoming: &b,
        outgoing: &a,
    };
    let transfer = async {
        let mut listener = remote.listen(2222).unwrap();
        let client = async {
            let mut stream = local
                .connect(&clock, "100.64.0.2".parse().unwrap(), 2222, 49152)
                .await
                .unwrap();
            stream.write_all(&[42; 8192]).await.unwrap();
            stream.shutdown().unwrap();
            let mut count = 0;
            let mut buffer = [0; 333];
            loop {
                let len = stream.read(&mut buffer).await.unwrap();
                if len == 0 {
                    break;
                }
                assert!(buffer[..len].iter().all(|byte| *byte == 21));
                count += len;
            }
            assert_eq!(count, 8192);
        };
        let server = async {
            let mut stream = listener.accept().await.unwrap();
            let mut count = 0;
            let mut buffer = [0; 333];
            loop {
                let len = stream.read(&mut buffer).await.unwrap();
                if len == 0 {
                    break;
                }
                assert!(buffer[..len].iter().all(|byte| *byte == 42));
                count += len;
            }
            assert_eq!(count, 8192);
            stream.write_all(&[21; 8192]).await.unwrap();
            stream.shutdown().unwrap();
        };
        tokio::join!(client, server);
        drop(listener);
        let (a, b) = tokio::join!(local.drain(&clock), remote.drain(&clock));
        a.unwrap();
        b.unwrap();
    };
    tokio::select! {
        _ = transfer => {},
        result = local.run(&clock, &local_io) => panic!("driver stopped: {result:?}"),
        result = remote.run(&clock, &remote_io) => panic!("driver stopped: {result:?}"),
        _ = tokio::time::sleep(core::time::Duration::from_secs(3)) => panic!("TCP exchange stalled"),
    }
}

#[tokio::test]
#[cfg(feature = "std")]
async fn borrowed_storage_on_tokio() {
    let mut a = Storage::<8, 512>::new();
    let mut b = Storage::<8, 512>::new();
    exchange(
        tailfeather_reactor::exec::TokioClock::default(),
        NetStack::<8, 8>::with_storage(1, &mut a),
        NetStack::<8, 8>::with_storage(2, &mut b),
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "embassy")]
async fn borrowed_storage_on_embassy() {
    let mut a = Storage::<8, 512>::new();
    let mut b = Storage::<8, 512>::new();
    exchange(
        tailfeather_reactor::exec::EmbassyClock,
        NetStack::<8, 8>::with_storage(1, &mut a),
        NetStack::<8, 8>::with_storage(2, &mut b),
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "std")]
async fn owned_storage_on_tokio() {
    exchange(
        tailfeather_reactor::exec::TokioClock::default(),
        NetStack::<8, 8, std::collections::VecDeque<Packet>>::new(1),
        NetStack::new(2),
    )
    .await;
}

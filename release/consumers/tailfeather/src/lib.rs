#![no_std]

use core::convert::Infallible;
use tailfeather::keys::{Identity, NodePrivate, Rng};
use tailfeather::netmap::{Netmap, Peer};
use tailfeather::{
    ControlCommand, ControlEvent, ControlSession, Endpoint, Node, NodeAction, Transport,
};

struct Fixed;
impl Rng for Fixed {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.fill(3);
    }
}

struct Stream;
impl embedded_io_async::ErrorType for Stream {
    type Error = Infallible;
}
impl embedded_io_async::Read for Stream {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}
impl embedded_io_async::Write for Stream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct FakeTransport;
impl Transport for FakeTransport {
    type Error = Infallible;
    type Stream<'a> = Stream;
    async fn connect<'a>(&'a mut self, _endpoint: &Endpoint) -> Result<Stream, Infallible> {
        Ok(Stream)
    }
}

pub fn lifecycle_compiles() {
    let mut node = Node::<2>::factory_reset(Identity::generate(&mut Fixed), 1);
    node.set_control_endpoint(Endpoint::new("control.example", 443).unwrap());
    node.set_registration_body(b"{}").unwrap();
    let state = match node.poll(0).unwrap().unwrap() {
        NodeAction::PersistState(state) => state,
        _ => unreachable!(),
    };
    node.persistence_result(state.generation(), true).unwrap();
    assert!(matches!(
        node.poll(0),
        Ok(Some(NodeAction::Control(ControlCommand::Connect { .. })))
    ));
    assert!(matches!(
        node.handle_control_event(ControlEvent::Connected),
        Ok(Some(NodeAction::Control(ControlCommand::Register { .. })))
    ));
    node.handle_control_event(ControlEvent::Registered).unwrap();

    let mut map = Netmap::<2>::new();
    map.peers
        .upsert(Peer::new(1, NodePrivate::from_bytes([9; 32]).public()))
        .unwrap();
    node.handle_control_event(ControlEvent::MapFinished {
        lease: &mut map,
        result: Ok(()),
    })
    .unwrap();
    assert_eq!(node.netmap().peers.len(), 1);

    let endpoint = Endpoint::new("control.example", 443).unwrap();
    let mut transport = FakeTransport;
    let _connect = ControlSession::<Stream>::connect(&mut transport, &endpoint);
}

//! Bringing up a ts2021 connection against a real control server.
//!
//! This is the thin layer that turns `ts-noise`'s sans-io pieces into something
//! that talks to a socket. It stops once the Noise channel is established and
//! the early payload has been read, because everything past that point is HTTP/2
//! and does not exist yet.
//!
//! Its value is as an oracle. The handshake ladder is the kind of code that
//! looks right and is wrong, and no test we write against our own understanding
//! can tell the difference — that lesson cost this project real time once
//! already. A real Headscale either derives the same keys or it does not.

use core::net::Ipv4Addr;

use ts_keys::{Identity, MachinePublic, Rng as _};
use ts_noise::{Session, upgrade};
use x25519_dalek::StaticSecret;

use crate::exec::Reactor;
use crate::net::{NetError, TcpStream};
use crate::store::FileStore;
use crate::{HexBytes, OsRng};

/// Big enough for the `/key` response, whose body is one short JSON object.
const HTTP_BUFFER: usize = 2048;

#[derive(Debug, Clone, Copy)]
pub enum ControlError {
    Net(NetError),
    Noise(ts_noise::Error),
    Store(crate::store::StoreError),
    Identity(ts_keys::StoreError),
    Keys(ts_keys::DecodeError),
    Netmap(ts_netmap::Error),
    Disco(ts_disco::Error),
    Derp(ts_derp::Error),
    Http2(crate::h2::H2Error),
    Json(ts_control::JsonError),
    /// The server understood the request and refused it.
    Rejected,
    /// The `/key` response did not contain a machine key.
    NoServerKey,
    /// The server answered, but not with the status we needed.
    UnexpectedStatus(u16),
    /// A response outgrew the fixed buffer.
    ResponseTooLong,
}

impl core::fmt::Display for ControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Net(e) => write!(f, "network: {e}"),
            Self::Noise(e) => write!(f, "ts2021: {e}"),
            Self::Store(e) => write!(f, "state: {e}"),
            Self::Identity(e) => write!(f, "identity: {e}"),
            Self::Keys(e) => write!(f, "key: {e}"),
            Self::Netmap(e) => write!(f, "netmap: {e}"),
            Self::Disco(e) => write!(f, "disco: {e}"),
            Self::Derp(e) => write!(f, "derp: {e}"),
            Self::Http2(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::Rejected => f.write_str("the server refused the registration"),
            Self::NoServerKey => f.write_str("the server published no machine key"),
            Self::UnexpectedStatus(s) => write!(f, "the server answered {s}"),
            Self::ResponseTooLong => f.write_str("response larger than the buffer"),
        }
    }
}

impl From<NetError> for ControlError {
    fn from(e: NetError) -> Self {
        Self::Net(e)
    }
}

impl From<ts_noise::Error> for ControlError {
    fn from(e: ts_noise::Error) -> Self {
        Self::Noise(e)
    }
}

impl ts_keys::Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::rt::getrandom(dest);
    }
}

impl ts_keys::store::Store for FileStore {
    type Error = crate::store::StoreError;

    fn load(&self, out: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        FileStore::load(self, out)
    }

    fn save(&self, blob: &[u8]) -> Result<(), Self::Error> {
        FileStore::save(self, blob)
    }
}

/// Run the whole bootstrap and report what happened at each step.
pub fn run(state_dir: &str, address: Ipv4Addr, port: u16) -> ! {
    let clock = crate::time::Clock::start();
    let reactor = Reactor::new(clock);

    match crate::exec::block_on(&reactor, connect(&reactor, state_dir, address, port)) {
        Ok(_) => {
            evt!("{{\"event\":\"ts2021\",\"result\":\"ok\"}}");
            crate::rt::exit(0)
        }
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"ts2021\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

/// Fetch the netmap, for callers that need its contents rather than a report.
pub async fn load_netmap(
    reactor: &Reactor,
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    hostname: &str,
    endpoints: &[&str],
) -> Result<ts_netmap::Netmap<{ ts_netmap::MAX_PEERS }>, ControlError> {
    fetch_map(reactor, state_dir, address, port, hostname, 1, endpoints).await
}

/// Everything up to an established channel with the early payload consumed.
pub async fn connect<'r>(
    reactor: &'r Reactor,
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
) -> Result<Ts2021<'r>, ControlError> {
    let store = FileStore::new(state_dir, "identity.bin").map_err(ControlError::Store)?;
    let (identity, is_new) = ts_keys::store::load_or_create(&store, &mut OsRng).map_err(|e| {
        match e {
            ts_keys::store::IdentityError::Store(e) => ControlError::Store(e),
            ts_keys::store::IdentityError::Format(e) => ControlError::Identity(e),
        }
    })?;
    report_identity(&identity, is_new);

    // A `Host` header the server will accept. Headscale compares it against its
    // configured server URL only for the redirect it never sends here, but a
    // missing or malformed one is a 400.
    let mut host = [0u8; 32];
    let host = write_host(address, port, &mut host);

    let server_key = fetch_server_key(reactor, address, port, host).await?;
    println!("server machine key: {server_key}");
    evt!("{{\"event\":\"serverkey\",\"key\":\"{server_key}\"}}");

    let mut session = handshake(reactor, address, port, host, &identity, &server_key).await?;
    println!("noise session established");
    evt!("{{\"event\":\"noise\",\"result\":\"ok\"}}");

    read_early_payload(&mut session).await?;
    Ok(session)
}

fn report_identity(identity: &Identity, is_new: bool) {
    println!(
        "identity {}: machine {}",
        if is_new { "created" } else { "loaded" },
        identity.machine.public()
    );
    println!("          node    {}", identity.node.public());
    println!("          disco   {}", identity.disco.public());
    evt!(
        "{{\"event\":\"identity\",\"new\":{},\"machine\":\"{}\",\"node\":\"{}\",\"disco\":\"{}\"}}",
        is_new,
        identity.machine.public(),
        identity.node.public(),
        identity.disco.public()
    );
}

/// `GET /key?v=<capver>`, and pull the machine key out of the JSON.
async fn fetch_server_key(
    reactor: &Reactor,
    address: Ipv4Addr,
    port: u16,
    host: &str,
) -> Result<MachinePublic, ControlError> {
    let stream = TcpStream::connect(reactor, address, port).await?;
    let mut request = [0u8; upgrade::MAX_REQUEST];
    let request = upgrade::write_key_request(host, &mut request)?;
    stream.write_all(request).await?;

    let mut buffer = [0u8; HTTP_BUFFER];
    let mut filled = 0;
    let response = loop {
        // `Connection: close` means the server hangs up when it is done, which
        // is the end-of-body signal for a response with no Content-Length.
        match stream.read(&mut buffer[filled..]).await {
            Ok(0) | Err(NetError::Closed) => break filled,
            Ok(n) => filled += n,
            Err(e) => return Err(e.into()),
        }
        if filled == buffer.len() {
            return Err(ControlError::ResponseTooLong);
        }
    };

    let parsed = upgrade::parse_response(&buffer[..response])?;
    if parsed.status != 200 {
        return Err(ControlError::UnexpectedStatus(parsed.status));
    }
    let body = &buffer[parsed.header_len..response];
    let text = json_string(body, "publicKey").ok_or(ControlError::NoServerKey)?;
    MachinePublic::parse(text).map_err(ControlError::Keys)
}

/// `POST /ts2021`, then the Noise response on the same connection.
async fn handshake<'r>(
    reactor: &'r Reactor,
    address: Ipv4Addr,
    port: u16,
    host: &str,
    identity: &Identity,
    server_key: &MachinePublic,
) -> Result<Ts2021<'r>, ControlError> {
    // A fresh connection: the `/key` one was closed, and the upgrade has to be
    // the first request on the connection it takes over.
    let stream = TcpStream::connect(reactor, address, port).await?;

    let mut ephemeral_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral = StaticSecret::from(ephemeral_bytes);

    let mut initiation = [0u8; ts_noise::INITIATION_LEN];
    let (len, handshake) = ts_noise::initiate(
        identity.machine.secret(),
        server_key.as_public(),
        &ephemeral,
        &mut initiation,
    )?;
    println!("-> initiation, {len} bytes");

    let mut request = [0u8; upgrade::MAX_REQUEST];
    let request = upgrade::write_upgrade_request(host, &initiation[..len], &mut request)?;
    stream.write_all(request).await?;

    // Read until the blank line. The Noise response may already be in the same
    // segment, which is why the parser reports where the headers ended instead
    // of consuming everything it was handed.
    let mut buffer = [0u8; HTTP_BUFFER];
    let mut filled = 0;
    let parsed = loop {
        match upgrade::parse_response(&buffer[..filled]) {
            Ok(parsed) => break parsed,
            Err(ts_noise::Error::Incomplete) => {}
            Err(e) => return Err(e.into()),
        }
        let n = stream.read(&mut buffer[filled..]).await?;
        filled += n;
        if filled == buffer.len() {
            return Err(ControlError::ResponseTooLong);
        }
    };

    if !upgrade::is_upgrade(&buffer[..filled], parsed) {
        println!("!! the server refused the upgrade: status {}", parsed.status);
        return Err(ControlError::UnexpectedStatus(parsed.status));
    }
    println!("<- 101 Switching Protocols");

    let mut response = [0u8; ts_noise::RESPONSE_LEN];
    let already = (filled - parsed.header_len).min(ts_noise::RESPONSE_LEN);
    response[..already].copy_from_slice(&buffer[parsed.header_len..parsed.header_len + already]);
    if already < ts_noise::RESPONSE_LEN {
        stream.read_exact(&mut response[already..]).await?;
    }
    println!("<- noise response, {} bytes", response.len());

    let session = handshake.consume_response(&response)?;
    Ok(Ts2021 {
        stream,
        session,
        pushback: heapless::Vec::new(),
    })
}

/// An established connection: the record layer plus the socket under it.
pub struct Ts2021<'r> {
    stream: TcpStream<'r>,
    session: Session,
    /// Decrypted bytes read past the early payload. These are already HTTP/2
    /// and must be handed on rather than dropped.
    pushback: heapless::Vec<u8, { ts_noise::MAX_PLAINTEXT }>,
}

impl<'r> Ts2021<'r> {
    /// Read and decrypt one record.
    async fn read_record(&mut self, out: &mut [u8]) -> Result<usize, ControlError> {
        let mut header = [0u8; ts_noise::HEADER_LEN];
        self.stream.read_exact(&mut header).await?;
        let len = Session::ciphertext_len(&header)?;

        let mut ciphertext = [0u8; ts_noise::MAX_MESSAGE];
        self.stream.read_exact(&mut ciphertext[..len]).await?;
        Ok(self.session.open(&ciphertext[..len], out)?)
    }

    /// Hand the connection to the HTTP/2 layer.
    pub async fn into_http2(self) -> Result<crate::h2::Http2<'r>, ControlError> {
        crate::h2::Http2::start(self.stream, self.session, &self.pushback)
            .await
            .map_err(ControlError::Http2)
    }
}

/// Read records until the early-payload question is settled.
///
/// The capture shows Headscale sending the nine-byte probe split across three
/// records, so this must keep reading rather than deciding on the first one.
async fn read_early_payload(session: &mut Ts2021<'_>) -> Result<(), ControlError> {
    let mut reader = ts_noise::EarlyReader::new();
    let mut plaintext = [0u8; ts_noise::MAX_PLAINTEXT];

    while !reader.is_complete() {
        let len = session.read_record(&mut plaintext).await?;
        println!("<- record, {len} bytes of plaintext");
        let consumed = reader.push(&plaintext[..len])?;
        // A record can hold the tail of the early payload and the start of the
        // HTTP/2 preface. Whatever was not consumed is already HTTP/2.
        if consumed < len {
            session
                .pushback
                .extend_from_slice(&plaintext[consumed..len])
                .map_err(|_| ControlError::ResponseTooLong)?;
        }
    }

    match reader.finish()? {
        ts_noise::early::Early::Payload(payload) => {
            println!("<- early payload, {} bytes", payload.len());
            match core::str::from_utf8(payload) {
                Ok(text) => println!("   {text}"),
                Err(_) => println!("   {}", HexBytes(payload)),
            }
            evt!(
                "{{\"event\":\"early\",\"present\":true,\"len\":{}}}",
                payload.len()
            );
        }
        ts_noise::early::Early::PushBack(bytes) => {
            // Not an error: a server without an early payload starts HTTP/2
            // immediately, and these nine bytes are its first frame header.
            println!("<- no early payload; first HTTP/2 header {}", HexBytes(bytes));
            evt!("{{\"event\":\"early\",\"present\":false}}");
            // Those nine bytes belong to HTTP/2. Dropping them would leave its
            // parser permanently one frame header short.
            // Those nine bytes belong to HTTP/2. Dropping them would leave its
            // parser permanently one frame header short.
            let mut carried = heapless::Vec::<u8, { ts_noise::MAX_PLAINTEXT }>::new();
            let _ = carried.extend_from_slice(bytes);
            let _ = carried.extend_from_slice(&session.pushback);
            session.pushback = carried;
        }
    }
    Ok(())
}

/// Pull a string field out of a flat JSON object.
///
/// Deliberately crude: the `/key` response is one object with two string
/// fields, and a real parser arrives with the netmap, which is the first thing
/// that needs one.
pub fn json_string<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let text = core::str::from_utf8(body).ok()?;
    let mut pattern = [0u8; 64];
    let quoted = {
        pattern[0] = b'"';
        pattern[1..1 + field.len()].copy_from_slice(field.as_bytes());
        pattern[1 + field.len()] = b'"';
        core::str::from_utf8(&pattern[..field.len() + 2]).ok()?
    };
    let start = text.find(quoted)? + quoted.len();
    let rest = text[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// `a.b.c.d:port`, for the `Host` header.
pub fn write_host(address: Ipv4Addr, port: u16, out: &mut [u8; 32]) -> &str {
    use core::fmt::Write as _;

    struct Buffer<'a>(&'a mut [u8; 32], usize);
    impl core::fmt::Write for Buffer<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.1 + s.len();
            if end > self.0.len() {
                return Err(core::fmt::Error);
            }
            self.0[self.1..end].copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }

    let mut buffer = Buffer(out, 0);
    let _ = write!(buffer, "{address}:{port}");
    let len = buffer.1;
    core::str::from_utf8(&out[..len]).expect("an address and a port are ASCII")
}

/// Register with the control server using a preauth key.
#[allow(clippy::too_many_arguments)]
pub fn run_register(
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    auth_key: &str,
    hostname: &str,
    exit_node: bool,
    rotate: bool,
) -> ! {
    let clock = crate::time::Clock::start();
    let reactor = Reactor::new(clock);

    let work = register(
        &reactor, state_dir, address, port, auth_key, hostname, exit_node, rotate,
    );
    match crate::exec::block_on(&reactor, work) {
        Ok(()) => {
            evt!("{{\"event\":\"register\",\"result\":\"ok\"}}");
            crate::rt::exit(0)
        }
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"register\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn register(
    reactor: &Reactor,
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    auth_key: &str,
    hostname: &str,
    exit_node: bool,
    rotate: bool,
) -> Result<(), ControlError> {
    let store = FileStore::new(state_dir, "identity.bin").map_err(ControlError::Store)?;
    let (mut identity, _) = ts_keys::store::load_or_create(&store, &mut OsRng).map_err(|e| match e {
        ts_keys::store::IdentityError::Store(e) => ControlError::Store(e),
        ts_keys::store::IdentityError::Format(e) => ControlError::Identity(e),
    })?;

    // Rotating replaces the node key while the machine key — the identity the
    // control plane authenticated — stays put. That separation is the whole
    // reason the two are different keys: the node can get a new data-plane
    // identity without becoming a new machine.
    let retired = rotate.then(|| identity.node.public());
    if rotate {
        identity.node = ts_keys::NodePrivate::generate(&mut OsRng);
        println!("rotating node key: {} -> {}", retired.unwrap(), identity.node.public());
    }

    let session = connect(reactor, state_dir, address, port).await?;
    let mut http2 = session.into_http2().await?;
    println!("http/2 connection established");
    evt!("{{\"event\":\"http2\",\"result\":\"ok\"}}");

    let mut host = [0u8; 32];
    let host = write_host(address, port, &mut host);

    let node_key = identity.node.public();
    let old_node_key = retired.as_ref();
    let request = ts_control::RegisterRequest {
        version: ts_control::CAPABILITY_VERSION,
        node_key: &node_key,
        old_node_key,
        auth_key,
        hostinfo: ts_control::Hostinfo {
            // Supplied by the caller so that a conformance run can tag the nodes
            // it creates and delete exactly those afterwards. Defaults to the
            // plain product name on a real device.
            hostname,
            routable_ips: if exit_node {
                &ts_control::EXIT_NODE_ROUTES
            } else {
                &[]
            },
            ..Default::default()
        },
        ephemeral: false,
    };

    let mut body = [0u8; 1024];
    let body = request.write(&mut body).map_err(ControlError::Json)?;
    println!("-> POST {} ({} bytes)", ts_control::register::PATH, body.len());

    let mut response = [0u8; 4096];
    let (status, len) = http2
        .request("POST", ts_control::register::PATH, host, body, &mut response)
        .await
        .map_err(ControlError::Http2)?;

    let text = core::str::from_utf8(&response[..len]).unwrap_or("");
    println!("<- {status}, {len} bytes");
    if status != 200 {
        println!("   {text}");
        return Err(ControlError::UnexpectedStatus(status));
    }

    let parsed = ts_control::RegisterResponse::parse(text);
    if !parsed.is_success() {
        println!("   {text}");
        if !parsed.auth_url.is_empty() {
            // A headless node cannot follow a login URL, so this is a failure
            // rather than a step. It is what an expired or spent preauth key
            // looks like.
            println!("!! the server wants an interactive login at {}", parsed.auth_url);
        }
        return Err(ControlError::Rejected);
    }

    // Only once the server has accepted it: persisting a key the server never
    // saw would leave the node holding an identity nobody recognises.
    if rotate {
        let blob = identity.to_blob();
        store.save(&blob.0).map_err(ControlError::Store)?;
    }

    println!("registered: node {node_key} as '{}'", parsed.login_name);
    evt!(
        "{{\"event\":\"registered\",\"node\":\"{}\",\"login\":\"{}\",\"exit_node\":{},\"rotated\":{}}}",
        node_key,
        parsed.login_name,
        exit_node,
        old_node_key.is_some()
    );
    Ok(())
}

/// Ask for the network map once and report how the server framed it.
///
/// This exists to answer one question with bytes rather than with reasoning:
/// does a server send an uncompressed map when the request does not ask for
/// compression? Every zstd decoder in Rust needs an allocator, so if the answer
/// is no, the no-allocation property of this whole project is in question and
/// the netmap parser cannot be written as planned.
pub fn run_map(
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    hostname: &str,
    wanted: usize,
) -> ! {
    let clock = crate::time::Clock::start();
    let reactor = Reactor::new(clock);

    let work = fetch_map(&reactor, state_dir, address, port, hostname, wanted, &[]);
    match crate::exec::block_on(&reactor, work) {
        Ok(_) => crate::rt::exit(0),
        Err(e) => {
            println!("FAIL {e}");
            evt!("{{\"event\":\"map\",\"result\":\"fail\"}}");
            crate::rt::exit(1)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_map(
    reactor: &Reactor,
    state_dir: &str,
    address: Ipv4Addr,
    port: u16,
    hostname: &str,
    wanted: usize,
    endpoints: &[&str],
) -> Result<ts_netmap::Netmap<{ ts_netmap::MAX_PEERS }>, ControlError> {
    let store = FileStore::new(state_dir, "identity.bin").map_err(ControlError::Store)?;
    let (identity, _) = ts_keys::store::load_or_create(&store, &mut OsRng).map_err(|e| match e {
        ts_keys::store::IdentityError::Store(e) => ControlError::Store(e),
        ts_keys::store::IdentityError::Format(e) => ControlError::Identity(e),
    })?;

    let session = connect(reactor, state_dir, address, port).await?;
    let mut http2 = session.into_http2().await?;

    let mut host = [0u8; 32];
    let host = write_host(address, port, &mut host);

    let request = ts_control::MapRequest {
        version: ts_control::CAPABILITY_VERSION,
        node_key: &identity.node.public(),
        disco_key: &identity.disco.public(),
        hostinfo: ts_control::Hostinfo {
            hostname,
            ..Default::default()
        },
        // The long poll is the only form that returns a map at all.
        stream: true,
        omit_peers: false,
        read_only: false,
        // Where peers should try to reach us. Without this the server has
        // nothing to tell them, so nobody ever probes us and every path has to
        // be discovered from our side alone.
        endpoints,
    };

    let mut body = [0u8; 1024];
    let body = request.write(&mut body).map_err(ControlError::Json)?;
    println!("-> POST {} ({} bytes)", ts_control::map::PATH, body.len());

    // A map request must be a long poll: Headscale answers a non-streaming one
    // with an empty 200, treating it as an endpoint update.
    let stream_id = http2
        .send_request("POST", ts_control::map::PATH, host, body)
        .await
        .map_err(ControlError::Http2)?;

    let mut netmap = ts_netmap::Netmap::<{ ts_netmap::MAX_PEERS }>::new();
    let mut frames = ts_netmap::FrameReader::new();
    let mut chunk = [0u8; 16384];
    let mut applied = 0usize;
    let mut compressed_seen = false;
    let mut first_frame = 0usize;

    let mut parser = ts_netmap::Parser::<{ ts_netmap::MAX_PEERS }>::new();

    while applied < wanted {
        let (len, finished) = http2
            .read_chunk(stream_id, &mut chunk)
            .await
            .map_err(ControlError::Http2)?;
        if http2.status() != 200 {
            println!("<- status {}", http2.status());
            return Err(ControlError::UnexpectedStatus(http2.status()));
        }

        let mut input: &[u8] = &chunk[..len];
        loop {
            let (piece, consumed) = frames.next(input).map_err(ControlError::Netmap)?;
            input = &input[consumed..];
            match piece {
                ts_netmap::frame::Chunk::Body(bytes) => {
                    if first_frame == 0 {
                        first_frame = bytes.len();
                        // Answering the phase gate: a zstd frame starts with
                        // 0xfd2fb528 little-endian, plain JSON with '{'.
                        compressed_seen = bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
                    }
                    parser.push(&mut netmap, bytes).map_err(ControlError::Netmap)?;
                    if frames.is_complete() {
                        frames.finish_response();
                        // One parser per response: the netmap is carried across
                        // them, but a JSON document is not, and feeding two into
                        // one scanner is a syntax error rather than two maps.
                        core::mem::take(&mut parser)
                            .finish(&mut netmap)
                            .map_err(ControlError::Netmap)?;
                        applied += 1;
                        report_netmap(&netmap, applied, compressed_seen);
                        configure_peers(&identity, &netmap);
                    }
                }
                ts_netmap::frame::Chunk::End => {
                    applied += 1;
                    println!("<- keepalive (zero-length response)");
                }
                ts_netmap::frame::Chunk::Need if consumed == 0 => break,
                ts_netmap::frame::Chunk::Need => {}
            }
        }

        if finished {
            println!("!! the map stream ended after {applied} response(s)");
            break;
        }
    }
    Ok(netmap)
}

/// Print what one applied MapResponse left behind.
fn report_netmap(netmap: &ts_netmap::Netmap<{ ts_netmap::MAX_PEERS }>, applied: usize, compressed: bool) {
    println!(
        "<- map {applied}: {} peer(s), {} DERP region(s)",
        netmap.peers.len(),
        netmap.derp.len()
    );
    for peer in netmap.peers.iter() {
        let mut endpoint = heapless::String::<48>::new();
        if let Some(direct) = peer.direct_endpoint() {
            let _ = core::fmt::Write::write_fmt(&mut endpoint, format_args!("{direct}"));
        } else {
            let _ = endpoint.push_str("(none)");
        }
        let mut address = heapless::String::<24>::new();
        if let Some(ip) = peer.tailscale_ipv4() {
            let _ = core::fmt::Write::write_fmt(&mut address, format_args!("{ip}"));
        }
        println!(
            "   peer {} {address} online={} derp={} endpoint={endpoint}",
            peer.id, peer.online, peer.home_derp
        );
        evt!(
            "{{\"event\":\"peer\",\"id\":{},\"key\":\"{}\",\"address\":\"{address}\",\"online\":{},\"derp\":{},\"endpoint\":\"{endpoint}\",\"disco\":{}}}",
            peer.id,
            peer.node_key,
            peer.online,
            peer.home_derp,
            peer.disco_key.is_some()
        );
    }
    for region in netmap.derp.iter() {
        for node in region.nodes.iter() {
            println!("   derp region {} '{}' {}:{}", region.id, region.code, node.host_name, node.port);
            evt!(
                "{{\"event\":\"derp\",\"region\":{},\"code\":\"{}\",\"host\":\"{}\",\"port\":{},\"stun\":{}}}",
                region.id,
                region.code,
                node.host_name,
                node.port,
                node.stun_port
            );
        }
    }
    evt!(
        "{{\"event\":\"map\",\"applied\":{applied},\"peers\":{},\"regions\":{},\"compressed\":{compressed},\"responses\":{}}}",
        netmap.peers.len(),
        netmap.derp.len(),
        netmap.responses
    );
}

/// Turn the netmap into a WireGuard peer table.
///
/// The node key *is* the WireGuard key — that is what makes the netmap a data
/// plane configuration rather than a directory. Each peer the server named
/// becomes a peer of the device, set to initiate, so whichever side notices a
/// missing session first starts the handshake.
///
/// The device is built and reported rather than kept, because the tunnel itself
/// is the next phase's work; what this proves is that a netmap contains
/// everything needed to configure one.
fn configure_peers(identity: &Identity, netmap: &ts_netmap::Netmap<{ ts_netmap::MAX_PEERS }>) {
    let mut device: wg_core::Device<{ ts_netmap::MAX_PEERS }> =
        wg_core::Device::new(identity.node.to_bytes());

    let mut configured = 0usize;
    let mut reachable = 0usize;
    for peer in netmap.peers.iter() {
        let Ok(id) = device.add_peer(*peer.node_key.as_bytes(), None) else {
            println!("!! more peers than the device table holds");
            break;
        };
        // Both sides of a mesh link are symmetric, unlike a gateway serving a
        // client, so either may start the handshake.
        let _ = device.set_initiating(id, true);
        configured += 1;
        if peer.direct_endpoint().is_some() {
            reachable += 1;
        }
    }

    // The device's own key must be the node key the server knows, or peers
    // would encrypt to an identity this node cannot decrypt with.
    let matches_netmap = device.public_key() == *identity.node.public().as_bytes();
    println!(
        "   configured {configured} wireguard peer(s), {reachable} with a direct endpoint"
    );
    evt!(
        "{{\"event\":\"peers\",\"configured\":{configured},\"reachable\":{reachable},\"key_matches\":{matches_netmap}}}"
    );
}

//! Transport-independent ts2021 Noise and HTTP/2 control sessions.
//!
//! TCP, DNS, and TLS stay in the platform adapter. Once an adapter yields an
//! [`embedded_io_async`] stream, this module performs the same `/key`, Noise
//! upgrade, registration, streaming-map, and endpoint-update protocol on a
//! workstation or an Embassy target.

use core::borrow::BorrowMut;

use embedded_io_async::{Read, Write};
use micro_h2::{Connection, Event, frame};
use x25519_dalek::StaticSecret;

use crate::control::CAPABILITY_VERSION;
use crate::keys::{Identity, MachinePublic, Rng};
use crate::netmap::{FrameReader, Netmap, Parser};
use crate::noise::{self, Session, upgrade};

const HTTP_BUFFER: usize = 2048;
// Control frames and response headers are small. DATA payloads are streamed
// through a separate record-sized plaintext window rather than retained as a
// complete 16 KiB HTTP/2 frame.
pub const H2_BUFFER: usize = 2 * 1024;
const H2_OUT_BUFFER: usize = 4096;
const H2_STATUS_SLOTS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub enum Error<E> {
    Io(E),
    UnexpectedEof,
    Noise(noise::Error),
    Http2(micro_h2::Error),
    Netmap(crate::netmap::Error),
    NoServerKey,
    Key(crate::keys::DecodeError),
    UnexpectedStatus(u16),
    ResponseTooLong,
    FrameTooLarge,
    InterleavedStream(u32),
    StreamEnded,
}

impl<E: core::fmt::Display> core::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "control I/O: {error}"),
            Self::UnexpectedEof => f.write_str("control stream ended mid-message"),
            Self::Noise(error) => write!(f, "ts2021: {error}"),
            Self::Http2(error) => write!(f, "HTTP/2: {error}"),
            Self::Netmap(error) => write!(f, "netmap: {error}"),
            Self::NoServerKey => f.write_str("control server published no machine key"),
            Self::Key(error) => write!(f, "control key: {error}"),
            Self::UnexpectedStatus(status) => write!(f, "control server answered {status}"),
            Self::ResponseTooLong => f.write_str("control response exceeds its static buffer"),
            Self::FrameTooLarge => f.write_str("HTTP/2 frame exceeds its static buffer"),
            Self::InterleavedStream(stream) => {
                write!(f, "HTTP/2 stream {stream} requires its own consumer")
            }
            Self::StreamEnded => f.write_str("streaming map ended"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> core::error::Error for Error<E> {}

fn read_error<E>(error: embedded_io_async::ReadExactError<E>) -> Error<E> {
    match error {
        embedded_io_async::ReadExactError::UnexpectedEof => Error::UnexpectedEof,
        embedded_io_async::ReadExactError::Other(error) => Error::Io(error),
    }
}

async fn read_exact_progress<S>(
    stream: &mut S,
    output: &mut [u8],
    filled: &mut u16,
) -> Result<(), Error<S::Error>>
where
    S: Read,
{
    while usize::from(*filled) < output.len() {
        let start = usize::from(*filled);
        let amount = stream.read(&mut output[start..]).await.map_err(Error::Io)?;
        if amount == 0 {
            return Err(Error::UnexpectedEof);
        }
        *filled += amount as u16;
    }
    Ok(())
}

/// Read `GET /key` from a connection the platform has already authenticated.
pub async fn fetch_server_key<S>(
    stream: &mut S,
    authority: &str,
) -> Result<MachinePublic, Error<S::Error>>
where
    S: Read + Write,
{
    let mut request = [0; upgrade::MAX_REQUEST];
    let request = upgrade::write_key_request(authority, &mut request).map_err(Error::Noise)?;
    stream.write_all(request).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut response = [0; HTTP_BUFFER];
    let mut filled = 0;
    loop {
        if filled == response.len() {
            return Err(Error::ResponseTooLong);
        }
        if let Some(complete) = response_length(&response[..filled]).map_err(Error::Noise)? {
            if complete > response.len() {
                return Err(Error::ResponseTooLong);
            }
            if filled >= complete {
                break;
            }
        }
        let read = stream
            .read(&mut response[filled..])
            .await
            .map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    let parsed = upgrade::parse_response(&response[..filled]).map_err(Error::Noise)?;
    if parsed.status != 200 {
        return Err(Error::UnexpectedStatus(parsed.status));
    }
    let body = &response[parsed.header_len..filled];
    let key = json_string(body, "publicKey").ok_or(Error::NoServerKey)?;
    MachinePublic::parse(key).map_err(Error::Key)
}

/// Stop at an explicit HTTP/1 body boundary instead of waiting for the peer to
/// close TLS. Some embedded TCP adapters surface a clean TLS `close_notify` or
/// the following FIN as an I/O error, even after the complete response arrived.
fn response_length(response: &[u8]) -> Result<Option<usize>, noise::Error> {
    let Some(header_end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return Ok(None);
    };
    let header_len = header_end + 4;
    let headers =
        core::str::from_utf8(&response[..header_end]).map_err(|_| noise::Error::Malformed)?;
    let mut content_length = None;
    for line in headers.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(noise::Error::Malformed);
        };
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| noise::Error::Malformed)?;
            if content_length.replace(length).is_some() {
                return Err(noise::Error::Malformed);
            }
        }
    }
    let Some(content_length) = content_length else {
        return Ok(None);
    };
    header_len
        .checked_add(content_length)
        .map(Some)
        .ok_or(noise::Error::Malformed)
}

/// The first ts2021 handshake message, ready to send.
///
/// Over TCP it travels base64-encoded in the `X-Tailscale-Handshake` header of
/// the `POST /ts2021` upgrade. A WebSocket client cannot set request headers,
/// so it carries the same bytes in the query string instead; either way the
/// bytes exist before the stream that will carry the response.
pub struct Initiation {
    bytes: [u8; noise::INITIATION_LEN],
    len: usize,
}

impl Initiation {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Client handshake state between [`initiate`] and [`complete`].
pub struct PendingHandshake {
    handshake: noise::Handshake,
}

/// Start a ts2021 handshake without touching any stream.
///
/// This is the half of [`establish`] a transport needs when the initiation must
/// be known before the connection is opened, as with ts2021 over WebSocket.
pub fn initiate(
    identity: &Identity,
    server_key: &MachinePublic,
    rng: &mut impl Rng,
) -> Result<(Initiation, PendingHandshake), noise::Error> {
    let mut ephemeral = [0; 32];
    rng.fill_bytes(&mut ephemeral);
    let ephemeral = StaticSecret::from(ephemeral);
    let mut bytes = [0; noise::INITIATION_LEN];
    let (len, handshake) = noise::initiate(
        identity.machine.secret(),
        server_key.as_public(),
        &ephemeral,
        &mut bytes,
    )?;
    Ok((Initiation { bytes, len }, PendingHandshake { handshake }))
}

/// Finish a handshake on a stream whose next bytes are the server's Noise
/// response, with no HTTP/1.1 exchange in front of it.
///
/// This is the WebSocket shape. There the server may say nothing more until
/// the client's HTTP/2 preface arrives, so the optional early payload is read
/// only once HTTP/2 has started; see [`DeferredNoiseStream`].
pub async fn complete<S>(
    mut stream: S,
    pending: PendingHandshake,
) -> Result<DeferredNoiseStream<S>, Error<S::Error>>
where
    S: Read + Write,
{
    let session = read_noise_response(&mut stream, pending, &[]).await?;
    Ok(DeferredNoiseStream { stream, session })
}

/// Read the server's Noise response, of which the first `carried` bytes were
/// already read from the stream, and derive the record session.
async fn read_noise_response<S>(
    stream: &mut S,
    pending: PendingHandshake,
    carried: &[u8],
) -> Result<Session, Error<S::Error>>
where
    S: Read + Write,
{
    let mut noise_response = [0; noise::RESPONSE_LEN];
    let carried = &carried[..carried.len().min(noise_response.len())];
    noise_response[..carried.len()].copy_from_slice(carried);
    if carried.len() < noise_response.len() {
        stream
            .read_exact(&mut noise_response[carried.len()..])
            .await
            .map_err(read_error)?;
    }
    pending
        .handshake
        .consume_response(&noise_response)
        .map_err(Error::Noise)
}

/// Read records until the early-payload question is answered. Plaintext past
/// the payload — or the probe itself, when it was not the payload magic —
/// belongs to HTTP/2 and is left in `pushback`.
async fn read_early_payload<S>(
    stream: &mut S,
    session: &mut Session,
    pushback: &mut heapless::Vec<u8, { noise::MAX_PLAINTEXT }>,
) -> Result<(), Error<S::Error>>
where
    S: Read,
{
    let mut reader = noise::EarlyReader::new();
    let mut plaintext = [0; noise::MAX_PLAINTEXT];
    while !reader.is_complete() {
        let len = read_record(stream, session, &mut plaintext).await?;
        let consumed = reader.push(&plaintext[..len]).map_err(Error::Noise)?;
        pushback
            .extend_from_slice(&plaintext[consumed..len])
            .map_err(|_| Error::ResponseTooLong)?;
    }
    if let noise::early::Early::PushBack(bytes) = reader.finish().map_err(Error::Noise)? {
        let mut carried = heapless::Vec::new();
        carried
            .extend_from_slice(bytes)
            .map_err(|_| Error::ResponseTooLong)?;
        carried
            .extend_from_slice(pushback)
            .map_err(|_| Error::ResponseTooLong)?;
        *pushback = carried;
    }
    Ok(())
}

async fn read_record<S>(
    stream: &mut S,
    session: &mut Session,
    out: &mut [u8],
) -> Result<usize, Error<S::Error>>
where
    S: Read,
{
    let mut header = [0; noise::HEADER_LEN];
    stream.read_exact(&mut header).await.map_err(read_error)?;
    let len = Session::ciphertext_len(&header).map_err(Error::Noise)?;
    let mut ciphertext = [0; noise::MAX_MESSAGE];
    stream
        .read_exact(&mut ciphertext[..len])
        .await
        .map_err(read_error)?;
    session.open(&ciphertext[..len], out).map_err(Error::Noise)
}

/// Upgrade a fresh authenticated stream to ts2021 and consume its optional
/// early payload. The returned stream is ready for one reusable HTTP/2 session.
///
/// Composed of [`initiate`] and the same Noise-response handling as
/// [`complete`] around the HTTP/1.1 upgrade. Over HTTP/1.1 the server sends
/// its early payload straight away, so it is consumed here.
pub async fn establish<S>(
    mut stream: S,
    authority: &str,
    identity: &Identity,
    server_key: &MachinePublic,
    rng: &mut impl Rng,
) -> Result<NoiseStream<S>, Error<S::Error>>
where
    S: Read + Write,
{
    let (initiation, pending) = initiate(identity, server_key, rng).map_err(Error::Noise)?;
    let mut request = [0; upgrade::MAX_REQUEST];
    let request = upgrade::write_upgrade_request(authority, initiation.as_bytes(), &mut request)
        .map_err(Error::Noise)?;
    stream.write_all(request).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    let mut response = [0; HTTP_BUFFER];
    let mut filled = 0;
    let parsed = loop {
        match upgrade::parse_response(&response[..filled]) {
            Ok(parsed) => break parsed,
            Err(noise::Error::Incomplete) => {}
            Err(error) => return Err(Error::Noise(error)),
        }
        if filled == response.len() {
            return Err(Error::ResponseTooLong);
        }
        // Stop exactly at the header boundary. A larger speculative read would
        // require retaining up to another 2 KiB of encrypted Noise bytes for
        // the lifetime of the HTTP/2 connection.
        let read = stream
            .read(&mut response[filled..filled + 1])
            .await
            .map_err(Error::Io)?;
        if read == 0 {
            return Err(Error::UnexpectedEof);
        }
        filled += read;
    };
    if !upgrade::is_upgrade(&response[..filled], parsed) {
        return Err(Error::UnexpectedStatus(parsed.status));
    }
    let session =
        read_noise_response(&mut stream, pending, &response[parsed.header_len..filled]).await?;
    let mut stream = NoiseStream {
        stream,
        session,
        pushback: heapless::Vec::new(),
    };
    stream.read_early().await?;
    Ok(stream)
}

pub struct NoiseStream<S> {
    stream: S,
    session: Session,
    pushback: heapless::Vec<u8, { noise::MAX_PLAINTEXT }>,
}

impl<S> NoiseStream<S>
where
    S: Read + Write,
{
    async fn read_early(&mut self) -> Result<(), Error<S::Error>> {
        read_early_payload(&mut self.stream, &mut self.session, &mut self.pushback).await
    }

    pub async fn into_http2(self) -> Result<Http2<S>, Error<S::Error>> {
        Http2::start_carried(self.stream, self.session, &self.pushback, false).await
    }

    /// Start HTTP/2 with an HTTPS pseudo-scheme after a verified TLS adapter.
    pub async fn into_https2(self) -> Result<Http2<S>, Error<S::Error>> {
        Http2::start_carried(self.stream, self.session, &self.pushback, true).await
    }

    /// Start HTTPS-flavoured HTTP/2 directly in caller-owned storage.
    ///
    /// Embedded executors otherwise reserve space for both the returned
    /// connection and the future receiving it. Placing the connection before
    /// the first HTTP/2 write keeps exactly one copy alive.
    pub async fn into_https2_placed<'a>(
        self,
        place: impl FnOnce(Http2<S>) -> &'a mut Http2<S>,
    ) -> Result<&'a mut Http2<S>, Error<S::Error>>
    where
        S: 'a,
    {
        Http2::start_carried_placed(self.stream, self.session, &self.pushback, true, place).await
    }

    /// Start plaintext-flavoured HTTP/2 directly in caller-owned storage.
    pub async fn into_http2_placed<'a>(
        self,
        place: impl FnOnce(Http2<S>) -> &'a mut Http2<S>,
    ) -> Result<&'a mut Http2<S>, Error<S::Error>>
    where
        S: 'a,
    {
        Http2::start_carried_placed(self.stream, self.session, &self.pushback, false, place).await
    }

    pub async fn into_https2_with_buffer(
        self,
        buffer: &mut [u8; H2_BUFFER],
    ) -> Result<Http2<S, &mut [u8; H2_BUFFER]>, Error<S::Error>> {
        Http2::start_with_storage(
            self.stream,
            self.session,
            &self.pushback,
            true,
            buffer,
            Connection::new(),
        )
        .await
    }

    /// Start HTTPS-flavoured HTTP/2 using caller-owned receive and protocol state.
    /// The connection state is reset for each session, allowing reconnects to
    /// reuse one allocation-free slot without copying it through async futures.
    pub async fn into_https2_with_storage<'a>(
        self,
        buffer: &'a mut [u8; H2_BUFFER],
        connection: &'a mut Connection,
    ) -> Result<Http2<S, &'a mut [u8; H2_BUFFER], &'a mut Connection>, Error<S::Error>> {
        self.into_carried_with_storage(buffer, connection, true)
            .await
    }

    /// Start plaintext-flavoured HTTP/2 using reusable receive and protocol state.
    pub async fn into_http2_with_storage<'a>(
        self,
        buffer: &'a mut [u8; H2_BUFFER],
        connection: &'a mut Connection,
    ) -> Result<Http2<S, &'a mut [u8; H2_BUFFER], &'a mut Connection>, Error<S::Error>> {
        self.into_carried_with_storage(buffer, connection, false)
            .await
    }

    async fn into_carried_with_storage<'a>(
        self,
        buffer: &'a mut [u8; H2_BUFFER],
        connection: &'a mut Connection,
        secure: bool,
    ) -> Result<Http2<S, &'a mut [u8; H2_BUFFER], &'a mut Connection>, Error<S::Error>> {
        *connection = Connection::new();
        Http2::start_with_storage(
            self.stream,
            self.session,
            &self.pushback,
            secure,
            buffer,
            connection,
        )
        .await
    }
}

/// A ts2021 stream from [`complete`] whose optional early payload has not been
/// read yet.
///
/// Starting HTTP/2 writes the client preface first and then reads the early
/// payload, because a WebSocket-accepting server may send nothing — neither
/// the payload nor its own HTTP/2 preface — until the client has spoken.
pub struct DeferredNoiseStream<S> {
    stream: S,
    session: Session,
}

impl<S> DeferredNoiseStream<S>
where
    S: Read + Write,
{
    pub async fn into_http2(self) -> Result<Http2<S>, Error<S::Error>> {
        let mut http2 = Http2::start_carried(self.stream, self.session, &[], false).await?;
        http2.read_deferred_early().await?;
        Ok(http2)
    }

    /// Start HTTP/2 with an HTTPS pseudo-scheme, as over a `wss:` socket.
    pub async fn into_https2(self) -> Result<Http2<S>, Error<S::Error>> {
        let mut http2 = Http2::start_carried(self.stream, self.session, &[], true).await?;
        http2.read_deferred_early().await?;
        Ok(http2)
    }
}

/// One reusable HTTP/2 connection over the ts2021 record layer.
///
/// The default `B = [u8; H2_BUFFER]` owns its receive storage and remains the
/// convenient host interface. Firmware may borrow caller-owned storage through
/// [`NoiseStream::into_https2_with_buffer`] so reconnects can reuse it.
/// The `C` parameter similarly allows [`NoiseStream::into_https2_with_storage`]
/// to borrow the protocol state instead of carrying it through async futures.
pub struct Http2<S, B = [u8; H2_BUFFER], C = Connection> {
    stream: S,
    session: Session,
    connection: C,
    buffer: B,
    filled: u16,
    plaintext: [u8; noise::MAX_PLAINTEXT],
    plaintext_start: u16,
    plaintext_end: u16,
    record_scratch: [u8; noise::TAG_LEN],
    record_progress: u16,
    record_state: u16,
    data: Option<DataFrame>,
    statuses: Statuses,
    status: u16,
    secure: bool,
}

#[derive(Clone, Copy)]
struct DataFrame {
    header: frame::FrameHeader,
    remaining: u16,
    padding: u16,
}

struct Statuses {
    streams: heapless::Vec<u32, H2_STATUS_SLOTS>,
    values: [u16; H2_STATUS_SLOTS],
}

impl Statuses {
    const fn new() -> Self {
        Self {
            streams: heapless::Vec::new(),
            values: [0; H2_STATUS_SLOTS],
        }
    }

    fn get(&self, stream: u32) -> Option<u16> {
        self.streams
            .iter()
            .position(|id| *id == stream)
            .map(|index| self.values[index])
    }

    fn set(&mut self, stream: u32, status: u16) -> Result<(), ()> {
        if let Some(index) = self.streams.iter().position(|id| *id == stream) {
            self.values[index] = status;
            return Ok(());
        }
        let index = self.streams.len();
        self.streams.push(stream).map_err(|_| ())?;
        self.values[index] = status;
        Ok(())
    }

    fn take(&mut self, stream: u32) -> Option<u16> {
        let index = self.streams.iter().position(|id| *id == stream)?;
        let last = self.streams.len() - 1;
        let status = self.values[index];
        self.streams.swap_remove(index);
        if index != last {
            self.values[index] = self.values[last];
        }
        Some(status)
    }
}

enum Input<'a> {
    Frame(usize),
    Data {
        stream: u32,
        bytes: &'a [u8],
        end_stream: bool,
        frame_done: bool,
    },
}

impl<S> Http2<S>
where
    S: Read + Write,
{
    pub async fn start(
        stream: S,
        session: Session,
        pushback: &[u8],
    ) -> Result<Self, Error<S::Error>> {
        Self::start_carried(stream, session, pushback, false).await
    }

    async fn start_carried(
        stream: S,
        session: Session,
        pushback: &[u8],
        secure: bool,
    ) -> Result<Self, Error<S::Error>> {
        Self::start_with_storage(
            stream,
            session,
            pushback,
            secure,
            [0; H2_BUFFER],
            Connection::new(),
        )
        .await
    }

    async fn start_carried_placed<'a>(
        stream: S,
        session: Session,
        pushback: &[u8],
        secure: bool,
        place: impl FnOnce(Self) -> &'a mut Self,
    ) -> Result<&'a mut Self, Error<S::Error>>
    where
        S: 'a,
    {
        let (client, out, len) = Self::prepare(
            stream,
            session,
            pushback,
            secure,
            [0; H2_BUFFER],
            Connection::new(),
        )?;
        let client = place(client);
        client.send(&out[..len]).await?;
        Ok(client)
    }
}

impl<S, B, C> Http2<S, B, C>
where
    S: Read + Write,
    B: AsRef<[u8]> + AsMut<[u8]>,
    C: BorrowMut<Connection>,
{
    async fn start_with_storage(
        stream: S,
        session: Session,
        pushback: &[u8],
        secure: bool,
        buffer: B,
        connection: C,
    ) -> Result<Self, Error<S::Error>> {
        let (mut client, out, len) =
            Self::prepare(stream, session, pushback, secure, buffer, connection)?;
        client.send(&out[..len]).await?;
        Ok(client)
    }

    /// Consume an early payload that arrives after the client preface. Nothing
    /// has been read through HTTP/2 yet, so what follows the payload becomes
    /// the start of the plaintext HTTP/2 input.
    async fn read_deferred_early(&mut self) -> Result<(), Error<S::Error>> {
        let mut pushback = heapless::Vec::<u8, { noise::MAX_PLAINTEXT }>::new();
        read_early_payload(&mut self.stream, &mut self.session, &mut pushback).await?;
        self.plaintext[..pushback.len()].copy_from_slice(&pushback);
        self.plaintext_start = 0;
        self.plaintext_end = u16::try_from(pushback.len()).map_err(|_| Error::FrameTooLarge)?;
        Ok(())
    }

    fn prepare(
        stream: S,
        session: Session,
        pushback: &[u8],
        secure: bool,
        mut buffer: B,
        connection: C,
    ) -> Result<(Self, [u8; 256], usize), Error<S::Error>> {
        buffer.as_mut().fill(0);
        let mut client = Self {
            stream,
            session,
            connection,
            buffer,
            filled: 0,
            plaintext: [0; noise::MAX_PLAINTEXT],
            plaintext_start: 0,
            plaintext_end: pushback.len() as u16,
            record_scratch: [0; noise::TAG_LEN],
            record_progress: 0,
            record_state: 0,
            data: None,
            statuses: Statuses::new(),
            status: 0,
            secure,
        };
        client.plaintext[..pushback.len()].copy_from_slice(pushback);
        let mut out = [0; 256];
        let len = client
            .connection
            .borrow_mut()
            .start(&mut out)
            .map_err(Error::Http2)?;
        Ok((client, out, len))
    }

    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        request_body: &[u8],
        response: &mut [u8],
    ) -> Result<(u16, usize), Error<S::Error>> {
        let stream = self
            .send_request(method, path, authority, request_body)
            .await?;
        let mut written = 0;
        self.status = 0;
        loop {
            let (len, finished) = self.read_chunk(stream, &mut response[written..]).await?;
            written += len;
            if finished {
                self.status = self.take_status(stream).unwrap_or(0);
                return Ok((self.status, written));
            }
        }
    }

    pub async fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        request_body: &[u8],
    ) -> Result<u32, Error<S::Error>> {
        let mut out = [0; H2_OUT_BUFFER];
        let (stream, len) = self
            .connection
            .borrow_mut()
            .request(
                method,
                path,
                authority,
                if self.secure { "https" } else { "http" },
                &[("content-type", "application/json")],
                request_body,
                &mut out,
            )
            .map_err(Error::Http2)?;
        self.send(&out[..len]).await?;
        Ok(stream)
    }

    pub async fn read_chunk(
        &mut self,
        wanted_stream: u32,
        body_out: &mut [u8],
    ) -> Result<(usize, bool), Error<S::Error>> {
        loop {
            let input = self.next_input().await?;
            if let Input::Data {
                stream,
                bytes,
                end_stream,
                frame_done,
            } = input
            {
                let len = bytes.len();
                let mut written = 0;
                let mut error = None;
                if stream == wanted_stream {
                    if len > body_out.len() {
                        error = Some(Error::FrameTooLarge);
                    } else {
                        body_out[..len].copy_from_slice(bytes);
                        written = len;
                    }
                }
                self.consume_data(len).await?;
                if let Some(error) = error {
                    return Err(error);
                }
                let finished = stream == wanted_stream && end_stream && frame_done;
                if written != 0 || finished {
                    return Ok((written, finished));
                }
                continue;
            }
            let Input::Frame(frame_len) = input else {
                unreachable!();
            };
            let mut replies = [0; 256];
            let mut parsed_status = None;
            let (event, reply_len) = self
                .connection
                .borrow_mut()
                .recv(
                    &self.buffer.as_ref()[..frame_len],
                    |name, value| {
                        if name == ":status" {
                            parsed_status = Some(value.parse().unwrap_or(0));
                        }
                    },
                    &mut replies,
                )
                .map_err(Error::Http2)?;
            let header_status = match &event {
                Event::Headers { stream, .. } => parsed_status.map(|status| (*stream, status)),
                _ => None,
            };
            let written = 0;
            let mut finished = false;
            let mut error = None;
            match event {
                Event::Headers { stream, end_stream } if stream == wanted_stream => {
                    finished = end_stream;
                }
                Event::Data { .. } => unreachable!("DATA is streamed before frame dispatch"),
                Event::Reset { stream, .. } if stream == wanted_stream => {
                    error = Some(Error::Http2(micro_h2::Error::StreamReset));
                }
                Event::GoAway { .. } => error = Some(Error::Http2(micro_h2::Error::GoAway)),
                _ => {}
            }
            if let Some((stream, status)) = header_status {
                self.set_status(stream, status)?;
            }
            self.consume(frame_len);
            if reply_len != 0 {
                self.send(&replies[..reply_len]).await?;
            }
            if let Some(error) = error {
                return Err(error);
            }
            if written != 0 || finished {
                return Ok((written, finished));
            }
        }
    }

    /// Consume a response to completion without retaining its body.
    pub async fn drain_stream(&mut self, wanted_stream: u32) -> Result<(), Error<S::Error>> {
        loop {
            let input = self.next_input().await?;
            if let Input::Data {
                stream,
                bytes,
                end_stream,
                frame_done,
            } = input
            {
                let len = bytes.len();
                self.consume_data(len).await?;
                if stream == wanted_stream && end_stream && frame_done {
                    return Ok(());
                }
                continue;
            }
            let Input::Frame(frame_len) = input else {
                unreachable!();
            };
            let header = frame::FrameHeader::parse(&self.buffer.as_ref()[..frame_len])
                .map_err(Error::Http2)?;
            if header.stream != 0 && header.stream != wanted_stream {
                return Err(Error::InterleavedStream(header.stream));
            }
            let mut replies = [0; 256];
            let mut parsed_status = None;
            let (event, reply_len) = self
                .connection
                .borrow_mut()
                .recv(
                    &self.buffer.as_ref()[..frame_len],
                    |name, value| {
                        if name == ":status" {
                            parsed_status = Some(value.parse().unwrap_or(0));
                        }
                    },
                    &mut replies,
                )
                .map_err(Error::Http2)?;
            let header_status = match &event {
                Event::Headers { stream, .. } => parsed_status.map(|status| (*stream, status)),
                _ => None,
            };
            let mut finished = false;
            let mut error = None;
            match event {
                Event::Headers { stream, end_stream } if stream == wanted_stream => {
                    finished = end_stream;
                }
                Event::Data { .. } => unreachable!("DATA is streamed before frame dispatch"),
                Event::Reset { stream, .. } if stream == wanted_stream => {
                    error = Some(Error::Http2(micro_h2::Error::StreamReset));
                }
                Event::GoAway { .. } => error = Some(Error::Http2(micro_h2::Error::GoAway)),
                _ => {}
            }
            if let Some((stream, status)) = header_status {
                self.set_status(stream, status)?;
            }
            self.consume(frame_len);
            if reply_len != 0 {
                self.send(&replies[..reply_len]).await?;
            }
            if let Some(error) = error {
                return Err(error);
            }
            if finished {
                return Ok(());
            }
        }
    }

    /// Status of the response most recently read through [`Self::read_chunk`].
    /// Connection-level frames and headers for other streams do not change it.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Status received for an in-flight response, if its headers have arrived.
    ///
    /// Streaming responses do not reach the completion point where [`Self::status`]
    /// is normally finalised, and several streams may be active at once. Callers
    /// consuming such a stream must therefore query the status by stream id.
    pub fn stream_status(&self, stream: u32) -> Option<u16> {
        self.statuses.get(stream)
    }

    async fn send(&mut self, mut plaintext: &[u8]) -> Result<(), Error<S::Error>> {
        let mut record = [0; noise::MAX_MESSAGE];
        while !plaintext.is_empty() {
            let take = plaintext.len().min(noise::MAX_PLAINTEXT);
            let len = self
                .session
                .seal(&plaintext[..take], &mut record)
                .map_err(Error::Noise)?;
            self.stream
                .write_all(&record[..len])
                .await
                .map_err(Error::Io)?;
            plaintext = &plaintext[take..];
        }
        self.stream.flush().await.map_err(Error::Io)
    }

    async fn next_input(&mut self) -> Result<Input<'_>, Error<S::Error>> {
        loop {
            if let Some(data) = self.data {
                if data.remaining == 0 {
                    return Ok(Input::Data {
                        stream: data.header.stream,
                        bytes: &[],
                        end_stream: data.header.has(micro_h2::frame::flags::END_STREAM),
                        frame_done: true,
                    });
                }
                if self.filled == 0 {
                    self.fill().await?;
                    continue;
                }
                let len = usize::from(self.filled.min(data.remaining));
                return Ok(Input::Data {
                    stream: data.header.stream,
                    bytes: &self.buffer.as_ref()[..len],
                    end_stream: data.header.has(micro_h2::frame::flags::END_STREAM),
                    frame_done: len == usize::from(data.remaining),
                });
            }
            if usize::from(self.filled) >= frame::HEADER_LEN {
                let header =
                    frame::FrameHeader::parse(self.buffer.as_ref()).map_err(Error::Http2)?;
                if header.length > frame::DEFAULT_MAX_FRAME {
                    return Err(Error::FrameTooLarge);
                }
                let total = frame::HEADER_LEN + header.length;
                if header.kind == micro_h2::FrameType::Data {
                    self.consume(frame::HEADER_LEN);
                    let (remaining, padding) = if header.has(micro_h2::frame::flags::PADDED) {
                        if self.filled == 0 {
                            self.fill().await?;
                        }
                        let padding = usize::from(self.buffer.as_ref()[0]);
                        self.consume(1);
                        let remaining = header
                            .length
                            .checked_sub(1 + padding)
                            .ok_or(Error::Http2(micro_h2::Error::Protocol))?;
                        (
                            u16::try_from(remaining).map_err(|_| Error::FrameTooLarge)?,
                            u16::try_from(padding).map_err(|_| Error::FrameTooLarge)?,
                        )
                    } else {
                        (
                            u16::try_from(header.length).map_err(|_| Error::FrameTooLarge)?,
                            0,
                        )
                    };
                    self.data = Some(DataFrame {
                        header,
                        remaining,
                        padding,
                    });
                    continue;
                }
                if total > self.buffer.as_ref().len() {
                    return Err(Error::FrameTooLarge);
                }
                if usize::from(self.filled) >= total {
                    return Ok(Input::Frame(total));
                }
            }
            self.fill().await?;
        }
    }

    async fn consume_data(&mut self, len: usize) -> Result<(), Error<S::Error>> {
        let mut data = self.data.ok_or(Error::Http2(micro_h2::Error::Protocol))?;
        if len > usize::from(data.remaining) || len > usize::from(self.filled) {
            return Err(Error::Http2(micro_h2::Error::Protocol));
        }
        self.consume(len);
        data.remaining -= u16::try_from(len).map_err(|_| Error::FrameTooLarge)?;
        if data.remaining != 0 {
            self.data = Some(data);
            return Ok(());
        }

        let mut padding = usize::from(data.padding);
        while padding != 0 {
            if self.filled == 0 {
                self.fill().await?;
            }
            let take = padding.min(usize::from(self.filled));
            self.consume(take);
            padding -= take;
        }
        self.data = None;
        let mut reply = [0; 2 * frame::HEADER_LEN + 8];
        let reply_len = self
            .connection
            .borrow_mut()
            .finish_data_with_length(
                data.header,
                data.header.length
                    - usize::from(data.padding)
                    - usize::from(data.header.has(micro_h2::frame::flags::PADDED)),
                &mut reply,
            )
            .map_err(Error::Http2)?;
        if reply_len != 0 {
            self.send(&reply[..reply_len]).await?;
        }
        Ok(())
    }

    async fn fill(&mut self) -> Result<(), Error<S::Error>> {
        const TAG_PHASE: u16 = 1 << 15;

        if self.plaintext_start != self.plaintext_end {
            self.copy_plaintext()?;
            return Ok(());
        }
        if self.record_state == 0 {
            read_exact_progress(
                &mut self.stream,
                &mut self.record_scratch[..noise::HEADER_LEN],
                &mut self.record_progress,
            )
            .await?;
            let ciphertext_len =
                Session::ciphertext_len(&self.record_scratch).map_err(Error::Noise)?;
            let plaintext_len = ciphertext_len - noise::TAG_LEN;
            self.record_state =
                u16::try_from(plaintext_len + 1).map_err(|_| Error::FrameTooLarge)?;
            self.record_progress = 0;
        }
        let plaintext_len = usize::from((self.record_state & !TAG_PHASE) - 1);
        if self.record_state & TAG_PHASE == 0 {
            read_exact_progress(
                &mut self.stream,
                &mut self.plaintext[..plaintext_len],
                &mut self.record_progress,
            )
            .await?;
            self.record_state |= TAG_PHASE;
            self.record_progress = 0;
        }
        read_exact_progress(
            &mut self.stream,
            &mut self.record_scratch[..noise::TAG_LEN],
            &mut self.record_progress,
        )
        .await?;
        let plaintext_len = self
            .session
            .open_parts(
                &mut self.plaintext[..plaintext_len],
                &self.record_scratch[..noise::TAG_LEN],
            )
            .map_err(Error::Noise)?;
        self.record_progress = 0;
        self.record_state = 0;
        self.plaintext_start = 0;
        self.plaintext_end = u16::try_from(plaintext_len).map_err(|_| Error::FrameTooLarge)?;
        self.copy_plaintext()?;
        Ok(())
    }

    fn copy_plaintext(&mut self) -> Result<(), Error<S::Error>> {
        let filled = usize::from(self.filled);
        let start = usize::from(self.plaintext_start);
        let end = usize::from(self.plaintext_end);
        let available = self.buffer.as_ref().len() - filled;
        if available == 0 {
            return Err(Error::FrameTooLarge);
        }
        let pending = end - start;
        let take = available.min(pending);
        self.buffer.as_mut()[filled..filled + take]
            .copy_from_slice(&self.plaintext[start..start + take]);
        self.filled = u16::try_from(filled + take).map_err(|_| Error::FrameTooLarge)?;
        self.plaintext_start = u16::try_from(start + take).map_err(|_| Error::FrameTooLarge)?;
        Ok(())
    }

    fn consume(&mut self, len: usize) {
        let filled = usize::from(self.filled);
        self.buffer.as_mut().copy_within(len..filled, 0);
        self.filled -= len as u16;
    }

    fn set_status(&mut self, stream: u32, status: u16) -> Result<(), Error<S::Error>> {
        self.statuses
            .set(stream, status)
            .map_err(|()| Error::ResponseTooLong)
    }

    fn take_status(&mut self, stream: u32) -> Option<u16> {
        self.statuses.take(stream)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapEvent {
    Applied,
    KeepAlive,
}

/// Persistent state for one long-lived streaming map response.
pub struct MapStream<const PEERS: usize> {
    stream: u32,
    frames: FrameReader,
    parser: Parser<PEERS>,
    pending: heapless::Deque<MapEvent, 4>,
    status: Option<u16>,
    ended: bool,
}

impl<const PEERS: usize> Default for MapStream<PEERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PEERS: usize> MapStream<PEERS> {
    /// Construct inactive map-stream state. Firmware can place this in static
    /// storage and activate it with [`MapStream::start_in`] so the bounded JSON
    /// token buffer never becomes part of an async task's stack frame.
    pub const fn new() -> Self {
        Self {
            stream: 0,
            status: None,
            frames: FrameReader::new(),
            parser: Parser::new(),
            pending: heapless::Deque::new(),
            ended: false,
        }
    }

    /// Whether a response drained alongside another request already applied a
    /// newer map to its staging lease. Callers must not reseed that lease from
    /// the older active map before [`Self::next`] returns the queued event.
    pub fn has_pending_update(&self) -> bool {
        self.pending.iter().any(|event| *event == MapEvent::Applied)
    }

    pub async fn start<S, B, C>(
        http2: &mut Http2<S, B, C>,
        authority: &str,
        request_body: &[u8],
    ) -> Result<Self, Error<S::Error>>
    where
        S: Read + Write,
        B: AsRef<[u8]> + AsMut<[u8]>,
        C: BorrowMut<Connection>,
    {
        let mut map = Self::new();
        Self::start_in(&mut map, http2, authority, request_body).await?;
        Ok(map)
    }

    /// Start a map request using caller-provided persistent storage.
    pub async fn start_in<S, B, C>(
        map: &mut Self,
        http2: &mut Http2<S, B, C>,
        authority: &str,
        request_body: &[u8],
    ) -> Result<(), Error<S::Error>>
    where
        S: Read + Write,
        B: AsRef<[u8]> + AsMut<[u8]>,
        C: BorrowMut<Connection>,
    {
        let stream = http2
            .send_request("POST", crate::control::map::PATH, authority, request_body)
            .await?;
        map.stream = stream;
        map.status = None;
        map.frames.finish_response();
        map.parser.reset();
        map.pending.clear();
        map.ended = false;
        Ok(())
    }

    pub async fn next<S, B, C>(
        &mut self,
        http2: &mut Http2<S, B, C>,
        staging: &mut Netmap<PEERS>,
    ) -> Result<MapEvent, Error<S::Error>>
    where
        S: Read + Write,
        B: AsRef<[u8]> + AsMut<[u8]>,
        C: BorrowMut<Connection>,
    {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }
            if self.ended {
                return Err(Error::StreamEnded);
            }

            let input = http2.next_input().await?;
            if let Input::Data {
                stream,
                bytes,
                end_stream,
                frame_done,
            } = input
            {
                let len = bytes.len();
                let mut stream_error = None;
                if stream == self.stream {
                    if self.status != Some(200) {
                        stream_error = Some(Error::UnexpectedStatus(self.status.unwrap_or(0)));
                    } else if let Err(error) = self.queue_data(staging, bytes) {
                        stream_error = Some(error);
                    }
                    self.ended |= end_stream && frame_done;
                }
                http2.consume_data(len).await?;
                if let Some(error) = stream_error {
                    return Err(error);
                }
                continue;
            }
            let Input::Frame(frame_len) = input else {
                unreachable!();
            };
            let mut replies = [0; 256];
            let mut parsed_status = None;
            let (event, reply_len) = http2
                .connection
                .borrow_mut()
                .recv(
                    &http2.buffer.as_ref()[..frame_len],
                    |name, value| {
                        if name == ":status" {
                            parsed_status = Some(value.parse().unwrap_or(0));
                        }
                    },
                    &mut replies,
                )
                .map_err(Error::Http2)?;
            let result = self.consume_event(event, parsed_status, staging);
            http2.consume(frame_len);
            if reply_len != 0 {
                http2.send(&replies[..reply_len]).await?;
            }
            let (outcome, ended) = result?;
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
            if ended {
                return Err(Error::StreamEnded);
            }
        }
    }

    /// Drain another response while preserving and parsing interleaved map
    /// frames from this stream.
    pub async fn drain_response<S, B, C>(
        &mut self,
        http2: &mut Http2<S, B, C>,
        staging: &mut Netmap<PEERS>,
        wanted_stream: u32,
    ) -> Result<(), Error<S::Error>>
    where
        S: Read + Write,
        B: AsRef<[u8]> + AsMut<[u8]>,
        C: BorrowMut<Connection>,
    {
        loop {
            let input = http2.next_input().await?;
            if let Input::Data {
                stream,
                bytes,
                end_stream,
                frame_done,
            } = input
            {
                if stream != 0 && stream != wanted_stream && stream != self.stream {
                    return Err(Error::InterleavedStream(stream));
                }
                let len = bytes.len();
                let mut stream_error = None;
                if stream == self.stream {
                    if self.status != Some(200) {
                        stream_error = Some(Error::UnexpectedStatus(self.status.unwrap_or(0)));
                    } else if let Err(error) = self.queue_data(staging, bytes) {
                        stream_error = Some(error);
                    }
                    self.ended |= end_stream && frame_done;
                }
                let finished = stream == wanted_stream && end_stream && frame_done;
                http2.consume_data(len).await?;
                if let Some(error) = stream_error {
                    return Err(error);
                }
                if finished {
                    return Ok(());
                }
                continue;
            }
            let Input::Frame(frame_len) = input else {
                unreachable!();
            };
            let header = frame::FrameHeader::parse(&http2.buffer.as_ref()[..frame_len])
                .map_err(Error::Http2)?;
            if header.stream != 0 && header.stream != wanted_stream && header.stream != self.stream
            {
                return Err(Error::InterleavedStream(header.stream));
            }

            let mut replies = [0; 256];
            let mut parsed_status = None;
            let (event, reply_len) = http2
                .connection
                .borrow_mut()
                .recv(
                    &http2.buffer.as_ref()[..frame_len],
                    |name, value| {
                        if name == ":status" {
                            parsed_status = Some(value.parse().unwrap_or(0));
                        }
                    },
                    &mut replies,
                )
                .map_err(Error::Http2)?;
            let header_status = match &event {
                Event::Headers { stream, .. } => parsed_status.map(|status| (*stream, status)),
                _ => None,
            };
            let mut finished = false;
            let mut stream_error = None;
            match event {
                Event::Headers { stream, end_stream } if stream == wanted_stream => {
                    finished = end_stream;
                }
                Event::Data { .. } => unreachable!("DATA is streamed before frame dispatch"),
                Event::Headers { stream, end_stream } if stream == self.stream => {
                    if let Some(status) = parsed_status {
                        self.status = Some(status);
                    }
                    if self.status != Some(200) {
                        stream_error = Some(Error::UnexpectedStatus(self.status.unwrap_or(0)));
                    }
                    self.ended |= end_stream;
                }
                Event::Reset { stream, .. } if stream == wanted_stream || stream == self.stream => {
                    stream_error = Some(Error::Http2(micro_h2::Error::StreamReset));
                }
                Event::GoAway { .. } => {
                    stream_error = Some(Error::Http2(micro_h2::Error::GoAway));
                }
                _ => {}
            }
            if let Some((stream, status)) = header_status {
                http2.set_status(stream, status)?;
            }
            http2.consume(frame_len);
            if reply_len != 0 {
                http2.send(&replies[..reply_len]).await?;
            }
            if let Some(error) = stream_error {
                return Err(error);
            }
            if finished {
                return Ok(());
            }
        }
    }

    fn queue_data<E>(
        &mut self,
        staging: &mut Netmap<PEERS>,
        mut data: &[u8],
    ) -> Result<(), Error<E>> {
        while !data.is_empty() {
            let (outcome, consumed) = self.consume_data(staging, data)?;
            data = &data[consumed..];
            if let Some(outcome) = outcome {
                // A single HTTP/2 DATA chunk may contain an arbitrary run of
                // zero-length keepalives or several complete deltas. Only the
                // latest applied map and the fact that liveness was observed
                // matter to the actor, so coalesce duplicate notifications
                // instead of turning valid compressed input into queue growth.
                if !self.pending.iter().any(|pending| *pending == outcome) {
                    self.pending
                        .push_back(outcome)
                        .map_err(|_| Error::ResponseTooLong)?;
                }
            }
            if consumed == 0 {
                return Err(Error::FrameTooLarge);
            }
        }
        Ok(())
    }

    fn consume_data<E>(
        &mut self,
        staging: &mut Netmap<PEERS>,
        data: &[u8],
    ) -> Result<(Option<MapEvent>, usize), Error<E>> {
        let mut consumed_total = 0;
        loop {
            let input = &data[consumed_total..];
            let (piece, consumed) = self.frames.next(input).map_err(Error::Netmap)?;
            consumed_total += consumed;
            match piece {
                crate::netmap::frame::Chunk::Body(bytes) => {
                    self.parser.push(staging, bytes).map_err(Error::Netmap)?;
                    if self.frames.is_complete() {
                        self.frames.finish_response();
                        core::mem::take(&mut self.parser)
                            .finish(staging)
                            .map_err(Error::Netmap)?;
                        return Ok((Some(MapEvent::Applied), consumed_total));
                    }
                }
                crate::netmap::frame::Chunk::End => {
                    return Ok((Some(MapEvent::KeepAlive), consumed_total));
                }
                crate::netmap::frame::Chunk::Need if consumed == 0 => {
                    return Ok((None, consumed_total));
                }
                crate::netmap::frame::Chunk::Need => {}
            }
        }
    }

    /// Apply one decoded HTTP/2 event to this map response.
    ///
    /// Status is deliberately checked only on this stream's response HEADERS.
    /// A server is expected to send connection-level SETTINGS first; treating
    /// that frame as a response with status zero was the physical device's
    /// post-registration bootstrap failure.
    fn consume_event<E>(
        &mut self,
        event: Event<'_>,
        frame_status: Option<u16>,
        staging: &mut Netmap<PEERS>,
    ) -> Result<(Option<MapEvent>, bool), Error<E>> {
        match event {
            Event::Headers { stream, end_stream } if stream == self.stream => {
                if let Some(status) = frame_status {
                    self.status = Some(status);
                }
                if self.status != Some(200) {
                    return Err(Error::UnexpectedStatus(self.status.unwrap_or(0)));
                }
                self.ended |= end_stream;
            }
            Event::Data {
                stream,
                data,
                end_stream,
            } if stream == self.stream => {
                if self.status != Some(200) {
                    return Err(Error::UnexpectedStatus(self.status.unwrap_or(0)));
                }
                self.queue_data(staging, data)?;
                self.ended |= end_stream;
                return Ok((self.pending.pop_front(), self.ended));
            }
            Event::Reset { stream, .. } if stream == self.stream => {
                return Err(Error::Http2(micro_h2::Error::StreamReset));
            }
            Event::GoAway { .. } => return Err(Error::Http2(micro_h2::Error::GoAway)),
            _ => {}
        }
        Ok((None, false))
    }
}

/// Send a non-streaming endpoint update without disturbing the map stream.
pub async fn send_endpoint_update<S, B, C, const PEERS: usize>(
    http2: &mut Http2<S, B, C>,
    map: &mut MapStream<PEERS>,
    staging: &mut Netmap<PEERS>,
    authority: &str,
    request_body: &[u8],
) -> Result<(), Error<S::Error>>
where
    S: Read + Write,
    B: AsRef<[u8]> + AsMut<[u8]>,
    C: BorrowMut<Connection>,
{
    let stream = http2
        .send_request("POST", crate::control::map::PATH, authority, request_body)
        .await?;
    map.drain_response(http2, staging, stream).await?;
    let status = http2.take_status(stream).unwrap_or(0);
    if status != 200 {
        return Err(Error::UnexpectedStatus(status));
    }
    Ok(())
}

fn json_string<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let text = core::str::from_utf8(body).ok()?;
    let mut pattern = heapless::String::<64>::new();
    pattern.push('"').ok()?;
    pattern.push_str(field).ok()?;
    pattern.push('"').ok()?;
    let rest = &text[text.find(pattern.as_str())? + pattern.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(&rest[..rest.find('"')?])
}

const _: () = assert!(CAPABILITY_VERSION == 131);

#[cfg(test)]
mod tests {
    use super::*;

    struct PausingReader {
        input: &'static [u8],
        position: usize,
        pause_at: usize,
        paused: bool,
    }

    impl embedded_io_async::ErrorType for PausingReader {
        type Error = core::convert::Infallible;
    }

    impl Read for PausingReader {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let limit = if self.paused {
                self.pause_at
            } else {
                self.input.len()
            };
            if self.position == limit {
                return core::future::pending().await;
            }
            let amount = output.len().min(limit - self.position);
            output[..amount].copy_from_slice(&self.input[self.position..self.position + amount]);
            self.position += amount;
            Ok(amount)
        }
    }

    #[test]
    fn exact_read_progress_survives_future_cancellation() {
        use core::future::Future as _;
        use core::task::{Context, Poll, Waker};

        let mut stream = PausingReader {
            input: b"record",
            position: 0,
            pause_at: 2,
            paused: true,
        };
        let mut output = [0; 6];
        let mut filled = 0;
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        {
            let mut read =
                core::pin::pin!(read_exact_progress(&mut stream, &mut output, &mut filled));
            assert!(matches!(read.as_mut().poll(&mut context), Poll::Pending));
        }
        assert_eq!(filled, 2);

        stream.paused = false;
        {
            let mut read =
                core::pin::pin!(read_exact_progress(&mut stream, &mut output, &mut filled));
            assert!(matches!(
                read.as_mut().poll(&mut context),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(&output, b"record");
    }

    #[test]
    fn compact_status_storage_preserves_eight_active_streams() {
        let mut statuses = Statuses::new();
        for stream in 1..=H2_STATUS_SLOTS as u32 {
            statuses.set(stream, 200 + stream as u16).unwrap();
        }
        assert!(statuses.set(9, 209).is_err());
        assert_eq!(statuses.get(4), Some(204));
        assert_eq!(statuses.take(4), Some(204));
        statuses.set(9, 209).unwrap();
        assert_eq!(statuses.get(9), Some(209));
    }

    #[test]
    fn map_boundaries_stop_before_the_next_response_prefix() {
        let mut stream = MapStream::<1> {
            stream: 1,
            frames: FrameReader::new(),
            parser: Parser::new(),
            pending: heapless::Deque::new(),
            status: Some(200),
            ended: false,
        };
        let mut staging = Netmap::new();
        let bytes = [0u8; 8];

        let (first, consumed) = stream.consume_data::<()>(&mut staging, &bytes).unwrap();
        assert_eq!(first, Some(MapEvent::KeepAlive));
        assert_eq!(consumed, 4);
        let (second, consumed) = stream
            .consume_data::<()>(&mut staging, &bytes[consumed..])
            .unwrap();
        assert_eq!(second, Some(MapEvent::KeepAlive));
        assert_eq!(consumed, 4);
    }

    #[derive(serde::Deserialize)]
    struct PostRegisterFixture {
        map_stream: u32,
        frames: std::vec::Vec<std::string::String>,
    }

    fn decode_hex(text: &str) -> std::vec::Vec<u8> {
        assert!(text.len().is_multiple_of(2));
        text.as_bytes()
            .chunks_exact(2)
            .map(|digits| {
                let digits = core::str::from_utf8(digits).unwrap();
                u8::from_str_radix(digits, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn explicit_http_body_boundary_does_not_require_connection_close() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nkey";
        assert_eq!(response_length(response).unwrap(), Some(response.len()));
        assert_eq!(
            response_length(&response[..response.len() - 1]).unwrap(),
            Some(response.len())
        );
    }

    #[test]
    fn close_delimited_and_malformed_lengths_are_handled_safely() {
        assert_eq!(
            response_length(b"HTTP/1.1 200 OK\r\n\r\nkey").unwrap(),
            None
        );
        assert!(response_length(b"HTTP/1.1 200 OK\r\nContent-Length: no\r\n\r\n").is_err());
        assert!(
            response_length(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx")
                .is_err()
        );
    }

    #[test]
    fn settings_before_map_headers_are_not_status_zero() {
        let fixture: PostRegisterFixture = serde_json::from_str(include_str!(
            "../../../../tests/vectors/post_register_map_h2.json"
        ))
        .unwrap();
        let mut connection = Connection::new();
        // The capture starts after registration and the map request. Open the
        // same streams before replaying their responses.
        let mut request = [0; 256];
        for path in ["/machine/register", "/machine/map"] {
            connection
                .request(
                    "POST",
                    path,
                    "control.example",
                    "https",
                    &[],
                    &[],
                    &mut request,
                )
                .unwrap();
        }
        let mut map = MapStream::<1> {
            stream: fixture.map_stream,
            status: None,
            frames: FrameReader::new(),
            parser: Parser::new(),
            pending: heapless::Deque::new(),
            ended: false,
        };
        let mut netmap = Netmap::new();
        let mut applied = false;

        for encoded in fixture.frames {
            let bytes = decode_hex(&encoded);
            let mut status = None;
            let mut reply = [0; 256];
            let (event, _) = connection
                .recv(
                    &bytes,
                    |name, value| {
                        if name == ":status" {
                            status = value.parse().ok();
                        }
                    },
                    &mut reply,
                )
                .unwrap();
            let (outcome, ended) = map
                .consume_event::<core::convert::Infallible>(event, status, &mut netmap)
                .unwrap();
            applied |= outcome == Some(MapEvent::Applied);
            assert!(!ended);
        }

        assert_eq!(map.status, Some(200));
        assert!(applied);
        assert_eq!(netmap.responses, 1);
    }

    /// An in-memory stream: reads drain `inbound`, writes append to `written`.
    struct Scripted {
        inbound: std::vec::Vec<u8>,
        read: usize,
        written: std::vec::Vec<u8>,
    }

    impl Scripted {
        fn new(inbound: std::vec::Vec<u8>) -> Self {
            Self {
                inbound,
                read: 0,
                written: std::vec::Vec::new(),
            }
        }
    }

    impl embedded_io_async::ErrorType for Scripted {
        type Error = core::convert::Infallible;
    }

    impl Read for Scripted {
        async fn read(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
            let take = out.len().min(self.inbound.len() - self.read);
            out[..take].copy_from_slice(&self.inbound[self.read..self.read + take]);
            self.read += take;
            Ok(take)
        }
    }

    impl Write for Scripted {
        async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            core::task::Poll::Ready(output) => output,
            core::task::Poll::Pending => panic!("scripted streams never block"),
        }
    }

    #[test]
    fn streamed_data_validates_content_length_without_counting_padding() {
        // Every attempt reuses the same protocol state, including after an
        // invalid response. Each new session must start again at stream 1.
        let mut buffer = [0; H2_BUFFER];
        let mut connection = Connection::new();
        for padding in [None, Some(0), Some(7), Some(255)] {
            for content_length in [4, 5, 6] {
                let mut headers = [0; 64];
                let len = micro_h2::hpack::encode::encode_header(":status", "200", &mut headers, 0)
                    .unwrap();
                let len = micro_h2::hpack::encode::encode_header(
                    "content-length",
                    &std::format!("{content_length}"),
                    &mut headers,
                    len,
                )
                .unwrap();
                let mut response = [0; 512];
                let mut len = frame::write_frame(
                    micro_h2::FrameType::Headers,
                    frame::flags::END_HEADERS,
                    1,
                    &headers[..len],
                    &mut response,
                )
                .unwrap();
                let mut payload = std::vec::Vec::new();
                if let Some(padding) = padding {
                    payload.push(padding);
                }
                payload.extend_from_slice(b"hello");
                if let Some(padding) = padding {
                    payload.resize(payload.len() + usize::from(padding), 0);
                }
                len += frame::write_frame(
                    micro_h2::FrameType::Data,
                    frame::flags::END_STREAM
                        | if padding.is_some() {
                            frame::flags::PADDED
                        } else {
                            0
                        },
                    1,
                    &payload,
                    &mut response[len..],
                )
                .unwrap();
                let mut server = Session::new([2; 32], [1; 32]);
                let mut inbound = std::vec::Vec::new();
                // Split both DATA and its padding across authenticated records.
                for chunk in response[..len].chunks(3) {
                    let mut record = [0; 64];
                    let len = server.seal(chunk, &mut record).unwrap();
                    inbound.extend_from_slice(&record[..len]);
                }
                let noise = NoiseStream {
                    stream: Scripted::new(inbound),
                    session: Session::new([1; 32], [2; 32]),
                    pushback: heapless::Vec::new(),
                };
                let mut http2 =
                    block_on(noise.into_https2_with_storage(&mut buffer, &mut connection)).unwrap();
                let mut body = [0; 5];
                let result = block_on(http2.request(
                    "POST",
                    "/machine/register",
                    "control.example",
                    &[],
                    &mut body,
                ));
                if content_length == 5 {
                    assert_eq!(result.unwrap(), (200, 5), "padding: {padding:?}");
                    assert_eq!(&body, b"hello");
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::Http2(micro_h2::Error::Protocol))
                    ));
                }
            }
        }
    }

    struct Counter(u8);

    impl crate::keys::Rng for Counter {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// The server's side after the Noise response: an early payload and the
    /// first nine bytes of its HTTP/2 preface, split across two records.
    fn server_records(server: &mut Session) -> (std::vec::Vec<u8>, [u8; 9]) {
        let challenge = br#"{"nodeKeyChallenge":"chalpub:00"}"#;
        let settings = [0, 0, 0, 4, 0, 0, 0, 0, 0];
        let mut first = std::vec::Vec::from(noise::EARLY_MAGIC);
        first.extend_from_slice(&(challenge.len() as u32).to_be_bytes());
        first.extend_from_slice(&challenge[..10]);
        let mut second = std::vec::Vec::from(&challenge[10..]);
        second.extend_from_slice(&settings);
        let mut wire = std::vec::Vec::new();
        for plaintext in [first, second] {
            let mut record = [0; noise::MAX_MESSAGE];
            let len = server.seal(&plaintext, &mut record).unwrap();
            wire.extend_from_slice(&record[..len]);
        }
        (wire, settings)
    }

    #[test]
    fn a_split_handshake_yields_the_same_session_as_the_http_upgrade() {
        let identity = Identity::generate(&mut Counter(1));
        let server_private = StaticSecret::from([0x42; 32]);
        let server_key =
            MachinePublic::from_bytes(x25519_dalek::PublicKey::from(&server_private).to_bytes());
        let server_ephemeral = StaticSecret::from([0x43; 32]);

        // WebSocket shape: the initiation leaves out of band, and the stream
        // starts directly with the Noise response.
        let (initiation, pending) = initiate(&identity, &server_key, &mut Counter(9)).unwrap();
        let (response, mut server_split) = crate::noise::ik::respond_for_test(
            &server_private,
            &server_ephemeral,
            initiation.as_bytes(),
        );
        let mut inbound = std::vec::Vec::from(response);
        let (records, settings) = server_records(&mut server_split);
        inbound.extend_from_slice(&records);
        let split = block_on(complete(Scripted::new(inbound), pending)).unwrap();
        assert!(split.stream.written.is_empty());
        let mut split = block_on(split.into_http2()).unwrap();

        // HTTP/1.1 shape, from the same random stream.
        let (response, mut server_upgrade) = crate::noise::ik::respond_for_test(
            &server_private,
            &server_ephemeral,
            initiation.as_bytes(),
        );
        let mut inbound = std::vec::Vec::from(
            &b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n"[..],
        );
        inbound.extend_from_slice(&response);
        inbound.extend_from_slice(&server_records(&mut server_upgrade).0);
        let upgraded = block_on(establish(
            Scripted::new(inbound),
            "control.example",
            &identity,
            &server_key,
            &mut Counter(9),
        ))
        .unwrap();
        let mut request = [0; upgrade::MAX_REQUEST];
        let request =
            upgrade::write_upgrade_request("control.example", initiation.as_bytes(), &mut request)
                .unwrap();
        assert_eq!(upgraded.stream.written.as_slice(), request);
        assert_eq!(upgraded.pushback.as_slice(), &settings);
        let mut upgraded = block_on(upgraded.into_http2()).unwrap();

        // The same HTTP/2 preface bytes followed the handshake on both, and
        // both stripped the early payload and kept the server's first frame.
        assert_eq!(
            &upgraded.stream.written[request.len()..],
            split.stream.written.as_slice()
        );
        for http2 in [&split, &upgraded] {
            assert_eq!(
                &http2.plaintext
                    [usize::from(http2.plaintext_start)..usize::from(http2.plaintext_end)],
                &settings
            );
        }

        // Identical record keys and counters: both seal the same bytes, and
        // the server opens them.
        assert_eq!(split.session.counters(), upgraded.session.counters());
        let mut sealed_split = [0; 64];
        let mut sealed_upgraded = [0; 64];
        let len = split.session.seal(b"ping", &mut sealed_split).unwrap();
        assert_eq!(
            upgraded
                .session
                .seal(b"ping", &mut sealed_upgraded)
                .unwrap(),
            len
        );
        assert_eq!(sealed_split[..len], sealed_upgraded[..len]);
        let mut opened = [0; noise::MAX_PLAINTEXT];
        let mut preface = &split.stream.written[..];
        while !preface.is_empty() {
            let len = Session::ciphertext_len(preface).unwrap();
            server_split
                .open(
                    &preface[noise::HEADER_LEN..noise::HEADER_LEN + len],
                    &mut opened,
                )
                .unwrap();
            preface = &preface[noise::HEADER_LEN + len..];
        }
        let opened_len = server_split
            .open(&sealed_split[noise::HEADER_LEN..len], &mut opened)
            .unwrap();
        assert_eq!(&opened[..opened_len], b"ping");
    }

    #[test]
    fn a_websocket_handshake_does_not_wait_for_the_early_payload() {
        // Over WebSocket the server sends only its Noise response, then waits
        // for the client's HTTP/2 preface before anything else.
        let identity = Identity::generate(&mut Counter(1));
        let server_private = StaticSecret::from([0x42; 32]);
        let server_key =
            MachinePublic::from_bytes(x25519_dalek::PublicKey::from(&server_private).to_bytes());
        let (initiation, pending) = initiate(&identity, &server_key, &mut Counter(9)).unwrap();
        let (response, _) = crate::noise::ik::respond_for_test(
            &server_private,
            &StaticSecret::from([0x43; 32]),
            initiation.as_bytes(),
        );
        let stream = block_on(complete(
            Scripted::new(std::vec::Vec::from(response)),
            pending,
        ));
        assert!(stream.is_ok());
    }

    #[test]
    fn a_refused_upgrade_is_reported_before_any_noise_bytes_are_read() {
        let identity = Identity::generate(&mut Counter(1));
        let server_key = MachinePublic::from_bytes([0x42; 32]);
        let inbound = std::vec::Vec::from(&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..]);
        assert!(matches!(
            block_on(establish(
                Scripted::new(inbound),
                "control.example",
                &identity,
                &server_key,
                &mut Counter(9),
            )),
            Err(Error::UnexpectedStatus(403))
        ));
    }

    #[test]
    fn host_storage_is_owned_and_firmware_storage_is_borrowed() {
        struct HostStream;
        type Owned = Http2<HostStream>;
        type Borrowed = Http2<HostStream, &'static mut [u8; H2_BUFFER], &'static mut Connection>;

        assert!(core::mem::size_of::<Owned>() >= H2_BUFFER);
        assert!(core::mem::size_of::<Borrowed>() < core::mem::size_of::<Owned>());
        assert_eq!(H2_BUFFER, 2_048);
    }
}

//! HTTP/2 over a ts2021 Noise channel.
//!
//! Two framings stacked, with nothing in common. Underneath, controlbase
//! records: `1B type ‖ 2B length ‖ ciphertext`, at most 4096 bytes. Above,
//! HTTP/2 frames: nine bytes of header and a payload up to 16 KiB. Neither knows
//! about the other, so an HTTP/2 frame routinely spans several records and a
//! record routinely holds several frames.
//!
//! That mismatch is all this module handles: it keeps a buffer of decrypted
//! bytes, tops it up a record at a time, and hands out whole HTTP/2 frames.

use micro_h2::{Connection, Event, frame};
use tailfeather::noise::Session;

use crate::net::{NetError, TcpStream};

/// Room for the largest HTTP/2 frame we accept, plus a partial one behind it.
const BUFFER: usize = 2 * (frame::HEADER_LEN + frame::DEFAULT_MAX_FRAME);

/// Enough for a registration body and its headers.
const OUT_BUFFER: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub enum H2Error {
    Net(NetError),
    Noise(tailfeather::noise::Error),
    Http2(micro_h2::Error),
    /// A frame larger than the buffer this client keeps.
    FrameTooLarge,
}

impl core::fmt::Display for H2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Net(e) => write!(f, "network: {e}"),
            Self::Noise(e) => write!(f, "ts2021: {e}"),
            Self::Http2(e) => write!(f, "http/2: {e}"),
            Self::FrameTooLarge => f.write_str("http/2 frame larger than our buffer"),
        }
    }
}

impl From<NetError> for H2Error {
    fn from(e: NetError) -> Self {
        Self::Net(e)
    }
}

impl From<tailfeather::noise::Error> for H2Error {
    fn from(e: tailfeather::noise::Error) -> Self {
        Self::Noise(e)
    }
}

impl From<micro_h2::Error> for H2Error {
    fn from(e: micro_h2::Error) -> Self {
        Self::Http2(e)
    }
}

/// An HTTP/2 client speaking through a Noise session on a TCP stream.
pub struct Http2<'r> {
    stream: TcpStream<'r>,
    session: Session,
    connection: Connection,
    /// Decrypted bytes not yet consumed as HTTP/2 frames.
    buffer: [u8; BUFFER],
    filled: usize,
    status: u16,
}

impl<'r> Http2<'r> {
    /// Take over an established Noise session.
    ///
    /// `pushback` is whatever the early-payload probe read but did not consume:
    /// on a server with no early payload those nine bytes are already the first
    /// HTTP/2 frame header, and dropping them would leave the parser permanently
    /// one header short.
    pub async fn start(
        stream: TcpStream<'r>,
        session: Session,
        pushback: &[u8],
    ) -> Result<Self, H2Error> {
        let mut client = Self {
            stream,
            session,
            connection: Connection::new(),
            buffer: [0; BUFFER],
            filled: 0,
            status: 0,
        };
        client.buffer[..pushback.len()].copy_from_slice(pushback);
        client.filled = pushback.len();

        let mut out = [0u8; 256];
        let len = client.connection.start(&mut out)?;
        client.send(&out[..len]).await?;
        Ok(client)
    }

    /// Send a request and read the whole response.
    ///
    /// Only for responses that end: a map long-poll never does, and must be
    /// read with [`Http2::send_request`] and [`Http2::read_chunk`] instead.
    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        request_body: &[u8],
        body_out: &mut [u8],
    ) -> Result<(u16, usize), H2Error> {
        let stream = self
            .send_request(method, path, authority, request_body)
            .await?;
        let mut written = 0;
        loop {
            let (len, finished) = self.read_chunk(stream, &mut body_out[written..]).await?;
            written += len;
            if finished {
                return Ok((self.status, written));
            }
        }
    }

    /// Send a request and return its stream identifier.
    pub async fn send_request(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        request_body: &[u8],
    ) -> Result<u32, H2Error> {
        let mut out = [0u8; OUT_BUFFER];
        let (stream, len) = self.connection.request(
            method,
            path,
            authority,
            // Plain HTTP: the Noise channel already provides confidentiality
            // and authentication, so this is not TLS and must not claim to be.
            "http",
            &[("content-type", "application/json")],
            request_body,
            &mut out,
        )?;
        self.send(&out[..len]).await?;
        Ok(stream)
    }

    /// Read the next piece of a response body.
    ///
    /// Returns how many bytes were written and whether the stream has ended.
    /// A long-poll never ends, so a caller reading one stops when it has what it
    /// came for rather than when this says to.
    pub async fn read_chunk(
        &mut self,
        stream: u32,
        body_out: &mut [u8],
    ) -> Result<(usize, bool), H2Error> {
        loop {
            let frame = self.next_frame().await?;
            // Split so the frame stays borrowed from `self.buffer` while
            // `recv` writes its replies elsewhere.
            let mut replies = [0u8; 256];
            let mut status = self.status;
            let (event, reply_len) = {
                let (buffer, connection) = (&self.buffer[..frame], &mut self.connection);
                connection.recv(
                    buffer,
                    |name, value| {
                        if name == ":status" {
                            status = value.parse().unwrap_or(0);
                        }
                    },
                    &mut replies,
                )?
            };
            self.status = status;

            let mut written = 0usize;
            let mut finished = false;
            let mut failed = None;

            match event {
                Event::Headers {
                    stream: s,
                    end_stream,
                } if s == stream => finished = end_stream,
                Event::Data {
                    stream: s,
                    data,
                    end_stream,
                } if s == stream => {
                    if data.len() > body_out.len() {
                        failed = Some(H2Error::FrameTooLarge);
                    } else {
                        body_out[..data.len()].copy_from_slice(data);
                        written = data.len();
                    }
                    finished = end_stream;
                }
                Event::Reset { stream: s, .. } if s == stream => {
                    failed = Some(H2Error::Http2(micro_h2::Error::StreamReset));
                }
                Event::GoAway { .. } => failed = Some(H2Error::Http2(micro_h2::Error::GoAway)),
                _ => {}
            }

            self.consume(frame);
            if reply_len > 0 {
                self.send(&replies[..reply_len]).await?;
            }
            if let Some(e) = failed {
                return Err(e);
            }
            if written > 0 || finished {
                return Ok((written, finished));
            }
        }
    }

    /// The status of the most recent response.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Seal and send, splitting across records when needed.
    async fn send(&mut self, mut plaintext: &[u8]) -> Result<(), H2Error> {
        let mut record = [0u8; tailfeather::noise::MAX_MESSAGE];
        while !plaintext.is_empty() {
            let take = plaintext.len().min(tailfeather::noise::MAX_PLAINTEXT);
            let len = self.session.seal(&plaintext[..take], &mut record)?;
            self.stream.write_all(&record[..len]).await?;
            plaintext = &plaintext[take..];
        }
        Ok(())
    }

    /// Read until a whole HTTP/2 frame is buffered, returning its total length.
    async fn next_frame(&mut self) -> Result<usize, H2Error> {
        loop {
            if self.filled >= frame::HEADER_LEN {
                let header = frame::FrameHeader::parse(&self.buffer)?;
                let total = frame::HEADER_LEN + header.length;
                if total > self.buffer.len() {
                    return Err(H2Error::FrameTooLarge);
                }
                if self.filled >= total {
                    return Ok(total);
                }
            }
            self.fill().await?;
        }
    }

    /// Decrypt one record onto the end of the buffer.
    async fn fill(&mut self) -> Result<(), H2Error> {
        let mut header = [0u8; tailfeather::noise::HEADER_LEN];
        self.stream.read_exact(&mut header).await?;
        let len = Session::ciphertext_len(&header)?;

        let mut ciphertext = [0u8; tailfeather::noise::MAX_MESSAGE];
        self.stream.read_exact(&mut ciphertext[..len]).await?;

        let plaintext_len = self
            .session
            .open(&ciphertext[..len], &mut self.buffer[self.filled..])?;
        self.filled += plaintext_len;
        Ok(())
    }

    /// Drop a consumed frame, keeping whatever followed it in the same record.
    fn consume(&mut self, len: usize) {
        self.buffer.copy_within(len..self.filled, 0);
        self.filled -= len;
    }
}

//! Blocking drivers over `embedded-io` streams.

use embedded_io::{Read, Seek, SeekFrom, Write};

use super::resume::{BLOCK_SIZE, BlockChecksum, BlockHasher, LINE_MAX, LineBuffer};
use super::*;

/// Read a message head into `buf`, whose first `carried` bytes were already
/// received (left over after an earlier head on the same connection).
fn read_head<IO: Read>(
    io: &mut IO,
    buf: &mut [u8],
    carried: usize,
) -> Result<Option<(usize, usize)>, HeadError<IO::Error>> {
    let mut filled = carried;
    loop {
        if let Some(head) = head_progress(buf, filled).map_err(HeadError::Http)? {
            return Ok(Some((head, filled)));
        }
        let read = io.read(&mut buf[filled..]).map_err(HeadError::Io)?;
        if read == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(HeadError::Http(http::Error::UnexpectedEof))
            };
        }
        filled += read;
    }
}

fn reply<IO: Write>(io: &mut IO, reply: Reply) -> Result<(), IO::Error> {
    let mut out = [0u8; REPLY_BUFFER];
    // Every canned reply fits the fixed buffer; covered by a unit test.
    let len = reply.write(&mut out).unwrap_or(0);
    io.write_all(&out[..len])?;
    io.flush()
}

/// Serve one Taildrop request on a blocking stream.
///
/// `buf` holds the request head and then body reads; 1–2 KiB is plenty,
/// and heads larger than it are refused with `431`.
pub fn serve<IO, S>(
    io: &mut IO,
    peer: &Peer,
    config: &Config,
    sink: &mut S,
    buf: &mut [u8],
) -> Result<Served, ServeError<IO::Error, S::Error>>
where
    IO: Read + Write,
    S: FileSink,
{
    let (head, filled) = match read_head(io, buf, 0) {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(Served::Closed),
        Err(HeadError::Io(error)) => return Err(ServeError::Io(error)),
        Err(HeadError::Http(error)) => {
            let _ = reply(io, Reply::for_error(error));
            return Err(ServeError::Http(error));
        }
    };
    let mut name = [0u8; MAX_NAME];
    let action = match http::parse_request(&buf[..head]) {
        Ok(request) => route(&request, peer, config, &mut name),
        Err(error) => {
            let _ = reply(io, Reply::for_error(error));
            return Err(ServeError::Http(error));
        }
    };
    let (name, framing, expect_continue, offset) = match action {
        Action::Respond(answer) => {
            reply(io, answer).map_err(ServeError::Io)?;
            return Ok(Served::Replied(answer.status()));
        }
        Action::Checksums { name } => return stream_checksums(io, peer, sink, name, buf),
        Action::ListPartials => return list_partials(io, peer, sink, buf),
        Action::Receive {
            name,
            framing,
            expect_continue,
            offset,
        } => (name, framing, expect_continue, offset),
    };
    let incoming = Incoming {
        from: peer.addr,
        name,
        offset,
        size: framing.declared_len(),
    };
    match sink.begin(&incoming) {
        Ok(()) => {}
        Err(Refusal::Exists) => {
            let _ = reply(io, Reply::Exists);
            return Err(ServeError::Exists);
        }
        Err(Refusal::Failed(error)) => {
            let _ = reply(io, Reply::StorageFailed);
            return Err(ServeError::Sink(error));
        }
    }
    if expect_continue && let Err(error) = io.write_all(http::CONTINUE).and_then(|()| io.flush()) {
        sink.abort();
        return Err(ServeError::Io(error));
    }

    let mut decoder = BodyDecoder::new(framing);
    let mut received = 0;
    let limit = config.max_file_size.saturating_sub(offset);
    let (mut start, mut end) = (head, filled);
    while !decoder.is_done() {
        if start == end {
            match io.read(buf) {
                Ok(0) => {
                    sink.abort();
                    return Err(ServeError::Http(http::Error::UnexpectedEof));
                }
                Ok(read) => (start, end) = (0, read),
                Err(error) => {
                    sink.abort();
                    return Err(ServeError::Io(error));
                }
            }
        }
        let step = match body_step(&mut decoder, &buf[start..end], &mut received, limit) {
            Ok(step) => step,
            Err(answer) => {
                sink.abort();
                let _ = reply(io, answer);
                return Err(if answer == Reply::TooLarge {
                    ServeError::TooLarge
                } else {
                    ServeError::Http(http::Error::BadChunk)
                });
            }
        };
        start += step.consumed;
        if !step.data.is_empty()
            && let Err(error) = sink.write(step.data)
        {
            sink.abort();
            let _ = reply(io, Reply::StorageFailed);
            return Err(ServeError::Sink(error));
        }
    }
    if let Err(error) = sink.finish() {
        sink.abort();
        let _ = reply(io, Reply::StorageFailed);
        return Err(ServeError::Sink(error));
    }
    reply(io, Reply::Stored).map_err(ServeError::Io)?;
    Ok(Served::Received {
        bytes: received,
        offset,
    })
}

fn stream_checksums<IO, S>(
    io: &mut IO,
    peer: &Peer,
    sink: &mut S,
    name: &str,
    buf: &mut [u8],
) -> Result<Served, ServeError<IO::Error, S::Error>>
where
    IO: Write,
    S: FileSink,
{
    let mut line = [0u8; LINE_MAX];
    let mut emit = |io: &mut IO, block: BlockChecksum| {
        let mut cursor = http::Cursor::new(&mut line);
        // A checksum line always fits LINE_MAX; covered by a unit test.
        let _ = block.write_line(&mut cursor);
        let len = cursor.len();
        io.write_all(&line[..len]).map_err(ServeError::Io)
    };
    io.write_all(CHECKSUMS_HEAD).map_err(ServeError::Io)?;
    let mut offset = 0;
    let mut block = BlockHasher::new(BLOCK_SIZE);
    loop {
        let read = sink
            .read_partial(peer.addr, name, offset, buf)
            .map_err(ServeError::Sink)?;
        if read == 0 {
            break;
        }
        offset += read as u64;
        let mut data = &buf[..read];
        while !data.is_empty() {
            data = &data[block.feed(data)..];
            if block.remaining() == 0 {
                let full = core::mem::replace(&mut block, BlockHasher::new(BLOCK_SIZE));
                emit(io, full.finish())?;
            }
        }
    }
    if !block.is_empty() {
        emit(io, block.finish())?;
    }
    io.flush().map_err(ServeError::Io)?;
    Ok(Served::Replied(200))
}

fn list_partials<IO, S>(
    io: &mut IO,
    peer: &Peer,
    sink: &mut S,
    buf: &mut [u8],
) -> Result<Served, ServeError<IO::Error, S::Error>>
where
    IO: Write,
    S: FileSink,
{
    let mut list = PartialList::new(buf);
    let listed = sink.partial_names(peer.addr, &mut |name| list.push(name));
    let body = list.finish();
    if let Err(error) = listed {
        let _ = reply(io, Reply::StorageFailed);
        return Err(ServeError::Sink(error));
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            let _ = reply(io, Reply::StorageFailed);
            return Err(ServeError::Http(error));
        }
    };
    let mut head = [0u8; REPLY_BUFFER];
    let len = http::write_response_head(&mut head, 200, "application/json", "", body as u64)
        .map_err(ServeError::Http)?;
    io.write_all(&head[..len]).map_err(ServeError::Io)?;
    io.write_all(&buf[..body]).map_err(ServeError::Io)?;
    io.flush().map_err(ServeError::Io)?;
    Ok(Served::Replied(200))
}

/// Send one file to a peer over a connected blocking stream.
///
/// The source must be positioned at [`Upload::offset`]. `buf` must hold the
/// request head (see [`MIN_CLIENT_BUFFER`]) and is reused to copy the body.
/// The receiver must honour `Expect: 100-continue`, as Go's `net/http`
/// (stock Tailscale) and [`serve`] do.
pub fn send<IO, R>(
    io: &mut IO,
    upload: &Upload<'_>,
    body: &mut R,
    buf: &mut [u8],
) -> Result<(), SendError<IO::Error, R::Error>>
where
    IO: Read + Write,
    R: Read,
{
    validate_name(upload.name).map_err(|_| SendError::InvalidName)?;
    let mut remaining = upload
        .size
        .checked_sub(upload.offset)
        .ok_or(SendError::InvalidOffset)?;
    let len = write_upload_head(upload, buf).map_err(SendError::Http)?;
    io.write_all(&buf[..len]).map_err(SendError::Io)?;
    io.flush().map_err(SendError::Io)?;
    // Only a request with a body asks for `100 Continue` (RFC 9110 §10.1.1).
    if remaining > 0 {
        let (status, carried) = response_status(io, buf, 0)?;
        if status != 100 {
            return Err(SendError::Rejected(status));
        }
        // A final response already behind the interim one ends the exchange
        // before any body byte: the receiver decided without it.
        if carried > 0 {
            return match response_status(io, buf, carried)?.0 {
                200 => Err(SendError::Http(http::Error::Malformed)),
                status => Err(SendError::Rejected(status)),
            };
        }
    }
    while remaining > 0 {
        let want = clamp(remaining, buf.len());
        let read = body.read(&mut buf[..want]).map_err(SendError::Source)?;
        if read == 0 {
            return Err(SendError::SourceEnded);
        }
        io.write_all(&buf[..read]).map_err(SendError::Io)?;
        remaining -= read as u64;
    }
    io.flush().map_err(SendError::Io)?;
    match response_status(io, buf, 0)?.0 {
        200 => Ok(()),
        status => Err(SendError::Rejected(status)),
    }
}

/// Ask the receiver how much of `name` it already holds from this node, and
/// position `source` there.
///
/// Probes on its own connection, compares the receiver's block checksums
/// with the source's blocks from the start, and returns the offset of the
/// first mismatch: pass it as [`Upload::offset`] to [`send`] on a new
/// connection. A receiver without resume support (`404`/`405`) yields zero.
pub fn resume_offset<IO, R>(
    io: &mut IO,
    peer_api: SocketAddr,
    name: &str,
    source: &mut R,
    buf: &mut [u8],
) -> Result<u64, SendError<IO::Error, R::Error>>
where
    IO: Read + Write,
    R: Read + Seek,
{
    validate_name(name).map_err(|_| SendError::InvalidName)?;
    if buf.len() < MIN_CLIENT_BUFFER {
        return Err(SendError::Http(http::Error::OutputTooSmall));
    }
    // The receiver's blocks start at the file's first byte, whatever an
    // earlier attempt left the source at; the fallback offset is zero too.
    source.seek(SeekFrom::Start(0)).map_err(SendError::Source)?;
    let len = write_probe_head(peer_api, name, buf).map_err(SendError::Http)?;
    io.write_all(&buf[..len]).map_err(SendError::Io)?;
    io.flush().map_err(SendError::Io)?;

    let (net, scratch) = buf.split_at_mut(buf.len() / 2);
    let (head, filled) = match read_head(io, net, 0) {
        Ok(Some(head)) => head,
        Ok(None) => return Err(SendError::Http(http::Error::UnexpectedEof)),
        Err(HeadError::Io(error)) => return Err(SendError::Io(error)),
        Err(HeadError::Http(error)) => return Err(SendError::Http(error)),
    };
    let response = http::parse_response(&net[..head]).map_err(SendError::Http)?;
    match response.status {
        200 => {}
        404 | 405 => return Ok(0),
        status => return Err(SendError::Rejected(status)),
    }
    let mut body = ResponseBody::new(response.framing);
    let mut lines = LineBuffer::default();
    let mut offset = 0;
    let mut matching = true;
    let mut pending = head..filled;
    loop {
        while !pending.is_empty() && !body.is_done() {
            let step = body
                .decode(&net[pending.clone()])
                .map_err(SendError::Http)?;
            pending.start += step.consumed;
            let mut data = step.data;
            while matching && !data.is_empty() {
                let Ok(used) = lines.push(data) else {
                    matching = false;
                    break;
                };
                data = &data[used..];
                if let Some(line) = lines.take() {
                    // A line that is not a checksum ends the matching prefix,
                    // as in stock Tailscale.
                    matching = match BlockChecksum::parse_line(line) {
                        Ok(block) if same_block(source, &block, scratch)? => {
                            offset += block.size;
                            true
                        }
                        _ => false,
                    };
                }
            }
        }
        if body.is_done() {
            break;
        }
        let read = io.read(net).map_err(SendError::Io)?;
        if read == 0 {
            body.at_eof().map_err(SendError::Http)?;
            break;
        }
        pending = 0..read;
    }
    source
        .seek(SeekFrom::Start(offset))
        .map_err(SendError::Source)?;
    Ok(offset)
}

/// Whether the source's next `block.size` bytes hash to `block`.
fn same_block<R: Read + Seek, E>(
    source: &mut R,
    block: &BlockChecksum,
    scratch: &mut [u8],
) -> Result<bool, SendError<E, R::Error>> {
    if block.size == 0 {
        return Ok(false);
    }
    let mut hasher = BlockHasher::new(block.size);
    while hasher.remaining() > 0 {
        let want = clamp(hasher.remaining(), scratch.len());
        let read = source
            .read(&mut scratch[..want])
            .map_err(SendError::Source)?;
        if read == 0 {
            return Ok(false);
        }
        hasher.feed(&scratch[..read]);
    }
    Ok(hasher.finish() == *block)
}

/// Read one response head, with `carried` bytes of it already at the front
/// of `buf`. An interim (1xx) response returns how many bytes that followed
/// it are now at the front of `buf`; a final response's body is drained, so
/// the receiver can finish writing before the caller closes.
fn response_status<IO: Read + Write, R>(
    io: &mut IO,
    buf: &mut [u8],
    carried: usize,
) -> Result<(u16, usize), SendError<IO::Error, R>> {
    let (head, filled) = match read_head(io, buf, carried) {
        Ok(Some(head)) => head,
        Ok(None) => return Err(SendError::Http(http::Error::UnexpectedEof)),
        Err(HeadError::Io(error)) => return Err(SendError::Io(error)),
        Err(HeadError::Http(error)) => return Err(SendError::Http(error)),
    };
    let response = http::parse_response(&buf[..head]).map_err(SendError::Http)?;
    if response.status < 200 {
        buf.copy_within(head..filled, 0);
        return Ok((response.status, filled - head));
    }
    let mut body = ResponseBody::new(response.framing);
    let mut pending = head..filled;
    loop {
        while !pending.is_empty() && !body.is_done() {
            let step = body
                .decode(&buf[pending.clone()])
                .map_err(SendError::Http)?;
            pending.start += step.consumed;
        }
        if body.is_done() {
            return Ok((response.status, 0));
        }
        let read = io.read(buf).map_err(SendError::Io)?;
        if read == 0 {
            return body
                .at_eof()
                .map(|()| (response.status, 0))
                .map_err(SendError::Http);
        }
        pending = 0..read;
    }
}

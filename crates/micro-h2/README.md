# micro-h2

A small, client-only HTTP/2 implementation for systems without `std` or an
allocator.

`micro-h2` exists to carry tailfeather's control-plane requests. It is sans-I/O:
the caller moves bytes to and from a socket while `Connection` owns the HTTP/2
and HPACK state.

## What it handles

- the client preface and SETTINGS exchange
- bounded request streams with HEADERS and optional DATA
- response HEADERS, CONTINUATION, and DATA frames
- connection and stream flow control
- PING, RST_STREAM, GOAWAY, padding, and unknown frame types
- HPACK static and dynamic tables, including Huffman decoding

The usual flow is:

1. Create a `Connection` and send the bytes from `Connection::start`.
2. Open a stream with `Connection::request`.
3. Feed each complete frame to `Connection::recv`.
4. Send any acknowledgement or WINDOW_UPDATE bytes it writes, and act on the
   returned `Event`.

## Deliberate limits

This is not a general browser HTTP/2 stack. It has four concurrent streams, a
4 KiB header-block buffer, no server mode, no push, no priority tree, no
trailers, and no outgoing CONTINUATION frames. Unsupported features are refused
instead of partially implemented.

TLS, TCP, retries, and request scheduling belong to the caller. This crate only
turns HTTP/2 bytes into bounded state and events.

## Verification

Unit tests cover framing, HPACK state, Huffman decoding, and flow control.
Differential tests in `ts-conformance` exchange traffic with the Rust `h2`
implementation and compare HPACK in both directions with `fluke-hpack`.

See the [repository README](https://github.com/pawelchcki/tailfeather) for where
this crate sits in the full stack.

## License

MIT OR Apache-2.0, at your option.

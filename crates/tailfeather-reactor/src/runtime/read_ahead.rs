//! Cancellation-safe reads over adapters whose own reads are not.
//!
//! [`super::SplitStream`] adapters need not make record reads
//! cancellation-safe (embedded-tls, for one, keeps a partially read record
//! header in its read future). A [`ReadAhead`] pump owns the only read future
//! for the connection's lifetime and hands complete chunks to a [`Pipe`],
//! whose reads only copy buffered bytes and can be dropped at any await.
use core::{
    cell::{Cell, RefCell},
    convert::Infallible,
    future::poll_fn,
    task::{Poll, Waker},
};
use embedded_io_async::{Error as _, ErrorKind, ErrorType, Read, Write};

pub(super) struct ReadAhead<const N: usize> {
    buffer: RefCell<[u8; N]>,
    /// Unread bytes are `buffer[start..end]`; `end == 0` means the pump owns
    /// the buffer and may be reading into it.
    start: Cell<usize>,
    end: Cell<usize>,
    /// `Some(None)` is end of stream, `Some(Some(kind))` a read failure.
    closed: Cell<Option<Option<ErrorKind>>>,
    reader: Cell<Option<Waker>>,
    pump: Cell<Option<Waker>>,
}

impl<const N: usize> ReadAhead<N> {
    pub(super) const fn new() -> Self {
        Self {
            buffer: RefCell::new([0; N]),
            start: Cell::new(0),
            end: Cell::new(0),
            closed: Cell::new(None),
            reader: Cell::new(None),
            pump: Cell::new(None),
        }
    }

    /// Drive the connection's single read future. It must be polled for as
    /// long as any [`Pipe`] over this buffer is used and dropped only with
    /// the whole connection.
    // The buffer is borrowed across the read only while it is empty, and the
    // consumer borrows it only while it holds unread bytes.
    #[allow(clippy::await_holding_refcell_ref)]
    pub(super) async fn pump<R: Read>(&self, reader: &mut R) -> Infallible {
        loop {
            poll_fn(|cx| {
                if self.end.get() == 0 {
                    Poll::Ready(())
                } else {
                    self.pump.set(Some(cx.waker().clone()));
                    Poll::Pending
                }
            })
            .await;
            let result = reader.read(&mut self.buffer.borrow_mut()[..]).await;
            match result {
                Ok(0) => self.closed.set(Some(None)),
                Ok(len) => {
                    self.start.set(0);
                    self.end.set(len);
                }
                Err(error) => self.closed.set(Some(Some(error.kind()))),
            }
            if let Some(waker) = self.reader.take() {
                waker.wake();
            }
            if self.closed.get().is_some() {
                return core::future::pending().await;
            }
        }
    }

    fn take(&self, output: &mut [u8]) -> Poll<Result<usize, ErrorKind>> {
        let (start, end) = (self.start.get(), self.end.get());
        if start < end {
            let len = output.len().min(end - start);
            output[..len].copy_from_slice(&self.buffer.borrow()[start..start + len]);
            if start + len == end {
                self.start.set(0);
                self.end.set(0);
                if let Some(waker) = self.pump.take() {
                    waker.wake();
                }
            } else {
                self.start.set(start + len);
            }
            return Poll::Ready(Ok(len));
        }
        match self.closed.get() {
            Some(None) => Poll::Ready(Ok(0)),
            Some(Some(kind)) => Poll::Ready(Err(kind)),
            None => Poll::Pending,
        }
    }
}

/// A connection whose reads come from a [`ReadAhead`] and whose writes go
/// directly to the adapter's write half.
pub(super) struct Pipe<'a, W, const N: usize> {
    pub(super) ahead: &'a ReadAhead<N>,
    pub(super) writer: W,
}

impl<W: Write, const N: usize> ErrorType for Pipe<'_, W, N> {
    type Error = ErrorKind;
}

impl<W: Write, const N: usize> Read for Pipe<'_, W, N> {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ErrorKind> {
        if output.is_empty() {
            return Ok(0);
        }
        poll_fn(|cx| {
            let result = self.ahead.take(output);
            if result.is_pending() {
                self.ahead.reader.set(Some(cx.waker().clone()));
            }
            result
        })
        .await
    }
}

impl<W: Write, const N: usize> Write for Pipe<'_, W, N> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        self.writer.write(bytes).await.map_err(|error| error.kind())
    }
    async fn flush(&mut self) -> Result<(), ErrorKind> {
        self.writer.flush().await.map_err(|error| error.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        task::{Context, Poll},
    };

    /// Like embedded-tls, keeps a partially read 5-byte header in its future:
    /// dropping that future mid-header would desynchronize the stream.
    struct Records<'a> {
        input: &'a [u8],
        position: usize,
        available: &'a Cell<usize>,
    }
    impl ErrorType for Records<'_> {
        type Error = ErrorKind;
    }
    impl Read for Records<'_> {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, ErrorKind> {
            let mut header = [0; 5];
            let mut filled = 0;
            while filled < header.len() {
                filled += poll_fn(|_| {
                    if self.position < self.available.get() {
                        header[filled] = self.input[self.position];
                        self.position += 1;
                        Poll::Ready(1)
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            let len = output.len().min(header.len());
            output[..len].copy_from_slice(&header[..len]);
            Ok(len)
        }
    }

    #[test]
    fn dropping_pipe_reads_never_loses_a_partially_read_record() {
        let available = Cell::new(0);
        let mut records = Records {
            input: b"firstsecond",
            position: 0,
            available: &available,
        };
        let ahead = ReadAhead::<8>::new();
        let mut pipe = Pipe {
            ahead: &ahead,
            writer: Discard,
        };
        let mut context = Context::from_waker(Waker::noop());
        let mut pump = core::pin::pin!(ahead.pump(&mut records));
        let mut received = std::vec::Vec::new();
        // Every consumer read is abandoned after a single poll.
        let mut read_once = |pipe: &mut Pipe<'_, Discard, 8>| {
            let mut output = [0; 3];
            let result = core::pin::pin!(pipe.read(&mut output))
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            if let Poll::Ready(Ok(len)) = result {
                received.extend_from_slice(&output[..len]);
            }
        };
        for step in 1..=10 {
            available.set(step);
            assert!(pump.as_mut().poll(&mut context).is_pending());
            read_once(&mut pipe);
            assert!(pump.as_mut().poll(&mut context).is_pending());
            read_once(&mut pipe);
        }
        assert_eq!(received, b"firstsecon");
    }

    #[test]
    fn end_of_stream_and_failures_reach_the_consumer() {
        struct Fails(Option<ErrorKind>);
        impl ErrorType for Fails {
            type Error = ErrorKind;
        }
        impl Read for Fails {
            async fn read(&mut self, _: &mut [u8]) -> Result<usize, ErrorKind> {
                self.0.map_or(Ok(0), Err)
            }
        }
        for (outcome, expected) in [
            (None, Ok(0)),
            (
                Some(ErrorKind::ConnectionReset),
                Err(ErrorKind::ConnectionReset),
            ),
        ] {
            let ahead = ReadAhead::<8>::new();
            let mut reader = Fails(outcome);
            let mut context = Context::from_waker(Waker::noop());
            let mut pump = core::pin::pin!(ahead.pump(&mut reader));
            assert!(pump.as_mut().poll(&mut context).is_pending());
            let mut pipe = Pipe {
                ahead: &ahead,
                writer: Discard,
            };
            let mut output = [0; 4];
            assert_eq!(
                core::pin::pin!(pipe.read(&mut output))
                    .as_mut()
                    .poll(&mut context),
                Poll::Ready(expected)
            );
        }
    }

    struct Discard;
    impl ErrorType for Discard {
        type Error = ErrorKind;
    }
    impl Write for Discard {
        async fn write(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
            Ok(bytes.len())
        }
        async fn flush(&mut self) -> Result<(), ErrorKind> {
            Ok(())
        }
    }
}

//! A single-threaded executor whose only blocking primitive is `poll`.
//!
//! # Why not `embassy-executor`
//!
//! Its `platform-spin` backend busy-polls, which would make a soak test measure
//! the executor rather than the tunnel, and it has an unresolved linker problem
//! on bare `x86_64`. But the deeper reason is that there is nothing here for a
//! general executor to do. Every library crate in this project is sans-io: each
//! reports what it wants to send and when it next wants to be woken, and never
//! blocks. That leaves exactly one question to answer in the whole program —
//! "sleep until one of these descriptors is ready or this deadline passes" —
//! which is one syscall.
//!
//! So this is a reactor with just enough executor around it to drive futures.
//! The library crates stay executor-agnostic; only this file knows about `poll`,
//! and an Embassy build would replace it without touching anything else.
//!
//! # Shape
//!
//! [`block_on`] drives one top-level future. When that future returns `Pending`
//! it has, by construction, registered at least one wakeup source with the
//! [`Reactor`] — a descriptor, a deadline, or both — and `block_on` sleeps on
//! exactly those. Wakers are inert: after any wait the top-level future is
//! polled again unconditionally, so there is no wakeup to lose and no need for
//! the atomics a multi-threaded executor would require.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use rustix::event::{PollFd, PollFlags};
use rustix::fd::{BorrowedFd, RawFd};
use rustix::fs::Timespec;

/// How many descriptors may be waited on at once.
///
/// A complete node needs the WireGuard socket, the control connection, and a
/// DERP connection, with room for one of each to be mid-replacement.
pub const MAX_SOURCES: usize = 8;

#[derive(Clone, Copy)]
struct Source {
    fd: RawFd,
    events: PollFlags,
    revents: PollFlags,
}

/// The set of things a sleeping program is waiting for.
pub struct Reactor {
    sources: RefCell<heapless::Vec<Source, MAX_SOURCES>>,
    /// The earliest deadline any future has asked for, in the clock's
    /// milliseconds. Recomputed from scratch each poll round, because a future
    /// that no longer cares has no way to retract a deadline it set.
    deadline: Cell<Option<u64>>,
    clock: crate::time::Clock,
}

impl Reactor {
    pub fn new(clock: crate::time::Clock) -> Self {
        Self {
            sources: RefCell::new(heapless::Vec::new()),
            deadline: Cell::new(None),
            clock,
        }
    }

    /// Wait for `fd` to become ready for `events`.
    pub fn ready(&self, fd: RawFd, events: PollFlags) -> Ready<'_> {
        Ready {
            reactor: self,
            fd,
            events,
        }
    }

    /// Complete once the clock reaches `deadline_millis`.
    pub fn sleep_until(&self, deadline_millis: u64) -> Sleep<'_> {
        Sleep {
            reactor: self,
            deadline_millis,
        }
    }

    /// The clock's milliseconds, for a caller computing its own deadline.
    pub fn clock_millis(&self) -> u64 {
        self.clock.millis()
    }

    pub fn sleep(&self, millis: u64) -> Sleep<'_> {
        self.sleep_until(self.clock.millis() + millis)
    }

    /// Register interest and report whatever readiness the last wait found.
    ///
    /// Readiness is consumed by reading it: the source is dropped from the set
    /// so that a future which has been satisfied stops contributing to the next
    /// wait. A future still interested re-registers on its next poll, which is
    /// the same call.
    fn poll_source(&self, fd: RawFd, events: PollFlags) -> Poll<PollFlags> {
        let mut sources = self.sources.borrow_mut();
        if let Some(index) = sources
            .iter()
            .position(|s| s.fd == fd && s.events == events)
        {
            let revents = sources[index].revents;
            if !revents.is_empty() {
                sources.swap_remove(index);
                return Poll::Ready(revents);
            }
            return Poll::Pending;
        }
        // A full source table is a programming error rather than a runtime
        // condition: the set of descriptors a node uses is fixed and small.
        sources
            .push(Source {
                fd,
                events,
                revents: PollFlags::empty(),
            })
            .unwrap_or_else(|_| panic!("more than {MAX_SOURCES} wakeup sources"));
        Poll::Pending
    }

    fn forget_source(&self, fd: RawFd, events: PollFlags) {
        let mut sources = self.sources.borrow_mut();
        if let Some(index) = sources
            .iter()
            .position(|s| s.fd == fd && s.events == events)
        {
            sources.swap_remove(index);
        }
    }

    fn note_deadline(&self, deadline_millis: u64) {
        let earliest = match self.deadline.get() {
            Some(existing) => existing.min(deadline_millis),
            None => deadline_millis,
        };
        self.deadline.set(Some(earliest));
    }

    /// Sleep until something registered becomes ready, then record what did.
    fn wait(&self) {
        let mut sources = self.sources.borrow_mut();
        let timeout = self.deadline.take().map(|deadline| {
            // A deadline already past must not become a negative timeout, which
            // would be read as "block forever".
            let remaining = deadline.saturating_sub(self.clock.millis());
            Timespec {
                tv_sec: (remaining / 1_000) as i64,
                tv_nsec: ((remaining % 1_000) * 1_000_000) as i64,
            }
        });

        if sources.is_empty() && timeout.is_none() {
            // The top-level future returned Pending having registered nothing,
            // so nothing can ever wake it.
            panic!("the executor would sleep forever");
        }

        let mut fds: heapless::Vec<PollFd<'_>, MAX_SOURCES> = heapless::Vec::new();
        for source in sources.iter() {
            // SAFETY: the descriptor is owned by a live socket in the future
            // being driven. A source is removed on drop of the `Ready` that
            // registered it, and that `Ready` borrows the socket, so the socket
            // cannot have been closed while its source is still registered.
            let fd = unsafe { BorrowedFd::borrow_raw(source.fd) };
            let _ = fds.push(PollFd::from_borrowed_fd(fd, source.events));
        }

        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            // A signal interrupted the wait, or the timeout expired; either way
            // polling the future again is the right response.
            Err(rustix::io::Errno::INTR) | Ok(0) => {}
            Err(_) => {}
            Ok(_) => {
                for (source, fd) in sources.iter_mut().zip(fds.iter()) {
                    // Errors and hangups are reported whether or not they were
                    // asked for, and must wake the waiter: otherwise a closed
                    // connection sleeps until its deadline instead of failing.
                    source.revents = fd.revents();
                }
            }
        }
    }
}

/// Waits for readiness on one descriptor.
pub struct Ready<'r> {
    reactor: &'r Reactor,
    fd: RawFd,
    events: PollFlags,
}

impl Future for Ready<'_> {
    /// The events that actually fired, which may include `ERR`/`HUP` even
    /// though those cannot be asked for.
    type Output = PollFlags;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<PollFlags> {
        self.reactor.poll_source(self.fd, self.events)
    }
}

impl Drop for Ready<'_> {
    /// Deregister on drop.
    ///
    /// A `select` that abandons this branch would otherwise leave a source
    /// behind that nobody will ever consume the readiness of, and `poll` would
    /// return immediately on it forever — a busy loop that looks like the
    /// reactor is broken rather than like a leak.
    fn drop(&mut self) {
        self.reactor.forget_source(self.fd, self.events);
    }
}

/// Waits for the clock to reach a deadline.
pub struct Sleep<'r> {
    reactor: &'r Reactor,
    deadline_millis: u64,
}

impl Future for Sleep<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.reactor.clock.millis() >= self.deadline_millis {
            return Poll::Ready(());
        }
        self.reactor.note_deadline(self.deadline_millis);
        Poll::Pending
    }
}

/// A waker that does nothing.
///
/// Sound because `block_on` re-polls the whole future after every wait, so a
/// "missed" wakeup cannot exist: there is one task, and it is always polled.
const VTABLE: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(core::ptr::null(), &VTABLE),
    |_| {},
    |_| {},
    |_| {},
);

fn noop_waker() -> Waker {
    // SAFETY: every function in VTABLE ignores its data pointer, so the null
    // pointer is never dereferenced, and clone returns an equally inert waker.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

/// Drive `future` to completion, sleeping whenever it is pending.
pub fn block_on<F: Future>(reactor: &Reactor, future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        reactor.wait();
    }
}

/// Poll two futures, returning whichever finishes first.
///
/// A node has several things happening at once — datagrams arriving, a control
/// stream to service, timers to fire — and this is all the concurrency needed to
/// express that without a task queue. `embassy-futures` offers the same thing;
/// it is a dozen lines, and not taking the dependency keeps the harness's build
/// for the bare target down to crates already in the tree.
pub async fn select<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = core::pin::pin!(a);
    let mut b = core::pin::pin!(b);
    core::future::poll_fn(move |cx| {
        if let Poll::Ready(value) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::First(value));
        }
        if let Poll::Ready(value) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Second(value));
        }
        Poll::Pending
    })
    .await
}

/// Poll four futures once each, beginning at `first` and wrapping around.
///
/// Callers that repeatedly wait on busy sources can advance `first` after each
/// completion so that one continuously-ready source cannot starve the others.
pub async fn select4<A: Future, B: Future, C: Future, D: Future>(
    first: u8,
    a: A,
    b: B,
    c: C,
    d: D,
) -> Either4<A::Output, B::Output, C::Output, D::Output> {
    let mut a = core::pin::pin!(a);
    let mut b = core::pin::pin!(b);
    let mut c = core::pin::pin!(c);
    let mut d = core::pin::pin!(d);
    core::future::poll_fn(move |cx| {
        for offset in 0..4 {
            match (usize::from(first) + offset) % 4 {
                0 => {
                    if let Poll::Ready(value) = a.as_mut().poll(cx) {
                        return Poll::Ready(Either4::First(value));
                    }
                }
                1 => {
                    if let Poll::Ready(value) = b.as_mut().poll(cx) {
                        return Poll::Ready(Either4::Second(value));
                    }
                }
                2 => {
                    if let Poll::Ready(value) = c.as_mut().poll(cx) {
                        return Poll::Ready(Either4::Third(value));
                    }
                }
                _ => {
                    if let Poll::Ready(value) = d.as_mut().poll(cx) {
                        return Poll::Ready(Either4::Fourth(value));
                    }
                }
            }
        }
        Poll::Pending
    })
    .await
}

pub enum Either<A, B> {
    First(A),
    Second(B),
}

pub enum Either4<A, B, C, D> {
    First(A),
    Second(B),
    Third(C),
    Fourth(D),
}

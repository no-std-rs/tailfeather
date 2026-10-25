//! Clock adapters and allocation-free cooperative scheduling.

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use pin_project_lite::pin_project;

/// A monotonic clock. Absolute deadlines are milliseconds in this clock's epoch.
pub trait Clock {
    fn now_millis(&self) -> u64;
    async fn sleep_until(&self, deadline_ms: u64);
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now_millis(&self) -> u64 {
        C::now_millis(self)
    }
    async fn sleep_until(&self, deadline_ms: u64) {
        C::sleep_until(self, deadline_ms).await;
    }
}

pub struct Reactor<C> {
    clock: C,
}

impl<C: Clock> Reactor<C> {
    pub const fn with_clock(clock: C) -> Self {
        Self { clock }
    }

    pub fn clock_millis(&self) -> u64 {
        self.clock.now_millis()
    }

    pub async fn sleep_until(&self, deadline_ms: u64) {
        self.clock.sleep_until(deadline_ms).await;
    }

    pub async fn sleep(&self, millis: u64) {
        self.sleep_until(self.clock_millis().saturating_add(millis))
            .await;
    }

    /// Cancel the operation when its total deadline expires.
    pub fn timeout<F: Future>(
        &self,
        millis: u64,
        operation: F,
    ) -> impl Future<Output = Result<F::Output, Timeout>> {
        TimeoutFuture {
            inner: select(operation, self.sleep(millis)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout;

/// Cooperatively yield after a bounded batch of immediately ready work.
pub async fn yield_now() {
    let mut yielded = false;
    core::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

#[derive(Debug, PartialEq, Eq)]
pub enum Either<A, B> {
    First(A),
    Second(B),
}

pin_project! {
    /// Directly owns its futures, avoiding copies through nested async wrappers.
    pub struct Select<A, B> {
        #[pin] first: A,
        #[pin] second: B,
        second_first: bool,
    }
}

pub fn select<A: Future, B: Future>(first: A, second: B) -> Select<A, B> {
    select_fair(false, first, second)
}

/// Choose the initial branch explicitly so a busy actor can alternate priority.
pub fn select_fair<A: Future, B: Future>(second_first: bool, first: A, second: B) -> Select<A, B> {
    Select {
        first,
        second,
        second_first,
    }
}

impl<A: Future, B: Future> Future for Select<A, B> {
    type Output = Either<A::Output, B::Output>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if *this.second_first
            && let Poll::Ready(value) = this.second.as_mut().poll(cx)
        {
            return Poll::Ready(Either::Second(value));
        }
        if let Poll::Ready(value) = this.first.poll(cx) {
            return Poll::Ready(Either::First(value));
        }
        if !*this.second_first
            && let Poll::Ready(value) = this.second.poll(cx)
        {
            return Poll::Ready(Either::Second(value));
        }
        Poll::Pending
    }
}

pin_project! {
    struct TimeoutFuture<A, B> { #[pin] inner: Select<A, B> }
}
impl<A: Future, B: Future<Output = ()>> Future for TimeoutFuture<A, B> {
    type Output = Result<A::Output, Timeout>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx).map(|value| match value {
            Either::First(result) => Ok(result),
            Either::Second(()) => Err(Timeout),
        })
    }
}

#[cfg(feature = "std")]
pub struct TokioClock(tokio::time::Instant);

#[cfg(feature = "std")]
impl Default for TokioClock {
    fn default() -> Self {
        Self(tokio::time::Instant::now())
    }
}

#[cfg(feature = "std")]
impl Clock for TokioClock {
    fn now_millis(&self) -> u64 {
        self.0.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    async fn sleep_until(&self, deadline_ms: u64) {
        let remaining = deadline_ms.saturating_sub(self.now_millis());
        tokio::time::sleep(core::time::Duration::from_millis(remaining)).await;
    }
}

/// Uses the application's Embassy time driver and timer queue configuration.
#[cfg(feature = "embassy")]
#[derive(Default)]
pub struct EmbassyClock;

#[cfg(feature = "embassy")]
impl Clock for EmbassyClock {
    fn now_millis(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }

    async fn sleep_until(&self, deadline_ms: u64) {
        embassy_time::Timer::at(embassy_time::Instant::from_millis(deadline_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    #[cfg(feature = "std")]
    async fn timeout_cancels_a_stalled_operation_at_its_deadline() {
        let reactor = Reactor::with_clock(TokioClock::default());
        let start = reactor.clock_millis();
        assert_eq!(
            reactor.timeout(150, core::future::pending::<()>()).await,
            Err(Timeout)
        );
        assert_eq!(reactor.clock_millis() - start, 150);
    }

    #[tokio::test]
    async fn busy_sources_can_alternate_without_starvation() {
        for second_first in [false, true] {
            let result = select_fair(second_first, async { 1 }, async { 2 }).await;
            assert_eq!(
                result,
                if second_first {
                    Either::Second(2)
                } else {
                    Either::First(1)
                }
            );
        }
    }
}

use std::{
    future::Future,
    time::{Duration, Instant},
};
pub struct Reactor(Instant);
impl Reactor {
    pub fn new() -> Self {
        Self(Instant::now())
    }
    pub fn clock_millis(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
    pub async fn sleep(&self, millis: u64) {
        tokio::time::sleep(Duration::from_millis(millis)).await
    }
}
pub enum Either<A, B> {
    First(A),
    Second(B),
}
pub async fn select<A: Future, B: Future>(first: A, second: B) -> Either<A::Output, B::Output> {
    tokio::select! {result=first=>Either::First(result),result=second=>Either::Second(result)}
}

//! Storage for collections that scale with the number of peers.
//!
//! Without the `alloc` feature a [`PeerVec<T, N>`] is a `heapless::Vec<T, N>`:
//! its full capacity is reserved inline, which is what a microcontroller with
//! a fixed RAM budget wants. With `alloc` it is a heap vector that grows on
//! demand up to `N` entries, so a host with memory to spare can choose a large
//! `N`, or [`UNBOUNDED`], and pay only for the peers it actually has.
//!
//! Either way a push that does not fit is refused rather than aborting: with
//! `alloc`, running out of memory (for the table or for the element itself)
//! is reported exactly like reaching `N`, so callers keep one
//! bounded-capacity code path.

use core::borrow::{Borrow, BorrowMut};
use core::ops::{Index, IndexMut};

/// A capacity with no configured limit; the collection grows while the
/// allocator has memory. Only meaningful with the `alloc` feature: without it
/// the capacity is reserved inline and this would not fit in memory.
pub const UNBOUNDED: usize = usize::MAX;

#[cfg(not(feature = "alloc"))]
type Slot<T> = T;

/// Each element lives in its own allocation so that it never moves once
/// stored: growing the vector or removing an element moves only handles,
/// never leaving copies of session keys behind in freed memory.
///
/// A one-element `Vec` rather than a `Box`, because stable Rust can allocate
/// a `Vec` fallibly (`try_reserve_exact`) but not a `Box`. It never grows past
/// its single element, so it never reallocates either.
#[cfg(feature = "alloc")]
#[derive(Clone)]
struct Slot<T>(alloc::vec::Vec<T>);

#[cfg(feature = "alloc")]
impl<T> Slot<T> {
    fn try_new(value: T) -> Result<Self, T> {
        let mut storage = alloc::vec::Vec::new();
        if storage.try_reserve_exact(1).is_err() {
            return Err(value);
        }
        storage.push(value);
        Ok(Self(storage))
    }
}

#[cfg(feature = "alloc")]
impl<T> Borrow<T> for Slot<T> {
    fn borrow(&self) -> &T {
        &self.0[0]
    }
}

#[cfg(feature = "alloc")]
impl<T> BorrowMut<T> for Slot<T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.0[0]
    }
}

/// A vector of at most `N` elements. See the [module documentation](self).
#[derive(Clone)]
pub struct PeerVec<T, const N: usize> {
    #[cfg(not(feature = "alloc"))]
    inner: heapless::Vec<Slot<T>, N>,
    #[cfg(feature = "alloc")]
    inner: alloc::vec::Vec<Slot<T>>,
}

impl<T, const N: usize> PeerVec<T, N> {
    pub const fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            inner: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            inner: alloc::vec::Vec::new(),
        }
    }

    /// The configured limit, which with `alloc` is not reserved up front.
    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.len() >= N
    }

    /// Append `value`, or return it if the vector already holds `N` elements
    /// or (with `alloc`) the allocator cannot grow it.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        #[cfg(not(feature = "alloc"))]
        {
            self.inner.push(value)
        }
        #[cfg(feature = "alloc")]
        {
            if self.inner.len() >= N || self.inner.try_reserve(1).is_err() {
                return Err(value);
            }
            self.inner.push(Slot::try_new(value)?);
            Ok(())
        }
    }

    /// Make room for the vector to hold `total` elements, so that pushes up
    /// to that length cannot be refused. Returns `false`, changing nothing, if
    /// `total` exceeds `N` or (with `alloc`) the allocator cannot provide it.
    #[must_use]
    pub fn try_reserve_total(&mut self, total: usize) -> bool {
        if total > N {
            return false;
        }
        #[cfg(feature = "alloc")]
        {
            self.inner
                .try_reserve(total.saturating_sub(self.inner.len()))
                .is_ok()
        }
        #[cfg(not(feature = "alloc"))]
        {
            true
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index).map(|slot| slot.borrow())
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index).map(|slot| slot.borrow_mut())
    }

    pub fn first(&self) -> Option<&T> {
        self.get(0)
    }

    pub fn last(&self) -> Option<&T> {
        self.inner.last().map(|slot| slot.borrow())
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + ExactSizeIterator + Clone {
        self.inner.iter().map(|slot| slot.borrow())
    }

    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut T> + ExactSizeIterator {
        self.inner.iter_mut().map(|slot| slot.borrow_mut())
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        self.inner.retain(|slot| keep(slot.borrow()));
    }

    pub fn retain_mut(&mut self, mut keep: impl FnMut(&mut T) -> bool) {
        self.inner.retain_mut(|slot| keep(slot.borrow_mut()));
    }

    pub fn swap_remove(&mut self, index: usize) -> T {
        Self::unslot(self.inner.swap_remove(index))
    }

    pub fn remove(&mut self, index: usize) -> T {
        Self::unslot(self.inner.remove(index))
    }

    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop().map(Self::unslot)
    }

    #[cfg(not(feature = "alloc"))]
    fn unslot(slot: Slot<T>) -> T {
        slot
    }

    #[cfg(feature = "alloc")]
    fn unslot(mut slot: Slot<T>) -> T {
        slot.0.pop().expect("a slot holds exactly one element")
    }
}

impl<T, const N: usize> Default for PeerVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Index<usize> for PeerVec<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.inner[index].borrow()
    }
}

impl<T, const N: usize> IndexMut<usize> for PeerVec<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.inner[index].borrow_mut()
    }
}

impl<T: core::fmt::Debug, const N: usize> core::fmt::Debug for PeerVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq, const N: usize> PartialEq for PeerVec<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<T: Eq, const N: usize> Eq for PeerVec<T, N> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_pushes_past_the_limit() {
        let mut values = PeerVec::<u8, 2>::new();
        assert_eq!(values.push(1), Ok(()));
        assert_eq!(values.push(2), Ok(()));
        assert_eq!(values.push(3), Err(3));
        assert_eq!(
            values.iter().copied().collect::<heapless::Vec<u8, 4>>(),
            [1, 2]
        );
        values.swap_remove(0);
        assert_eq!(values.push(4), Ok(()));
        assert_eq!(
            values.iter().copied().collect::<heapless::Vec<u8, 4>>(),
            [2, 4]
        );
    }

    #[test]
    fn reservations_respect_the_limit_and_change_nothing_on_failure() {
        let mut values = PeerVec::<u8, 3>::new();
        values.push(1).unwrap();
        assert!(values.try_reserve_total(3));
        assert!(!values.try_reserve_total(4));
        assert_eq!(values.len(), 1);
        values.push(2).unwrap();
        values.push(3).unwrap();
        assert_eq!(values.push(4), Err(4));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unbounded_grows_on_demand() {
        let mut values = PeerVec::<u32, UNBOUNDED>::new();
        for value in 0..10_000 {
            values.push(value).unwrap();
        }
        assert_eq!(values.len(), 10_000);
        assert!(core::mem::size_of_val(&values) <= 3 * core::mem::size_of::<usize>());
        assert_eq!(values[9_999], 9_999);
    }
}

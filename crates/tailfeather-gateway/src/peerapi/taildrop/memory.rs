//! A heap-backed [`FileSink`] for hosts, browsers and tests.

use alloc::{string::String, vec::Vec};
use core::net::IpAddr;

use super::{AsyncFileSink, FileSink, Incoming, Refusal};

/// A file kept by the sink, finished or partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFile {
    pub from: IpAddr,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// The file would exceed the sink's remaining byte budget.
    OverBudget,
    /// The allocator refused to grow a buffer.
    OutOfMemory,
    /// A resumed upload starts past what this sink kept of the file.
    BadOffset,
    /// `write` or `finish` without a `begin`.
    NoFile,
}

impl core::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OverBudget => "received files exceed the memory budget",
            Self::OutOfMemory => "out of memory while receiving a file",
            Self::BadOffset => "resume offset past the kept partial file",
            Self::NoFile => "no file in progress",
        })
    }
}

impl core::error::Error for MemoryError {}

/// Keeps received files in memory, within a total byte budget.
///
/// An aborted upload is kept as its sender's partial file, so the sender can
/// resume it; finished and partial files share the budget. The budget charges
/// what is allocated, not just what arrived: each file's record, name and
/// buffer capacity, so a reservation for an announced size counts until the
/// bytes come, and an aborted upload gives back what it reserved for bytes
/// that never arrived. The record tables count by capacity, spare slots
/// included, so [`MemorySink::allocated`] never exceeds the budget; only the
/// sink's own struct lies outside it. Allocation is fallible: a full heap
/// fails the transfer (the sender sees `500`) instead of aborting the process.
#[derive(Debug)]
pub struct MemorySink {
    budget: usize,
    current: Option<ReceivedFile>,
    files: Vec<ReceivedFile>,
    partials: Vec<ReceivedFile>,
}

impl MemorySink {
    /// Hold up to `budget` bytes of file data at once. Taking files out
    /// returns their bytes to the budget.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            current: None,
            files: Vec::new(),
            partials: Vec::new(),
        }
    }

    /// Finished files, oldest first.
    pub fn files(&self) -> &[ReceivedFile] {
        &self.files
    }

    /// Partial files kept from aborted uploads.
    pub fn partials(&self) -> &[ReceivedFile] {
        &self.partials
    }

    /// Remove and return all finished files.
    pub fn take(&mut self) -> Vec<ReceivedFile> {
        core::mem::take(&mut self.files)
    }

    /// Heap bytes the sink holds and charges against its budget: both record
    /// tables at their capacity, and every file's name and buffer.
    pub fn allocated(&self) -> usize {
        self.used()
    }

    fn used(&self) -> usize {
        let tables = (self.files.capacity() + self.partials.capacity()).saturating_mul(RECORD);
        self.files
            .iter()
            .chain(&self.partials)
            .chain(&self.current)
            .map(heap)
            .fold(tables, usize::saturating_add)
    }

    fn remaining(&self) -> usize {
        self.budget.saturating_sub(self.used())
    }

    fn partial(&self, from: IpAddr, name: &str) -> Option<usize> {
        self.partials
            .iter()
            .position(|file| file.from == from && file.name == name)
    }

    fn begin_file(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<MemoryError>> {
        self.abort_file();
        if self.files.iter().any(|kept| kept.name == file.name) {
            return Err(Refusal::Exists);
        }
        // Convert before taking the partial out, so a refusal cannot lose it.
        let kept = usize::try_from(file.offset).map_err(|_| MemoryError::BadOffset)?;
        let resumed = self.partial(file.from, file.name).map(|index| {
            let partial = self.partials.swap_remove(index);
            // The emptied slot would otherwise stay allocated, and charged.
            release_spare_slots(&mut self.partials);
            partial
        });
        let mut current = match resumed {
            Some(mut partial) => {
                if kept > partial.data.len() {
                    // Keep the partial for a correct retry.
                    self.partials.push(partial);
                    return Err(MemoryError::BadOffset.into());
                }
                partial.data.truncate(kept);
                partial
            }
            None if file.offset != 0 => return Err(MemoryError::BadOffset.into()),
            None => {
                let mut name = String::new();
                name.try_reserve_exact(file.name.len())
                    .map_err(|_| MemoryError::OutOfMemory)?;
                name.push_str(file.name);
                ReceivedFile {
                    from: file.from,
                    name,
                    data: Vec::new(),
                }
            }
        };
        let declared = match file.size {
            Some(size) => usize::try_from(size).map_err(|_| MemoryError::OverBudget)?,
            None => 0,
        };
        // The record itself must fit as well as what it announces: an empty
        // upload still keeps a record and a name. What it announces costs
        // only the growth beyond the buffer it already holds: a resumed
        // partial keeps its capacity after `truncate`, and reserving
        // `declared` from length `kept` needs exactly `kept + declared`.
        let growth = current
            .data
            .len()
            .checked_add(declared)
            .map(|needed| needed.saturating_sub(current.data.capacity()));
        // Landing this file needs a free slot in each table (it may finish or
        // be aborted); a full table grows by exactly one record.
        let slots = [&self.files, &self.partials]
            .iter()
            .filter(|table| table.len() == table.capacity())
            .count()
            * RECORD;
        let fits = growth
            .and_then(|growth| heap(&current).checked_add(growth))
            .and_then(|total| total.checked_add(slots))
            .is_some_and(|total| total <= self.remaining());
        if !fits {
            if current.data.is_empty() {
                return Err(MemoryError::OverBudget.into());
            }
            self.partials.push(current);
            return Err(MemoryError::OverBudget.into());
        }
        // Exact: the tables grow by the slot just charged, no more.
        let reserved = current
            .data
            .try_reserve_exact(declared)
            .and_then(|()| self.files.try_reserve_exact(1))
            .and_then(|()| self.partials.try_reserve_exact(1));
        if reserved.is_err() {
            return Err(MemoryError::OutOfMemory.into());
        }
        self.current = Some(current);
        Ok(())
    }

    fn write_file(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        let remaining = self.remaining();
        let file = self.current.as_mut().ok_or(MemoryError::NoFile)?;
        // Only growth beyond what `begin` reserved is newly charged. Grow
        // geometrically for chunked uploads, but never past the budget, and
        // always reserve first: `extend_from_slice` must never allocate, or
        // it could exceed the budget and abort on a full heap.
        let required = file
            .data
            .len()
            .checked_add(bytes.len())
            .ok_or(MemoryError::OverBudget)?;
        let capacity = file.data.capacity();
        if required > capacity {
            let ceiling = capacity.saturating_add(remaining);
            if required > ceiling {
                return Err(MemoryError::OverBudget);
            }
            let target = capacity.saturating_mul(2).max(required).min(ceiling);
            // `try_reserve_exact` counts from the length, not the capacity.
            file.data
                .try_reserve_exact(target - file.data.len())
                .map_err(|_| MemoryError::OutOfMemory)?;
        }
        debug_assert!(file.data.capacity() >= required);
        file.data.extend_from_slice(bytes);
        Ok(())
    }

    fn finish_file(&mut self) -> Result<(), MemoryError> {
        let mut file = self.current.take().ok_or(MemoryError::NoFile)?;
        release_spare(&mut file.data);
        // Capacity was reserved in `begin`.
        self.files.push(file);
        Ok(())
    }

    fn abort_file(&mut self) {
        if let Some(mut file) = self.current.take()
            && !file.data.is_empty()
        {
            // Keep what arrived, not the reservation for what did not: an
            // interrupted upload costs its bytes.
            release_spare(&mut file.data);
            // Capacity was reserved in `begin`.
            self.partials.push(file);
        }
    }

    fn read_partial_file(&self, from: IpAddr, name: &str, offset: u64, out: &mut [u8]) -> usize {
        let Some(index) = self.partial(from, name) else {
            return 0;
        };
        let data = &self.partials[index].data;
        let start = usize::try_from(offset).map_or(data.len(), |offset| offset.min(data.len()));
        let len = out.len().min(data.len() - start);
        out[..len].copy_from_slice(&data[start..start + len]);
        len
    }

    fn partial_file_names(&self, from: IpAddr, each: &mut (dyn FnMut(&str) + Send)) {
        for file in self.partials.iter().filter(|file| file.from == from) {
            each(&file.name);
        }
    }
}

/// One record slot in a file table.
const RECORD: usize = core::mem::size_of::<ReceivedFile>();

/// The heap a file holds beyond its record: its name and buffer.
fn heap(file: &ReceivedFile) -> usize {
    file.name.capacity() + file.data.capacity()
}

/// Shrink a record table to its length. Fallible: when the smaller table
/// cannot be allocated, the larger one is kept (and stays charged).
fn release_spare_slots(table: &mut Vec<ReceivedFile>) {
    if table.capacity() == table.len() {
        return;
    }
    let mut exact = Vec::new();
    if exact.try_reserve_exact(table.len()).is_ok() {
        exact.append(table);
        *table = exact;
    }
}

/// Give back capacity beyond `data`'s length. Fallible: when the smaller
/// buffer cannot be allocated, the larger one is kept (and stays charged).
fn release_spare(data: &mut Vec<u8>) {
    if data.capacity() == data.len() {
        return;
    }
    let mut exact = Vec::new();
    if exact.try_reserve_exact(data.len()).is_ok() {
        exact.extend_from_slice(data);
        *data = exact;
    }
}

impl FileSink for MemorySink {
    type Error = MemoryError;

    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<MemoryError>> {
        self.begin_file(file)
    }

    fn write(&mut self, data: &[u8]) -> Result<(), MemoryError> {
        self.write_file(data)
    }

    fn finish(&mut self) -> Result<(), MemoryError> {
        self.finish_file()
    }

    fn abort(&mut self) {
        self.abort_file();
    }

    fn read_partial(
        &mut self,
        from: IpAddr,
        name: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, MemoryError> {
        Ok(self.read_partial_file(from, name, offset, out))
    }

    fn partial_names(
        &mut self,
        from: IpAddr,
        each: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), MemoryError> {
        self.partial_file_names(from, each);
        Ok(())
    }
}

impl AsyncFileSink for MemorySink {
    type Error = MemoryError;

    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), Refusal<MemoryError>> {
        self.begin_file(file)
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), MemoryError> {
        self.write_file(data)
    }

    async fn finish(&mut self) -> Result<(), MemoryError> {
        self.finish_file()
    }

    async fn abort(&mut self) {
        self.abort_file();
    }

    async fn read_partial(
        &mut self,
        from: IpAddr,
        name: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, MemoryError> {
        Ok(self.read_partial_file(from, name, offset, out))
    }

    async fn partial_names(
        &mut self,
        from: IpAddr,
        each: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), MemoryError> {
        self.partial_file_names(from, each);
        Ok(())
    }
}

//! A heap-backed [`FileSink`] for hosts, browsers and tests.

use alloc::{string::String, vec::Vec};
use core::net::IpAddr;

use super::{AsyncFileSink, FileSink, Incoming};

/// A completely received file.
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
    /// `write` or `finish` without a `begin`.
    NoFile,
}

impl core::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OverBudget => "received files exceed the memory budget",
            Self::OutOfMemory => "out of memory while receiving a file",
            Self::NoFile => "no file in progress",
        })
    }
}

impl core::error::Error for MemoryError {}

/// Keeps received files in memory, within a total byte budget.
///
/// Allocation is fallible: a full heap fails the transfer (the sender sees
/// `500`) instead of aborting the process.
#[derive(Debug)]
pub struct MemorySink {
    budget: usize,
    used: usize,
    current: Option<ReceivedFile>,
    files: Vec<ReceivedFile>,
}

impl MemorySink {
    /// Accept up to `budget` bytes of file data in total, across all files
    /// held at once. Taking files out returns their bytes to the budget.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            used: 0,
            current: None,
            files: Vec::new(),
        }
    }

    /// Finished files, oldest first.
    pub fn files(&self) -> &[ReceivedFile] {
        &self.files
    }

    /// Remove and return all finished files.
    pub fn take(&mut self) -> Vec<ReceivedFile> {
        self.used -= self.files.iter().map(|file| file.data.len()).sum::<usize>();
        core::mem::take(&mut self.files)
    }

    fn remaining(&self) -> usize {
        let pending = self.current.as_ref().map_or(0, |file| file.data.len());
        self.budget - self.used - pending
    }

    fn begin_file(&mut self, file: &Incoming<'_>) -> Result<(), MemoryError> {
        self.abort_file();
        let declared = match file.size {
            Some(size) => usize::try_from(size).map_err(|_| MemoryError::OverBudget)?,
            None => 0,
        };
        if declared > self.remaining() {
            return Err(MemoryError::OverBudget);
        }
        let mut name = String::new();
        name.try_reserve_exact(file.name.len())
            .map_err(|_| MemoryError::OutOfMemory)?;
        name.push_str(file.name);
        let mut data = Vec::new();
        data.try_reserve_exact(declared)
            .map_err(|_| MemoryError::OutOfMemory)?;
        self.files
            .try_reserve(1)
            .map_err(|_| MemoryError::OutOfMemory)?;
        self.current = Some(ReceivedFile {
            from: file.from,
            name,
            data,
        });
        Ok(())
    }

    fn write_file(&mut self, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.len() > self.remaining() {
            return Err(MemoryError::OverBudget);
        }
        let file = self.current.as_mut().ok_or(MemoryError::NoFile)?;
        file.data
            .try_reserve(bytes.len())
            .map_err(|_| MemoryError::OutOfMemory)?;
        file.data.extend_from_slice(bytes);
        Ok(())
    }

    fn finish_file(&mut self) -> Result<(), MemoryError> {
        let file = self.current.take().ok_or(MemoryError::NoFile)?;
        self.used += file.data.len();
        // Capacity was reserved in `begin`.
        self.files.push(file);
        Ok(())
    }

    fn abort_file(&mut self) {
        self.current = None;
    }
}

impl FileSink for MemorySink {
    type Error = MemoryError;

    fn begin(&mut self, file: &Incoming<'_>) -> Result<(), MemoryError> {
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
}

impl AsyncFileSink for MemorySink {
    type Error = MemoryError;

    async fn begin(&mut self, file: &Incoming<'_>) -> Result<(), MemoryError> {
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
}

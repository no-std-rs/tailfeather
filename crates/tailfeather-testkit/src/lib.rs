//! Offline, deterministic compatibility checks for [`tailfeather`].
//!
//! ```
//! let report = tailfeather_testkit::replay::check_all();
//! assert!(report.passed());
//! ```

pub mod replay;
pub mod report;
pub mod vectors;

pub use report::{Check, Report, Status};

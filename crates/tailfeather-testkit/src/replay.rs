//! Deterministic checks which need no network, privileges, or device.

use crate::report::{Check, Report, Status};
use crate::vectors;

pub fn check_all() -> Report {
    let checks = vectors::ALL
        .iter()
        .map(|vector| {
            let actual = vectors::sha256(vector.bytes);
            let status = if actual == vector.sha256 {
                Status::Pass
            } else {
                Status::Fail
            };
            Check {
                name: vector.name,
                status,
                detail: actual,
            }
        })
        .collect();
    Report {
        schema_version: 1,
        checks,
    }
}

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.status == Status::Pass)
    }
}

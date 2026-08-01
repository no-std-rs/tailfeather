//! Comparing a run against a committed expectation.
//!
//! # Why in both directions
//!
//! The obvious use is catching a regression: something that passed now fails.
//! That is the *less* important half here.
//!
//! This suite's dominant failure mode is silent degradation to
//! [`Status::Skip`](crate::Status::Skip). A skip is excluded from the score
//! entirely, so a lab that quietly stopped running, a harness that was not
//! rebuilt, or a vector file that went missing all produce a *smaller
//! denominator* and a report that still says "100% compatible". CI gating on
//! the percentage would go green. Gating on failures alone would go green too,
//! because a skip is not a failure.
//!
//! So a baseline records the expected status of every check by id, and any
//! difference is an error — including a check that improved. An improvement is
//! good news that must be committed deliberately, not absorbed silently, or the
//! baseline stops describing anything.
//!
//! # What is not compared
//!
//! Only the status kind. Detail strings carry addresses, ports, key material and
//! node ids that change every run; a baseline containing them could never match
//! twice.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::Report;

/// The expected status of every check.
pub struct Baseline {
    checks: BTreeMap<String, String>,
    /// Recorded for the error message: comparing a lab baseline against a
    /// hosted run produces a wall of differences whose real cause is that the
    /// wrong file was named.
    target: Option<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let document: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;

        let checks = document["checks"]
            .as_object()
            .ok_or_else(|| format!("{}: no \"checks\" object", path.display()))?
            .iter()
            .map(|(id, status)| {
                let status = status
                    .as_str()
                    .ok_or_else(|| format!("{}: {id} is not a string", path.display()))?;
                Ok((id.clone(), status.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;

        Ok(Self {
            checks,
            target: document["target"].as_str().map(str::to_string),
        })
    }

    /// Write a baseline from a run. Used by `--write-expect`.
    pub fn write(report: &Report, path: &Path) -> Result<(), String> {
        let document = serde_json::json!({
            "_comment": "Expected status of every check, compared by `conformance \
                         --expect`. Any difference in either direction is an error: a \
                         check that silently degrades to \"skip\" leaves the score at \
                         100% because skips are excluded from the denominator, which \
                         is this suite's dominant failure mode. Regenerate \
                         deliberately with `--write-expect`, and read the diff.",
            "target": report.target.to_string(),
            "checks": report
                .outcomes
                .iter()
                .map(|o| (o.id.to_string(), serde_json::Value::from(o.status.kind())))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        });

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(path, format!("{document:#}\n"))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Compare a run against this baseline.
    pub fn compare(&self, report: &Report) -> Comparison {
        let mut comparison = Comparison {
            baseline_target: self.target.clone(),
            run_target: report.target.to_string(),
            ..Comparison::default()
        };

        let actual: BTreeMap<&str, &str> = report
            .outcomes
            .iter()
            .map(|o| (o.id, o.status.kind()))
            .collect();

        for (id, expected) in &self.checks {
            match actual.get(id.as_str()) {
                None => comparison.missing.push(id.clone()),
                Some(got) if got == expected => {}
                Some(got) => comparison.changed.push(Change {
                    id: id.clone(),
                    from: expected.clone(),
                    to: (*got).to_string(),
                    detail: report
                        .outcomes
                        .iter()
                        .find(|o| o.id == id)
                        .map(|o| o.status.detail().to_string())
                        .unwrap_or_default(),
                }),
            }
        }
        for id in actual.keys() {
            if !self.checks.contains_key(*id) {
                comparison.unexpected.push((*id).to_string());
            }
        }
        comparison
    }
}

/// One check whose status moved.
pub struct Change {
    pub id: String,
    pub from: String,
    pub to: String,
    pub detail: String,
}

impl Change {
    /// Whether this is a move away from a compatible status.
    ///
    /// `skip` counts as a regression from anything else even though it is not a
    /// failure — losing a measurement is the thing this file exists to catch.
    pub fn is_regression(&self) -> bool {
        let rank = |kind: &str| match kind {
            "pass" | "external" => 3,
            "todo" => 2,
            "fail" => 1,
            // Lowest: a skip is not a result at all.
            _ => 0,
        };
        rank(&self.to) < rank(&self.from)
    }
}

#[derive(Default)]
pub struct Comparison {
    pub changed: Vec<Change>,
    /// In the baseline, absent from the run — a check was removed or renamed.
    pub missing: Vec<String>,
    /// In the run, absent from the baseline — a check was added.
    pub unexpected: Vec<String>,
    pub baseline_target: Option<String>,
    pub run_target: String,
}

impl Comparison {
    pub fn agrees(&self) -> bool {
        self.changed.is_empty() && self.missing.is_empty() && self.unexpected.is_empty()
    }

    /// Whether the baseline was recorded against a different control plane.
    ///
    /// Reported first, because it explains every other difference at once.
    pub fn target_mismatch(&self) -> bool {
        self.baseline_target
            .as_ref()
            .is_some_and(|t| *t != self.run_target)
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.agrees() {
            return writeln!(f, "matches the baseline: every check has its expected status");
        }

        if self.target_mismatch() {
            writeln!(
                f,
                "the baseline was recorded against {}, but this run measured {} \
                 — the differences below are probably just the wrong baseline file",
                self.baseline_target.as_deref().unwrap_or("?"),
                self.run_target
            )?;
            writeln!(f)?;
        }

        let (regressions, improvements): (Vec<&Change>, Vec<&Change>) =
            self.changed.iter().partition(|c| c.is_regression());

        if !regressions.is_empty() {
            writeln!(f, "{} regression(s):", regressions.len())?;
            for change in regressions {
                writeln!(f, "  {} {} -> {}", change.id, change.from, change.to)?;
                if !change.detail.is_empty() {
                    writeln!(f, "      {}", change.detail)?;
                }
            }
            writeln!(f)?;
        }

        if !improvements.is_empty() {
            writeln!(
                f,
                "{} improvement(s) — good, but the baseline must be updated to \
                 record them:",
                improvements.len()
            )?;
            for change in improvements {
                writeln!(f, "  {} {} -> {}", change.id, change.from, change.to)?;
            }
            writeln!(f)?;
        }

        if !self.missing.is_empty() {
            writeln!(
                f,
                "{} check(s) in the baseline did not run — removed or renamed:",
                self.missing.len()
            )?;
            for id in &self.missing {
                writeln!(f, "  {id}")?;
            }
            writeln!(f)?;
        }

        if !self.unexpected.is_empty() {
            writeln!(
                f,
                "{} new check(s) absent from the baseline:",
                self.unexpected.len()
            )?;
            for id in &self.unexpected {
                writeln!(f, "  {id}")?;
            }
            writeln!(f)?;
        }

        writeln!(
            f,
            "Regenerate with `cargo run -p ts-conformance -- --write-expect <path>` \
             once the change is understood."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Area, Outcome, Status, Target};

    fn report(statuses: &[(&'static str, Status)]) -> Report {
        Report {
            target: Target::HeadscaleLab,
            outcomes: statuses
                .iter()
                .map(|(id, status)| Outcome {
                    id,
                    area: Area::Control,
                    description: "",
                    status: status.clone(),
                })
                .collect(),
            headscale_version: None,
            tailscale_version: None,
            doctor: None,
        }
    }

    fn baseline(pairs: &[(&str, &str)]) -> Baseline {
        Baseline {
            checks: pairs
                .iter()
                .map(|(id, status)| (id.to_string(), status.to_string()))
                .collect(),
            target: Some(Target::HeadscaleLab.to_string()),
        }
    }

    #[test]
    fn an_unchanged_run_agrees() {
        let comparison = baseline(&[("a", "pass"), ("b", "todo")])
            .compare(&report(&[
                ("a", Status::Pass(String::new())),
                ("b", Status::Todo(String::new())),
            ]));
        assert!(comparison.agrees());
    }

    /// The case the whole file exists for.
    #[test]
    fn a_pass_degrading_to_a_skip_is_a_regression() {
        let run = report(&[("a", Status::Skip("the lab is not running".into()))]);
        // The report itself looks perfect: nothing failed, and the score is
        // vacuously 100% because skips leave the denominator.
        assert_eq!(run.failures().count(), 0);
        assert_eq!(run.counted(), 0);

        let comparison = baseline(&[("a", "pass")]).compare(&run);
        assert!(!comparison.agrees());
        assert_eq!(comparison.changed.len(), 1);
        assert!(comparison.changed[0].is_regression());
        assert!(format!("{comparison}").contains("1 regression"));
    }

    #[test]
    fn a_failure_is_a_regression_and_carries_its_detail() {
        let comparison = baseline(&[("a", "pass")])
            .compare(&report(&[("a", Status::Fail("the tag did not verify".into()))]));
        assert!(comparison.changed[0].is_regression());
        assert!(format!("{comparison}").contains("the tag did not verify"));
    }

    /// An improvement is still a difference: the baseline has to record it, or
    /// it stops describing what the suite does.
    #[test]
    fn an_improvement_is_reported_but_not_as_a_regression() {
        let comparison = baseline(&[("a", "todo")])
            .compare(&report(&[("a", Status::Pass(String::new()))]));
        assert!(!comparison.agrees());
        assert!(!comparison.changed[0].is_regression());
        let text = format!("{comparison}");
        assert!(text.contains("1 improvement"));
        assert!(!text.contains("regression"));
    }

    #[test]
    fn a_skip_becoming_anything_at_all_is_an_improvement() {
        for status in [
            Status::Fail(String::new()),
            Status::Todo(String::new()),
            Status::Pass(String::new()),
        ] {
            let kind = status.kind();
            let comparison = baseline(&[("a", "skip")]).compare(&report(&[("a", status)]));
            assert!(
                !comparison.changed[0].is_regression(),
                "skip -> {kind} was called a regression"
            );
        }
    }

    #[test]
    fn added_and_removed_checks_are_both_errors() {
        let comparison = baseline(&[("a", "pass"), ("gone", "pass")])
            .compare(&report(&[
                ("a", Status::Pass(String::new())),
                ("brand-new", Status::Pass(String::new())),
            ]));
        assert!(!comparison.agrees());
        assert_eq!(comparison.missing, vec!["gone".to_string()]);
        assert_eq!(comparison.unexpected, vec!["brand-new".to_string()]);
        let text = format!("{comparison}");
        assert!(text.contains("removed or renamed"));
        assert!(text.contains("new check"));
    }

    #[test]
    fn a_baseline_for_the_wrong_target_says_so_first() {
        let mut wrong = baseline(&[("a", "pass")]);
        wrong.target = Some(Target::TailscaleSaas.to_string());
        let comparison = wrong.compare(&report(&[("a", Status::Skip(String::new()))]));
        assert!(comparison.target_mismatch());
        assert!(format!("{comparison}").contains("probably just the wrong baseline"));
    }
}

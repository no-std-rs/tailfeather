//! What this machine can measure, said once.
//!
//! # The problem with per-check skips
//!
//! Nineteen of thirty-four checks can skip, and each used to word its own
//! reason: "no control server configured; start one with tests/lab/lab.sh up",
//! "the no_std harness is not built", "no reference client; start one with
//! tests/lab/lab.sh reference". Individually each is clear. Nineteen of them in
//! one report is not: they read as nineteen separate problems, they bury the
//! checks that did run, and the single action that would fix most of them
//! appears nineteen times in nineteen phrasings.
//!
//! So `tests/lab/lab.sh doctor` writes `.lab/doctor.json`, this module reads it,
//! and [`Report`](crate::Report) prints one banner naming what is missing and
//! which check ids each absence disables.
//!
//! The per-check skip reasons stay. They are still what a reader needs when only
//! one check skipped, and the banner is a summary rather than a replacement.
//!
//! # Absence is not failure
//!
//! No `doctor.json` means the command was never run, which is the normal state
//! for someone who just cloned the repository. That produces no banner rather
//! than an error.

use std::fmt;
use std::path::Path;

/// What the environment offers, as `lab.sh doctor` found it.
#[derive(Debug, Default, Clone)]
pub struct Doctor {
    pub headscale: bool,
    pub headscale_version: Option<String>,
    pub headscale_image: Option<String>,
    /// Why Headscale is unavailable, in `lab.sh`'s words.
    pub headscale_reason: Option<String>,
    pub tailscaled_installed: bool,
    pub reference_client: bool,
    pub harness_built: bool,
    pub passwordless_sudo: bool,
}

/// One missing capability, and what it costs.
pub struct Gap {
    /// What to do about it.
    pub remedy: &'static str,
    pub what: &'static str,
    /// The check ids this absence disables.
    pub disables: &'static [&'static str],
}

impl Doctor {
    /// Read `.lab/doctor.json`, if `lab.sh doctor` has been run.
    pub fn load(repo_root: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(repo_root.join(".lab/doctor.json")).ok()?;
        let document: serde_json::Value = serde_json::from_str(&text).ok()?;
        let flag = |key: &str| document[key].as_bool().unwrap_or(false);
        let text_of = |key: &str| {
            document[key]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Some(Self {
            headscale: flag("headscale"),
            headscale_version: text_of("headscale_version"),
            headscale_image: text_of("headscale_image"),
            headscale_reason: text_of("headscale_reason"),
            tailscaled_installed: flag("tailscaled_installed"),
            reference_client: flag("reference_client"),
            harness_built: flag("harness_built"),
            passwordless_sudo: flag("passwordless_sudo"),
        })
    }

    /// Everything missing, with the checks it disables.
    ///
    /// The id lists are maintained by hand and asserted against the real check
    /// table by `tests/matrix.rs`, so a renamed check cannot leave this
    /// pointing at something that no longer exists.
    pub fn gaps(&self) -> Vec<Gap> {
        let mut gaps = Vec::new();

        if !self.headscale {
            gaps.push(Gap {
                what: "no control server",
                remedy: "tests/lab/lab.sh up",
                disables: &[
                    "control.key.fetch",
                    "control.key.capver",
                    "control.capver.minimum",
                    "control.noise.handshake",
                    "control.controlbase.framing",
                    "control.register",
                    "control.hostinfo",
                    "control.reauth",
                    "keys.machine",
                    "keys.node",
                    "keys.disco",
                    "keys.persistence",
                    "transport.http2",
                    "netmap.fields",
                    "netmap.delta",
                    "netmap.streaming",
                    "netmap.compression",
                    "netmap.to_peers",
                    "derp.relay",
                    "disco.pong",
                    "disco.ping",
                    "disco.endpoints",
                    "exit.advertise",
                ],
            });
        }
        if !self.harness_built {
            gaps.push(Gap {
                what: "the no_std harness is not built",
                remedy: "cd harness && cargo build --release",
                // Every live check drives the harness; naming them all would
                // repeat the list above, so this names the consequence.
                disables: &[],
            });
        }
        if !self.tailscaled_installed {
            gaps.push(Gap {
                what: "tailscaled is not installed",
                remedy: "install the tailscale package",
                disables: &["disco.pong", "disco.ping", "derp.relay"],
            });
        } else if !self.reference_client {
            gaps.push(Gap {
                what: "no reference client is running",
                remedy: "tests/lab/lab.sh reference",
                disables: &["disco.pong", "disco.ping", "derp.relay"],
            });
        }
        if !self.passwordless_sudo {
            gaps.push(Gap {
                what: "no passwordless sudo",
                remedy: "configure sudo, or run the interop scripts by hand",
                disables: &["exit.forward.udp", "exit.forward.tcp", "disco.pong"],
            });
        }
        gaps
    }

    /// Whether everything the suite can use is present.
    pub fn complete(&self) -> bool {
        self.gaps().is_empty()
    }
}

/// The banner, printed once above the matrix.
pub struct Banner<'a>(pub &'a Doctor);

impl fmt::Display for Banner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let gaps = self.0.gaps();
        if gaps.is_empty() {
            return Ok(());
        }

        writeln!(f, "This environment cannot measure everything:")?;
        for gap in &gaps {
            write!(f, "  {} — {}", gap.what, gap.remedy)?;
            if let Some(reason) = &self.0.headscale_reason
                && gap.what == "no control server"
            {
                write!(f, " ({reason})")?;
            }
            writeln!(f)?;
            if !gap.disables.is_empty() {
                writeln!(
                    f,
                    "      disables {} check(s): {}",
                    gap.disables.len(),
                    gap.disables.join(", ")
                )?;
            }
        }
        writeln!(
            f,
            "Those checks report SKIP and are excluded from the score, so the \
             percentage below\nis over what could actually be measured. \
             `--expect` compares against a baseline\nand treats a lost \
             measurement as a regression."
        )?;
        writeln!(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn everything() -> Doctor {
        Doctor {
            headscale: true,
            headscale_version: Some("v0.29.3".into()),
            headscale_image: None,
            headscale_reason: None,
            tailscaled_installed: true,
            reference_client: true,
            harness_built: true,
            passwordless_sudo: true,
        }
    }

    #[test]
    fn a_complete_environment_prints_nothing() {
        let doctor = everything();
        assert!(doctor.complete());
        assert_eq!(Banner(&doctor).to_string(), "");
    }

    #[test]
    fn a_missing_control_server_names_the_checks_it_costs() {
        let doctor = Doctor {
            headscale: false,
            headscale_reason: Some("no headscale-lab container; run 'lab.sh up'".into()),
            ..everything()
        };
        let text = Banner(&doctor).to_string();
        assert!(text.contains("no control server — tests/lab/lab.sh up"));
        assert!(text.contains("no headscale-lab container"));
        assert!(text.contains("control.register"));
        // One banner, not one line per check.
        assert!(text.lines().count() < 12, "the banner grew into a list:\n{text}");
    }

    /// tailscaled being absent and the reference simply not running are
    /// different problems with different remedies, and only one applies.
    #[test]
    fn an_uninstalled_tailscaled_and_a_stopped_reference_do_not_both_report() {
        let uninstalled = Doctor {
            tailscaled_installed: false,
            reference_client: false,
            ..everything()
        };
        let text = Banner(&uninstalled).to_string();
        assert!(text.contains("tailscaled is not installed"));
        assert!(!text.contains("no reference client"));

        let stopped = Doctor {
            reference_client: false,
            ..everything()
        };
        let text = Banner(&stopped).to_string();
        assert!(text.contains("no reference client"));
        assert!(!text.contains("not installed"));
    }

    #[test]
    fn every_gap_offers_something_to_do_about_it() {
        let nothing = Doctor::default();
        let gaps = nothing.gaps();
        assert!(gaps.len() >= 3);
        for gap in gaps {
            assert!(!gap.what.is_empty());
            assert!(!gap.remedy.is_empty(), "{} has no remedy", gap.what);
        }
    }
}

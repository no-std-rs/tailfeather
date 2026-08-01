//! A compatibility suite measuring this project against real Tailscale and
//! Headscale.
//!
//! # Why it is shaped like this
//!
//! "100% compatible" is not something a test suite can prove. What it *can* do
//! is make the gap explicit, measurable, and impossible to lose track of. So
//! this suite is not a set of tests that pass or fail; it is an enumeration of
//! every behaviour a Tailscale-compatible node must exhibit, each carrying a
//! status. Behaviour that is not implemented yet is declared as
//! [`Status::Todo`] rather than omitted, so the score starts low and honestly.
//!
//! The second rule follows from experience on this project. The one protocol
//! bug that cost real time — WireGuard's Noise construction string — would have
//! passed any test written against our own understanding, because our
//! understanding was the thing that was wrong. It was caught by handing a
//! packet to the Linux kernel and watching it disagree. So every check here is
//! either run against a live reference implementation, or against bytes
//! captured from one. A check that only consults our own code is worth very
//! little, and is marked as such.
//!
//! # Statuses
//!
//! [`Status::Pass`] means this run verified the behaviour. [`Status::External`]
//! means a reference-backed artifact outside this process verified it — the
//! root-requiring interop scripts — and names it. Those two are the only ones
//! that count as compatible. [`Status::Todo`] is unbuilt work,
//! [`Status::Fail`] is a real defect, and [`Status::Skip`] means the check
//! could not run, which is never counted as success.

pub mod baseline;
pub mod checks;
pub mod derp;
pub mod disco;
pub mod exit;
pub mod harness;
pub mod headscale;
pub mod http;
pub mod multipeer;
pub mod netmap;
pub mod pcap;
pub mod register;
pub mod runscope;
pub mod tls;
pub mod ts2021;

use std::fmt;
use std::path::PathBuf;

/// Which control-plane implementation a run is measured against.
///
/// Compatibility with one does not imply the other: Headscale is reachable over
/// plain HTTP on a LAN, while Tailscale's coordination server requires TLS and
/// DERP. Behaviour that only ever gets exercised against the lab is not
/// evidence about the hosted service, so the target is recorded in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A local Headscale started by `tests/lab/lab.sh`.
    HeadscaleLab,
    /// The hosted coordination server at `controlplane.tailscale.com`.
    TailscaleSaas,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeadscaleLab => "Headscale (local lab)",
            Self::TailscaleSaas => "Tailscale (hosted)",
        })
    }
}

/// Which milestone a behaviour belongs to, so the report reads as a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Area {
    DataPlane,
    Keys,
    Control,
    Netmap,
    Derp,
    Disco,
    ExitNode,
    Transport,
}

impl fmt::Display for Area {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DataPlane => "data plane (WireGuard)",
            Self::Keys => "keys",
            Self::Control => "control plane (ts2021)",
            Self::Netmap => "netmap",
            Self::Derp => "DERP",
            Self::Disco => "disco",
            Self::ExitNode => "exit node",
            Self::Transport => "transport (TLS/HTTP2)",
        })
    }
}

#[derive(Debug, Clone)]
pub enum Status {
    /// Verified during this run against a reference implementation or a
    /// capture of one.
    Pass(String),
    /// Verified by a named artifact outside this process.
    External(String),
    /// A genuine incompatibility.
    Fail(String),
    /// Not implemented yet. The string says what is missing.
    Todo(String),
    /// Could not be evaluated. Never counted as compatible.
    Skip(String),
}

impl Status {
    pub fn is_compatible(&self) -> bool {
        matches!(self, Self::Pass(_) | Self::External(_))
    }

    pub fn is_counted(&self) -> bool {
        !matches!(self, Self::Skip(_))
    }

    /// A stable, machine-readable name for this status.
    ///
    /// Distinct from [`Status::marker`], which is for humans and may be
    /// reworded. This one appears in `--json` output and in the committed
    /// baselines under `tests/expectations/`, so changing a string here
    /// invalidates every baseline file.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Pass(_) => "pass",
            Self::External(_) => "external",
            Self::Fail(_) => "fail",
            Self::Todo(_) => "todo",
            Self::Skip(_) => "skip",
        }
    }

    fn marker(&self) -> &'static str {
        match self {
            Self::Pass(_) => "PASS",
            Self::External(_) => "PASS*",
            Self::Fail(_) => "FAIL",
            Self::Todo(_) => "TODO",
            Self::Skip(_) => "SKIP",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Pass(d)
            | Self::External(d)
            | Self::Fail(d)
            | Self::Todo(d)
            | Self::Skip(d) => d,
        }
    }
}

/// One required behaviour.
pub struct Check {
    /// A stable identifier, so a behaviour can be referred to in commits and
    /// issues even as its description is reworded.
    pub id: &'static str,
    pub area: Area,
    pub description: &'static str,
    pub run: fn(&Env) -> Status,
}

/// What the checks are run against.
pub struct Env {
    pub target: Target,
    /// Base URL of the control server, if one is reachable.
    pub control_url: Option<String>,
    pub preauth_key: Option<String>,
    /// Committed ground truth captured from the reference implementations.
    pub vectors: PathBuf,
    pub headscale_version: Option<String>,
    pub tailscale_version: Option<String>,
    /// The built `no_std` harness, if there is one. Checks that need it report
    /// [`Status::Skip`] when it is absent rather than failing: an unbuilt binary
    /// is a missing measurement, not an incompatibility.
    pub harness: Option<harness::Harness>,
    /// Where the lab's control server listens, split for the harness, which
    /// parses dotted quads rather than URLs.
    pub control_address: Option<(String, u16)>,
    /// Tags the nodes this run registers and deletes them again when the run
    /// ends, including on the failure path.
    ///
    /// Without it the lab accumulates a node per run until the netmap exceeds
    /// `ts_netmap::MAX_PEERS` and five checks start failing for reasons
    /// unrelated to the code. See [`runscope`].
    pub scope: runscope::RunScope,
}

impl Env {
    /// Build the environment from the lab's state file, falling back to an
    /// offline environment in which live checks skip and vector-backed checks
    /// still run.
    pub fn discover(repo_root: &std::path::Path) -> Self {
        let mut env = Self {
            target: Target::HeadscaleLab,
            control_url: None,
            preauth_key: None,
            vectors: repo_root.join("tests/vectors"),
            headscale_version: None,
            tailscale_version: None,
            harness: harness::Harness::discover(repo_root),
            control_address: None,
            // Enabled below, once we know whether there is a lab to clean up.
            scope: runscope::RunScope::new(false),
        };

        if let Ok(text) = std::fs::read_to_string(repo_root.join(".lab/lab.env")) {
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    match key {
                        "HEADSCALE_URL" => env.control_url = Some(value.to_string()),
                        "HEADSCALE_PREAUTH_KEY" => env.preauth_key = Some(value.to_string()),
                        "HEADSCALE_VERSION" => env.headscale_version = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        // Pointing the same checks at the hosted service is opt-in: it needs
        // credentials and internet access, so it can never be the default.
        if let Ok(url) = std::env::var("TS_CONTROL_URL") {
            env.target = Target::TailscaleSaas;
            env.control_url = Some(url);
            env.preauth_key = std::env::var("TS_AUTHKEY").ok();
        }

        // A control server that is configured but not answering means the lab
        // is simply not running, which must skip rather than fail. Reserving
        // failure for genuine incompatibilities is what makes the suite safe to
        // gate anything on. Probing once here beats every check discovering it
        // separately and reporting a connection error as a protocol defect.
        if let Some(url) = &env.control_url
            && env.target == Target::HeadscaleLab
            && http::get(&format!("{url}/health")).is_err()
        {
            env.control_url = None;
        }

        env.control_address = env.control_url.as_deref().and_then(split_address);

        // Cleanup is only meaningful against the local lab: it deletes nodes
        // through `headscale` in the lab container, which the hosted service
        // has no equivalent of. A hosted run must not silently believe it is
        // tidying up after itself.
        env.scope = runscope::RunScope::new(
            env.control_url.is_some() && env.target == Target::HeadscaleLab,
        );

        if let Ok(text) = std::fs::read_to_string(env.vectors.join("versions.json"))
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
        {
            env.tailscale_version = json["tailscale_client"].as_str().map(str::to_string);
            if env.headscale_version.is_none() {
                env.headscale_version = json["headscale"].as_str().map(str::to_string);
            }
        }

        env
    }

    /// Load a committed vector by file name.
    pub fn vector(&self, name: &str) -> Result<serde_json::Value, String> {
        let path = self.vectors.join(name);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e} — run tests/lab/capture.sh", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Split `http://host:port` into the parts the harness takes as arguments.
fn split_address(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

pub struct Outcome {
    pub id: &'static str,
    pub area: Area,
    pub description: &'static str,
    pub status: Status,
}

pub struct Report {
    pub target: Target,
    pub outcomes: Vec<Outcome>,
    pub headscale_version: Option<String>,
    pub tailscale_version: Option<String>,
}

impl Report {
    pub fn run(env: &Env) -> Self {
        let outcomes = checks::all()
            .iter()
            .map(|check| Outcome {
                id: check.id,
                area: check.area,
                description: check.description,
                status: (check.run)(env),
            })
            .collect();

        Self {
            target: env.target,
            outcomes,
            headscale_version: env.headscale_version.clone(),
            tailscale_version: env.tailscale_version.clone(),
        }
    }

    pub fn compatible(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.status.is_compatible())
            .count()
    }

    pub fn counted(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.status.is_counted())
            .count()
    }

    pub fn failures(&self) -> impl Iterator<Item = &Outcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.status, Status::Fail(_)))
    }

    /// The report as JSON, for `--json` and for comparison against a baseline.
    ///
    /// Only the status *kind* is recorded per check, never the detail string.
    /// Details name addresses, ports, key material and node ids that differ on
    /// every run, so a baseline that included them could never match twice.
    pub fn to_json(&self) -> serde_json::Value {
        let checks: serde_json::Map<String, serde_json::Value> = self
            .outcomes
            .iter()
            .map(|o| (o.id.to_string(), serde_json::Value::from(o.status.kind())))
            .collect();

        serde_json::json!({
            "target": self.target.to_string(),
            "headscale_version": self.headscale_version,
            "tailscale_version": self.tailscale_version,
            "compatible": self.compatible(),
            "counted": self.counted(),
            "total": self.outcomes.len(),
            "checks": checks,
            "details": self
                .outcomes
                .iter()
                .map(|o| {
                    (
                        o.id.to_string(),
                        serde_json::Value::from(o.status.detail()),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        })
    }

    pub fn percentage(&self) -> f64 {
        let counted = self.counted();
        if counted == 0 {
            return 0.0;
        }
        100.0 * self.compatible() as f64 / counted as f64
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Tailscale/Headscale compatibility")
        ?;
        writeln!(f, "  measured against: {}", self.target)?;
        if let Some(v) = &self.headscale_version {
            writeln!(f, "  headscale:        {v}")?;
        }
        if let Some(v) = &self.tailscale_version {
            writeln!(f, "  tailscale client: {v}")?;
        }
        writeln!(f)?;

        let mut areas: Vec<Area> = self.outcomes.iter().map(|o| o.area).collect();
        areas.sort();
        areas.dedup();

        for area in areas {
            let in_area: Vec<&Outcome> =
                self.outcomes.iter().filter(|o| o.area == area).collect();
            let done = in_area.iter().filter(|o| o.status.is_compatible()).count();
            writeln!(f, "{} — {}/{}", area, done, in_area.len())?;
            for outcome in in_area {
                writeln!(
                    f,
                    "  {:<5} {:<34} {}",
                    outcome.status.marker(),
                    outcome.id,
                    outcome.description
                )?;
                let detail = outcome.status.detail();
                if !detail.is_empty() {
                    writeln!(f, "        {detail}")?;
                }
            }
            writeln!(f)?;
        }

        writeln!(
            f,
            "{}/{} behaviours verified — {:.0}% compatible",
            self.compatible(),
            self.counted(),
            self.percentage()
        )?;
        writeln!(f, "PASS* means verified by a named artifact outside this process.")?;
        let skipped = self.outcomes.len() - self.counted();
        if skipped > 0 {
            writeln!(f, "{skipped} check(s) skipped and excluded from the score.")?;
        }
        Ok(())
    }
}

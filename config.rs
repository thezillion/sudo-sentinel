//! Configuration file structures.
//!
//! Example `/etc/sudo-sentinel/config.toml`:
//!
//! ```toml
//! [daemon]
//! log_level = "info"          # RUST_LOG override
//!
//! # Block all sudo by users with real UIDs in the contractor range.
//! [[rules]]
//! name = "block-contractors"
//! [rules.match]
//! uid_range = [2000, 2999]
//! [rules.action]
//! signal        = "SIGKILL"
//! kill_children = true
//! log           = true
//!
//! # Block editing sensitive files, regardless of who's asking.
//! [[rules]]
//! name = "block-editing-sudoers"
//! [rules.match]
//! args_contain = ["/etc/sudoers", "/etc/sudoers.d"]
//! [rules.action]
//! signal = "SIGKILL"
//!
//! # Deadline rule: track and kill after 5m (optional [rules.match] command).
//! [[rules]]
//! name = "limit-sh-5m"
//! deadline = "5m"
//! [rules.match]
//! uid_range = [1000, 1999]
//! command = "sh"
//! [rules.action]
//! signal = "SIGKILL"
//! ```

use anyhow::Result;
use serde::Deserialize;

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// All rules (immediate and deadline-based). Rules with `deadline` set are
    /// tracked and killed after the duration; others fire immediately on match.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DaemonConfig {
    /// Overrides the `RUST_LOG` environment variable when set.
    pub log_level: Option<String>,
    /// Path to write the PID file.
    pub pid_file: Option<String>,
}

// ── Rule ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Rule {
    /// Human-readable name shown in log output.
    pub name: String,

    /// All specified conditions must match (logical AND).
    #[serde(rename = "match", default)]
    pub match_: MatchCondition,

    #[serde(default)]
    pub action: Action,

    /// If `true` (default), no further rules are evaluated once this one fires.
    /// Only applies to immediate (non-deadline) rules.
    #[serde(default = "default_true")]
    pub stop_on_match: bool,

    /// If set, this rule is deadline-based: matching invocations are tracked and
    /// killed only after this duration (e.g. `"30s"`, `"5m"`, `"1h"`). No immediate kill.
    pub deadline: Option<String>,
}

// ── Match conditions ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct MatchCondition {
    // ── Identity filters ──────────────────────────────────────────────────────

    /// Match if the real UID is in this list.
    pub uids: Option<Vec<u32>>,

    /// Skip (do NOT kill) if the real UID is in this list.
    /// Applied after `uids` / `uid_range`.
    pub exclude_uids: Option<Vec<u32>>,

    /// Match if real UID is in `[low, high]` (inclusive).
    pub uid_range: Option<[u32; 2]>,

    /// Match on the *login* UID (set at PAM/login time; survives su/sudo chains).
    /// `4294967295` (0xFFFFFFFF) means the process has no login session.
    pub auids: Option<Vec<u32>>,

    // ── Argument filters ──────────────────────────────────────────────────────

    /// Kill if **any** of these strings appear anywhere in the joined argument list.
    /// Example: `args_contain = ["vim", "nano"]` blocks `sudo vim` or `sudo nano`.
    pub args_contain: Option<Vec<String>>,

    /// Do NOT kill if **any** of these strings appear in the joined argument list.
    /// Useful for allow-listing specific invocations within a broader block.
    pub args_not_contain: Option<Vec<String>>,

    // ── Terminal / session filters ────────────────────────────────────────────

    /// Match a specific TTY string (e.g. `"pts/0"`, `"?"` for no TTY).
    pub tty: Option<String>,

    /// If `true`, only match when there is **no** controlling TTY.
    /// Useful for blocking non-interactive / scripted sudo invocations.
    pub no_tty: Option<bool>,

    /// Match the executed command (first arg after "sudo"). If set, the event's
    /// command must equal or end with this string (e.g. `"sh"` matches `sh`, `/bin/sh`).
    /// Used as an extra filter for immediate rules; required for deadline semantics.
    pub command: Option<String>,

    // ── Catch-all ─────────────────────────────────────────────────────────────

    /// If `true`, match every sudo invocation regardless of other conditions.
    #[serde(default)]
    pub match_all: bool,
}

// ── Action ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Action {
    /// Signal to deliver: `"SIGKILL"` (default) or `"SIGTERM"`.
    pub signal: Option<String>,

    /// Also send the signal to the entire process group (default: `true`).
    /// This catches commands that sudo has already `exec`'d.
    #[serde(default = "default_true")]
    pub kill_children: bool,

    /// Emit a log line when this rule fires (default: `true`).
    #[serde(default = "default_true")]
    pub log: bool,
}

impl Default for Action {
    fn default() -> Self {
        Self {
            signal: None,
            kill_children: true,
            log: true,
        }
    }
}

/// Parse a deadline string ("30s", "5m", "1h") into a duration in seconds.
pub fn parse_deadline(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("deadline string is empty");
    }
    let (num_str, unit) = if s.ends_with('s') && !s.ends_with("ms") {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else {
        anyhow::bail!("deadline must end with s, m, or h (e.g. 30s, 5m, 1h)");
    };
    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid number in deadline '{s}'"))?;
    let secs = match unit {
        "s" => num,
        "m" => num.checked_mul(60).ok_or_else(|| anyhow::anyhow!("deadline overflow"))?,
        "h" => num
            .checked_mul(3600)
            .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?,
        _ => unreachable!(),
    };
    Ok(std::time::Duration::from_secs(secs))
}

// ── Loader ────────────────────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let config: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse error in {path}: {e}"))?;
        Ok(config)
    }
}

fn default_true() -> bool {
    true
}

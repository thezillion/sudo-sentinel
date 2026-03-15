//! Rule matching, deadline tracking, and process termination.
//!
//! `RuleMatcher::process()` evaluates every rule against a `SudoEvent` and,
//! on the first match (or all matches if `stop_on_match = false`), sends the
//! configured signal to the sudo process and optionally to its process group
//! and `/proc`-discovered children.
//!
//! Deadline rules: when a sudo invocation matches a UID–command pair with a
//! deadline, the process is tracked and killed only after the deadline has passed.

use crate::config::{parse_deadline, Action, DeadlineRule, MatchCondition, Rule};
use crate::event::SudoEvent;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs;
use std::time::Instant;
use tracing::{debug, error, info, warn};

struct TrackedDeadline {
    deadline: Instant,
    signal: String,
    kill_children: bool,
    rule_name: String,
    /// Process start time from /proc/pid/stat (field 22) to avoid killing a recycled PID.
    starttime: Option<u64>,
}

pub struct RuleMatcher {
    rules: Vec<Rule>,
    deadline_rules: Vec<DeadlineRule>,
    /// PIDs currently under a deadline; killed when Instant::now() >= deadline.
    tracked: HashMap<u32, TrackedDeadline>,
}

impl RuleMatcher {
    pub fn new(rules: Vec<Rule>, deadline_rules: Vec<DeadlineRule>) -> Self {
        Self {
            rules,
            deadline_rules,
            tracked: HashMap::new(),
        }
    }

    /// Evaluate all rules against `event`; apply action on the first match
    /// (or on every match when `stop_on_match = false`).
    /// Then, if any deadline rule matches (UID–command pair), track the process
    /// and kill it only after its deadline.
    pub fn process(&mut self, event: &SudoEvent) {
        for rule in &self.rules {
            if matches_rule(&rule.match_, event) {
                if rule.action.log {
                    info!(
                        rule  = %rule.name,
                        pid   = event.pid,
                        uid   = event.uid,
                        auid  = event.auid,
                        tty   = %event.tty,
                        args  = ?event.args,
                        "Rule matched — sending {}",
                        signal_name(&rule.action),
                    );
                }
                apply_action(&rule.action, event);
                if rule.stop_on_match {
                    return;
                }
            }
        }

        // Track matching UID–command pairs with deadlines (kill only after deadline).
        for rule in &self.deadline_rules {
            if matches_deadline_rule(rule, event) {
                let duration = match parse_deadline(&rule.deadline) {
                    Ok(d) if !d.is_zero() => d,
                    Ok(_) => continue,
                    Err(e) => {
                        warn!("Invalid deadline '{}' in rule '{}': {}", rule.deadline, rule.name, e);
                        continue;
                    }
                };
                let deadline = Instant::now() + duration;
                let signal = rule
                    .action
                    .signal
                    .clone()
                    .unwrap_or_else(|| "SIGKILL".to_string());
                let kill_children = rule.action.kill_children;
                if rule.action.log {
                    info!(
                        rule = %rule.name,
                        pid = event.pid,
                        uid = event.uid,
                        command = ?event.args.get(1),
                        deadline_secs = duration.as_secs(),
                        "Deadline rule matched — tracking; will kill after deadline"
                    );
                }
                let starttime = read_pid_starttime(event.pid);
                self.tracked.insert(
                    event.pid,
                    TrackedDeadline {
                        deadline,
                        signal,
                        kill_children,
                        rule_name: rule.name.clone(),
                        starttime,
                    },
                );
            }
        }
    }

    /// Stop tracking a PID when the process exits (e.g. we saw a USER_END PAM audit event).
    pub fn untrack_pid(&mut self, pid: u32) {
        if self.tracked.remove(&pid).is_some() {
            debug!(pid = pid, "Stopped tracking — process exited (USER_END)");
        }
    }

    /// Check all tracked PIDs and kill any that have passed their deadline.
    /// Also evict any tracked PID whose process has already exited (USER_END may
    /// report a child pid, not the sudo pid we tracked).
    pub fn check_deadlines(&mut self) {
        let exited: Vec<u32> = self
            .tracked
            .iter()
            .filter(|(&pid, _)| !process_exists(pid))
            .map(|(&pid, _)| pid)
            .collect();
        for pid in exited {
            self.tracked.remove(&pid);
            info!(pid = pid, "Stopped tracking — process already exited");
        }

        let now = Instant::now();
        let overdue: Vec<_> = self
            .tracked
            .iter()
            .filter(|(_, t)| now >= t.deadline)
            .map(|(&pid, t)| {
                (
                    pid,
                    t.rule_name.clone(),
                    t.signal.clone(),
                    t.kill_children,
                    t.starttime,
                )
            })
            .collect();
        for (pid, rule_name, signal, kill_children, stored_starttime) in overdue {
            self.tracked.remove(&pid);
            let current_starttime = read_pid_starttime(pid);
            let same_process = stored_starttime
                .zip(current_starttime)
                .map(|(a, b)| a == b)
                .unwrap_or(false);
            if same_process {
                info!(
                    rule = %rule_name,
                    pid = pid,
                    "Deadline exceeded — killing process"
                );
                apply_action_for_pid(pid, &signal, kill_children);
            } else {
                debug!(
                    pid = pid,
                    rule = %rule_name,
                    "Skipping kill — process gone or PID reused"
                );
            }
        }
    }
}

// ── Matching logic ────────────────────────────────────────────────────────────

fn matches_rule(cond: &MatchCondition, ev: &SudoEvent) -> bool {
    // match_all bypasses every other condition.
    if cond.match_all {
        return true;
    }

    // ── UID / AUID filters ────────────────────────────────────────────────────

    if let Some(uids) = &cond.uids {
        if !uids.contains(&ev.uid) {
            return false;
        }
    }

    if let Some([lo, hi]) = cond.uid_range {
        if ev.uid < lo || ev.uid > hi {
            return false;
        }
    }

    if let Some(excl) = &cond.exclude_uids {
        if excl.contains(&ev.uid) {
            return false;
        }
    }

    if let Some(auids) = &cond.auids {
        if !auids.contains(&ev.auid) {
            return false;
        }
    }

    // ── Argument filters ──────────────────────────────────────────────────────

    let args_str = ev.args.join(" ");

    if let Some(must_contain) = &cond.args_contain {
        // ANY substring in the list must appear somewhere in the joined args.
        if !must_contain.iter().any(|pat| args_str.contains(pat.as_str())) {
            return false;
        }
    }

    if let Some(must_not) = &cond.args_not_contain {
        // If ANY exclusion substring is found, do NOT kill.
        if must_not.iter().any(|pat| args_str.contains(pat.as_str())) {
            return false;
        }
    }

    // ── TTY filters ───────────────────────────────────────────────────────────

    if let Some(tty) = &cond.tty {
        if &ev.tty != tty {
            return false;
        }
    }

    if let Some(true) = cond.no_tty {
        // no_tty = true: only match when there is no terminal.
        let has_tty = ev.tty != "?" && ev.tty != "(none)" && !ev.tty.is_empty();
        if has_tty {
            return false;
        }
    }

    // All specified conditions matched.
    true
}

/// Match a deadline rule: UID (uids or uid_range) and command.
/// Command is the executable name: for SYSCALL/EXECVE it's args[1]; for USER_CMD
/// the audit log may give either the post-sudo argv (args[1] = "sh") or the full
/// command line (args = ["sudo", "sudo", "-u", "user1", "sh"]), so we also match
/// when the rule's command equals or is a suffix of the last arg.
fn matches_deadline_rule(rule: &DeadlineRule, ev: &SudoEvent) -> bool {
    if let Some(uids) = &rule.uids {
        if !uids.contains(&ev.uid) {
            return false;
        }
    }
    if let Some([lo, hi]) = rule.uid_range {
        if ev.uid < lo || ev.uid > hi {
            return false;
        }
    }
    if rule.uids.is_none() && rule.uid_range.is_none() {
        return false;
    }
    let matches_cmd = |c: &str| c == rule.command || c.ends_with(&rule.command);
    let first = ev.args.get(1).map(String::as_str);
    let last = ev.args.last().map(String::as_str);
    if first.map_or(false, matches_cmd) {
        return true;
    }
    if last.map_or(false, matches_cmd) {
        return true;
    }
    false
}

// ── Kill logic ────────────────────────────────────────────────────────────────

fn apply_action(action: &Action, ev: &SudoEvent) {
    let signal_name = action.signal.as_deref().unwrap_or("SIGKILL");
    apply_action_for_pid(ev.pid, signal_name, action.kill_children);
}

fn apply_action_for_pid(pid: u32, signal_name: &str, kill_children: bool) {
    let sig = resolve_signal(signal_name);

    // 1. Kill the sudo process itself.
    send_signal(pid, sig, "sudo process");

    if kill_children {
        // 2. Kill the entire process group (catches already-exec'd children).
        if let Ok(pgid) = read_pgid(pid) {
            if pgid != 0 {
                send_signal_pgid(pgid, sig);
            }
        }
        // 3. Walk /proc for any children whose ppid == pid.
        for child_pid in find_children(pid) {
            send_signal(child_pid, sig, "child of sudo");
        }
    }
}

fn send_signal(pid: u32, sig: Signal, label: &str) {
    match kill(Pid::from_raw(pid as i32), sig) {
        Ok(()) => info!("Sent {} to {} (pid={})", sig, label, pid),
        Err(nix::errno::Errno::ESRCH) => {
            // Process already exited — not an error.
            info!("{} (pid={}) already exited before signal could be sent", label, pid);
        }
        Err(e) => {
            error!("Failed to send {} to {} (pid={}): {}", sig, label, pid, e);
        }
    }
}

fn send_signal_pgid(pgid: u32, sig: Signal) {
    // Negative pid → signal the process group.
    match kill(Pid::from_raw(-(pgid as i32)), sig) {
        Ok(()) => info!("Sent {} to process group {}", sig, pgid),
        Err(nix::errno::Errno::ESRCH) => {}
        Err(e) => warn!("Failed to signal process group {}: {}", pgid, e),
    }
}

/// Return true if a process with the given PID exists (kill(pid, 0) does not return ESRCH).
fn process_exists(pid: u32) -> bool {
    let ret = unsafe { libc::kill(pid as i32, 0) };
    if ret == 0 {
        true
    } else {
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
}

/// Read process start time from /proc/<pid>/stat (field 22, starttime in jiffies).
/// Used to verify we're still looking at the same process (avoids killing a recycled PID).
fn read_pid_starttime(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let stat = fs::read_to_string(&path).ok()?;
    let after_comm = stat.rfind(')')? + 1;
    let rest = stat[after_comm..].trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After comm: state ppid pgrp session tty_nr tty_pgrp flags min_flt cmin_flt maj_flt
    // cmaj_flt utime stime cutime cstime priority nice num_threads itrealvalue starttime
    fields.get(19).and_then(|s| s.parse().ok())
}

// ── /proc helpers ─────────────────────────────────────────────────────────────

/// Read the PGID of `pid` from `/proc/<pid>/stat`.
///
/// Field 5 (0-indexed: 4) in `/proc/<pid>/stat` is the process group ID.
fn read_pgid(pid: u32) -> Result<u32, ()> {
    let path = format!("/proc/{}/stat", pid);
    let stat = fs::read_to_string(&path).map_err(|_| ())?;

    // The second field is the comm, wrapped in parentheses and may contain
    // spaces or nested parens.  Skip past the last `)` to safely index fields.
    let after_comm = stat.rfind(')').ok_or(())? + 1;
    let rest = stat[after_comm..].trim_start();

    // Remaining fields: state ppid pgrp …
    // Indices (after comm+state):  0=state 1=ppid 2=pgrp
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state, [1] = ppid, [2] = pgrp
    fields
        .get(2)
        .and_then(|s| s.parse().ok())
        .ok_or(())
}

/// Return the PIDs of all processes whose PPID equals `parent_pid` by scanning
/// `/proc/*/status`.
fn find_children(parent_pid: u32) -> Vec<u32> {
    let mut children = Vec::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return children,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at numeric directories (PIDs).
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if pid == parent_pid {
            continue;
        }

        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = fs::read_to_string(&status_path) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("PPid:") {
                    if let Ok(ppid) = rest.trim().parse::<u32>() {
                        if ppid == parent_pid {
                            children.push(pid);
                        }
                    }
                    break;
                }
            }
        }
    }

    children
}

// ── Utility ───────────────────────────────────────────────────────────────────

fn resolve_signal(name: &str) -> Signal {
    match name {
        "SIGTERM" => Signal::SIGTERM,
        "SIGKILL" => Signal::SIGKILL,
        "SIGSTOP" => Signal::SIGSTOP,
        other => {
            warn!("Unknown signal '{}', defaulting to SIGKILL", other);
            Signal::SIGKILL
        }
    }
}

fn signal_name(action: &Action) -> &str {
    action.signal.as_deref().unwrap_or("SIGKILL")
}

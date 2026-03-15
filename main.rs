//! `sudo-sentinel` — daemon entry point.
//!
//! # Usage
//!
//!     sudo sudo-sentinel [/path/to/config.toml]
//!
//! The default config path is `/etc/sudo-sentinel/config.toml`.
//!
//! # Shutdown
//!
//! Send `SIGTERM` or `SIGINT`.  The daemon will remove its audit rule before
//! exiting so that the kernel rule list is clean.
//!
//! # Coexistence with auditd
//!
//! We subscribe to the `AUDIT_NLGRP_READLOG` multicast group, so we receive a
//! copy of every audit event without displacing an existing `auditd`.  Our
//! execve filter rule is added to (and removed from) the kernel rule list just
//! like any `auditctl` invocation.
//!
//! # Timing caveat
//!
//! Audit events arrive *after* the `execve` syscall has already returned.
//! Sudo may have forked and exec'd its child command by the time the signal is
//! delivered.  We mitigate this by killing the process group and scanning
//! `/proc` for children, but a true pre-exec interception requires eBPF LSM.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

mod audit;
mod config;
mod event;
mod matcher;

use audit::{
    AuditSocket, AUDIT_CWD, AUDIT_EOE, AUDIT_EXECVE, AUDIT_SYSCALL, AUDIT_USER_CMD, AUDIT_USER_END,
};
use config::Config;
use event::{build_from_user_cmd, parse_kv, EventBuilder};
use matcher::RuleMatcher;

// ── Global shutdown flag ──────────────────────────────────────────────────────

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/sudo-sentinel/config.toml".to_string());

    // ── Config ────────────────────────────────────────────────────────────────

    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from '{config_path}'"))?;

    // ── Logging ───────────────────────────────────────────────────────────────

    // RUST_LOG overrides config when set (so you can debug without editing config).
    let log_filter = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| config.daemon.log_level.clone())
        .unwrap_or_else(|| "info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    // ── Privilege check ───────────────────────────────────────────────────────

    if unsafe { libc::getuid() } != 0 {
        anyhow::bail!("sudo-sentinel must run as root (uid 0)");
    }

    info!("sudo-sentinel starting");
    info!(
        "Loaded {} rule(s) from '{}'",
        config.rules.len(),
        config_path
    );
    for rule in &config.rules {
        if let Some(ref d) = rule.deadline {
            info!("  • {} (deadline: {})", rule.name, d);
        } else {
            info!("  • {} (immediate)", rule.name);
        }
    }

    // ── PID file ──────────────────────────────────────────────────────────────

    if let Some(pid_file) = &config.daemon.pid_file {
        let pid = unsafe { libc::getpid() };
        std::fs::write(pid_file, format!("{}\n", pid))
            .with_context(|| format!("Cannot write PID file '{pid_file}'"))?;
        info!("PID file written to '{}'", pid_file);
    }

    // ── Audit socket setup ────────────────────────────────────────────────────

    let mut audit =
        AuditSocket::new().context("Failed to open NETLINK_AUDIT socket (kernel audit support enabled?)")?;

    // Try to enable auditing; non-fatal if auditd is already doing this.
    audit.try_enable_auditing();

    audit
        .add_execve_rule()
        .context("Failed to install execve audit rule")?;

    info!("Audit execve rule installed; monitoring for sudo invocations");

    // ── Signal handlers ───────────────────────────────────────────────────────

    unsafe {
        libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
        // Ignore SIGPIPE — shouldn't happen but be defensive.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // ── Rule matcher ──────────────────────────────────────────────────────────

    let mut matcher = RuleMatcher::new(config.rules);

    // ── Main event loop ───────────────────────────────────────────────────────

    // Audit events are multi-record bursts all sharing one serial number.
    // We accumulate records here until we see the EOE sentinel.
    let mut pending: HashMap<u64, EventBuilder> = HashMap::new();

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        matcher.check_deadlines();

        match audit.read_record() {
            // ── Timeout / EINTR ───────────────────────────────────────────────
            Ok(None) => continue,

            // ── Audit record received ─────────────────────────────────────────
            Ok(Some((msg_type, serial, text))) => {
                debug!(msg_type, serial, "record received");

                match msg_type {
                    AUDIT_SYSCALL => {
                        let kv = parse_kv(&text);
                        let builder = pending.entry(serial).or_insert_with(|| EventBuilder {
                            serial,
                            ..Default::default()
                        });
                        builder.syscall = Some(kv);
                    }

                    AUDIT_EXECVE => {
                        let kv = parse_kv(&text);
                        if let Some(builder) = pending.get_mut(&serial) {
                            builder.execve = Some(kv);
                        }
                    }

                    AUDIT_CWD => {
                        let kv = parse_kv(&text);
                        if let Some(builder) = pending.get_mut(&serial) {
                            builder.cwd = kv.get("cwd").cloned();
                        }
                    }

                    AUDIT_EOE => {
                        if let Some(builder) = pending.remove(&serial) {
                            if let Some(ev) = builder.build() {
                                info!(
                                    pid  = ev.pid,
                                    uid  = ev.uid,
                                    auid = ev.auid,
                                    tty  = %ev.tty,
                                    exe  = %ev.exe,
                                    args = ?ev.args,
                                    "sudo invocation detected"
                                );
                                matcher.process(&ev);
                            }
                        }

                        // Safety valve: evict the pending map if it somehow
                        // grows very large (e.g. many non-sudo execves with
                        // missing EOE records).
                        if pending.len() > 2048 {
                            warn!(
                                "Pending event buffer grew to {}; evicting stale entries",
                                pending.len()
                            );
                            pending.clear();
                        }
                    }

                    AUDIT_USER_CMD => {
                        // Fallback when kernel does not emit SYSCALL/EXECVE (e.g. execve rule not active).
                        if let Some(ev) = build_from_user_cmd(&text, serial) {
                            info!(
                                pid  = ev.pid,
                                uid  = ev.uid,
                                auid = ev.auid,
                                tty  = %ev.tty,
                                exe  = %ev.exe,
                                args = ?ev.args,
                                "sudo invocation detected (USER_CMD)"
                            );
                            matcher.process(&ev);
                        }
                    }

                    AUDIT_USER_END => {
                        // PAM session close: stop tracking this PID (sudo/session exited).
                        let kv = parse_kv(&text);
                        if let Some(pid_s) = kv.get("pid") {
                            if let Ok(pid) = pid_s.parse::<u32>() {
                                matcher.untrack_pid(pid);
                            }
                        }
                    }

                    _ => {}
                }
            }

            // ── I/O error ─────────────────────────────────────────────────────
            Err(e) => {
                if !SHUTDOWN.load(Ordering::Relaxed) {
                    error!("Error reading audit record: {}", e);
                    // Brief pause to avoid a tight error-spin loop.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    }

    // ── Clean shutdown ────────────────────────────────────────────────────────

    info!("Shutting down — removing audit rule");
    if let Err(e) = audit.remove_execve_rule() {
        warn!("Failed to remove audit rule on shutdown: {}", e);
    }

    if let Some(pid_file) = &config.daemon.pid_file {
        let _ = std::fs::remove_file(pid_file);
    }

    info!("Exiting");
    Ok(())
}

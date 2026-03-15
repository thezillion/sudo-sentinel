//! Linux Audit subsystem interface.
//!
//! Opens a raw `NETLINK_AUDIT` socket, joins the audit multicast readlog group
//! so we receive events without displacing an existing `auditd`, installs an
//! `execve`/`execveat` filter rule, and exposes a blocking-with-timeout
//! `read_record()` call for the main event loop.
//!
//! # Kernel message flow
//!
//! For every `execve` the kernel emits a burst of records sharing one serial:
//!
//! ```text
//! AUDIT_SYSCALL  (pid, uid, euid, exe, success, …)
//! AUDIT_EXECVE   (argc, a0, a1, …)
//! AUDIT_CWD      (cwd=…)
//! AUDIT_PATH     (item=0, name=…)          ← one per file descriptor touched
//! AUDIT_EOE                                ← end-of-event sentinel
//! ```
//!
//! Each record arrives as one complete netlink message; we never see fragments.

use anyhow::{bail, Result};
use libc::{c_int, c_void};
use std::mem;
use std::os::unix::io::RawFd;
use tracing::warn;

// ── Netlink constants ────────────────────────────────────────────────────────

const NETLINK_AUDIT: c_int = 9;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

const NLMSG_ERROR: u16 = 0x0002;

// ── Audit message types ──────────────────────────────────────────────────────

/// Query / set audit daemon status.
const AUDIT_GET: u16 = 1000;
const AUDIT_SET: u16 = 1001;
/// Add / delete a filter rule.
const AUDIT_ADD_RULE_DATA: u16 = 1011;
const AUDIT_DEL_RULE_DATA: u16 = 1012;

// Public: used by the main event loop to dispatch records.
pub const AUDIT_SYSCALL: u16 = 1300;
pub const AUDIT_PATH: u16 = 1302;
pub const AUDIT_CWD: u16 = 1307;
pub const AUDIT_EXECVE: u16 = 1309;
pub const AUDIT_EOE: u16 = 1320;
/// USER_CMD (1123): PAM/audit userspace; exe=, pid=, uid=, cmd= (hex). Fallback when kernel SYSCALL is not emitted.
pub const AUDIT_USER_CMD: u16 = 1123;
/// USER_END (1106): PAM session close; pid= in outer payload. Use to stop tracking when a sudo session exits.
pub const AUDIT_USER_END: u16 = 1106;

// ── Audit rule constants ─────────────────────────────────────────────────────

/// Apply rule on syscall exit.
const AUDIT_FILTER_EXIT: u32 = 0x04;
/// Always generate a record when matched.
const AUDIT_ALWAYS: u32 = 0x02;

/// Field: CPU architecture of the syscall.
const AUDIT_ARCH: u32 = 11;
/// Comparison operator: equality.
const AUDIT_EQUAL: u32 = 0;

/// x86-64 architecture tag used in audit rules (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE).
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// Syscall number for `execve` on x86-64.
const SYS_EXECVE: u32 = 59;
/// Syscall number for `execveat` on x86-64.
const SYS_EXECVEAT: u32 = 322;

/// Multicast group that receives a copy of every audit record.
/// Subscribing here lets us coexist with an existing `auditd`.
const AUDIT_NLGRP_READLOG: u32 = 1;

// ── Audit status flags ───────────────────────────────────────────────────────

const AUDIT_STATUS_ENABLED: u32 = 0x0001;

// ── Struct sizes ─────────────────────────────────────────────────────────────

const AUDIT_BITMASK_SIZE: usize = 64;
const AUDIT_MAX_FIELDS: usize = 64;

// ── Repr-C structs (must match kernel ABI exactly) ───────────────────────────

#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// `struct audit_rule_data` from `<linux/audit.h>`.
///
/// The flexible-array `buf[]` member is omitted here; it is appended manually
/// for rules that embed string data.  For our arch-only rule, `buflen == 0`
/// and the struct is sent as-is.
#[repr(C)]
struct AuditRuleData {
    flags: u32,
    action: u32,
    field_count: u32,
    mask: [u32; AUDIT_BITMASK_SIZE],
    fields: [u32; AUDIT_MAX_FIELDS],
    values: [u32; AUDIT_MAX_FIELDS],
    fieldflags: [u32; AUDIT_MAX_FIELDS],
    buflen: u32,
    // buf[] omitted — zero bytes appended when buflen > 0
}

/// `struct audit_status` from `<linux/audit.h>` (truncated to fields we use).
#[repr(C)]
struct AuditStatus {
    mask: u32,
    enabled: u32,
    failure: u32,
    pid: u32,
    rate_limit: u32,
    backlog_limit: u32,
    lost: u32,
    backlog: u32,
    feature_bitmap: u32,
    backlog_wait_time: u32,
    backlog_wait_time_actual: u32,
}

// ── Public interface ─────────────────────────────────────────────────────────

pub struct AuditSocket {
    fd: RawFd,
    /// Our socket's port ID, assigned by the kernel at bind time.
    nl_pid: u32,
    seq: u32,
}

impl AuditSocket {
    /// Create and bind the netlink socket, joining the audit multicast group.
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_AUDIT,
            )
        };
        if fd < 0 {
            bail!("socket(NETLINK_AUDIT): {}", last_os_error());
        }

        // Bind, joining the readlog multicast group so we receive events
        // without becoming the primary audit daemon.
        //
        // On some platforms `sockaddr_nl::nl_pad` is a `Padding<u16>` instead of a
        // plain integer field, so we zero-initialize the struct and then set the
        // fields we care about explicitly.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // let the kernel assign a unique port ID
        addr.nl_groups = AUDIT_NLGRP_READLOG;
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            bail!("bind(NETLINK_AUDIT): {}", last_os_error());
        }

        // Discover the kernel-assigned port ID.
        let mut bound_addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut addr_len = mem::size_of::<libc::sockaddr_nl>() as u32;
        unsafe {
            libc::getsockname(
                fd,
                &mut bound_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        let nl_pid = bound_addr.nl_pid;

        // Set a 1-second receive timeout so the main loop can check the
        // shutdown flag without blocking indefinitely.
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const c_void,
                mem::size_of::<libc::timeval>() as u32,
            )
        };

        Ok(Self { fd, nl_pid, seq: 1 })
    }

    /// Try to enable auditing in the kernel (best-effort; ignored if `auditd` is
    /// already managing this).
    pub fn try_enable_auditing(&mut self) {
        let status = AuditStatus {
            mask: AUDIT_STATUS_ENABLED,
            enabled: 1,
            failure: 1,
            pid: 0,
            rate_limit: 0,
            backlog_limit: 8192,
            lost: 0,
            backlog: 0,
            feature_bitmap: 0,
            backlog_wait_time: 60 * 1000,
            backlog_wait_time_actual: 0,
        };
        let data = unsafe {
            std::slice::from_raw_parts(
                &status as *const _ as *const u8,
                mem::size_of::<AuditStatus>(),
            )
        };
        if self.send_message(AUDIT_SET, data).is_ok() {
            // Drain the ACK; ignore errors (may fail if not privileged to set).
            let _ = self.recv_ack_or_err();
        }
    }

    /// Install the `execve`/`execveat` audit rule.
    ///
    /// Gracefully handles `EEXIST` (rule already present from a previous run).
    pub fn add_execve_rule(&mut self) -> Result<()> {
        match self.send_execve_rule(AUDIT_ADD_RULE_DATA) {
            Ok(()) => Ok(()),
            // EEXIST (17): rule was already installed (e.g. daemon restarted).
            Err(e) if format!("{e}").contains("17") => {
                warn!("execve audit rule already exists (EEXIST) — continuing");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Remove the rule we installed.  Called on clean shutdown.
    pub fn remove_execve_rule(&mut self) -> Result<()> {
        self.send_execve_rule(AUDIT_DEL_RULE_DATA)
    }

    /// Read one netlink message.
    ///
    /// Returns `Ok(None)` on timeout / `EINTR` (caller should loop).
    /// Returns `Ok(Some((msg_type, serial, payload_text)))` on success.
    pub fn read_record(&self) -> Result<Option<(u16, u64, String)>> {
        // 8 KiB is plenty for any single audit record.
        let mut buf = vec![0u8; 8192];

        let n = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };

        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(
                e.raw_os_error(),
                Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
            ) {
                return Ok(None);
            }
            bail!("recv(audit): {}", e);
        }

        let n = n as usize;
        if n < mem::size_of::<NlMsgHdr>() {
            return Ok(None);
        }

        let hdr = unsafe { &*(buf.as_ptr() as *const NlMsgHdr) };
        let msg_type = hdr.nlmsg_type;

        // Skip netlink housekeeping messages (ACKs, errors we didn't request).
        if msg_type == NLMSG_ERROR || msg_type < 1000 {
            return Ok(None);
        }

        let payload_start = mem::size_of::<NlMsgHdr>();
        let payload_end = (hdr.nlmsg_len as usize).min(n);

        let text = if payload_end > payload_start {
            // The kernel null-terminates audit text; strip that and any trailing
            // whitespace so the parser sees a clean string.
            let raw = &buf[payload_start..payload_end];
            let trimmed = raw
                .iter()
                .rposition(|&b| b != 0 && b != b'\n')
                .map(|p| &raw[..=p])
                .unwrap_or(&raw[..0]);
            String::from_utf8_lossy(trimmed).into_owned()
        } else {
            String::new()
        };

        let serial = parse_serial(&text).unwrap_or(0);
        Ok(Some((msg_type, serial, text)))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn send_execve_rule(&mut self, msg_type: u16) -> Result<()> {
        let mut rule: AuditRuleData = unsafe { mem::zeroed() };
        rule.flags = AUDIT_FILTER_EXIT;
        rule.action = AUDIT_ALWAYS;

        // Set one bit per syscall we want to watch.
        set_syscall_bit(&mut rule.mask, SYS_EXECVE);
        set_syscall_bit(&mut rule.mask, SYS_EXECVEAT);

        // Single field filter: arch == x86-64.
        // (Keeps the rule from firing on 32-bit compat-mode execves with
        // different syscall numbers; adjust if you need ia32 coverage.)
        rule.field_count = 1;
        rule.fields[0] = AUDIT_ARCH;
        rule.values[0] = AUDIT_ARCH_X86_64;
        rule.fieldflags[0] = AUDIT_EQUAL;
        rule.buflen = 0;

        let data = unsafe {
            std::slice::from_raw_parts(
                &rule as *const _ as *const u8,
                mem::size_of::<AuditRuleData>(),
            )
        };

        self.send_message(msg_type, data)?;
        self.recv_ack_or_err()
    }

    fn send_message(&mut self, msg_type: u16, payload: &[u8]) -> Result<()> {
        let total = mem::size_of::<NlMsgHdr>() + payload.len();
        let mut buf = vec![0u8; total];

        let hdr = NlMsgHdr {
            nlmsg_len: total as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: self.seq,
            nlmsg_pid: self.nl_pid,
        };
        self.seq += 1;

        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const _ as *const u8,
                mem::size_of::<NlMsgHdr>(),
            )
        };
        buf[..mem::size_of::<NlMsgHdr>()].copy_from_slice(hdr_bytes);
        buf[mem::size_of::<NlMsgHdr>()..].copy_from_slice(payload);

        let mut dest: libc::sockaddr_nl = unsafe { mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as u16;
        dest.nl_pid = 0; // destination: kernel
        dest.nl_groups = 0;
        let ret = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *const c_void,
                buf.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            bail!("sendto(audit): {}", last_os_error());
        }
        Ok(())
    }

    /// Receive one message from the kernel and surface any embedded error code.
    fn recv_ack_or_err(&self) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe {
            libc::recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0)
        };
        if n < 0 {
            bail!("recv(ack): {}", last_os_error());
        }
        let n = n as usize;
        if n < mem::size_of::<NlMsgHdr>() {
            return Ok(());
        }

        let hdr = unsafe { &*(buf.as_ptr() as *const NlMsgHdr) };
        if hdr.nlmsg_type == NLMSG_ERROR {
            // `struct nlmsgerr` starts with an `int error` immediately after
            // the netlink header.
            let payload_start = mem::size_of::<NlMsgHdr>();
            if n >= payload_start + 4 {
                let errno = i32::from_ne_bytes(
                    buf[payload_start..payload_start + 4]
                        .try_into()
                        .unwrap(),
                );
                if errno < 0 {
                    bail!(
                        "audit netlink errno {} ({})",
                        -errno,
                        std::io::Error::from_raw_os_error(-errno)
                    );
                }
            }
        }
        Ok(())
    }
}

impl Drop for AuditSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Set the bit for `syscall` in the rule's syscall bitmask.
///
/// `mask` is a 64-element array of u32, giving 2048 bits — one per syscall.
fn set_syscall_bit(mask: &mut [u32; AUDIT_BITMASK_SIZE], syscall: u32) {
    let word = (syscall / 32) as usize;
    let bit = syscall % 32;
    if word < AUDIT_BITMASK_SIZE {
        mask[word] |= 1u32 << bit;
    }
}

/// Extract the serial number from an audit text payload.
///
/// The payload begins with `audit(TIMESTAMP:SERIAL):`.
pub fn parse_serial(text: &str) -> Option<u64> {
    let start = text.find("audit(")? + 6;
    let rest = &text[start..];
    let colon = rest.find(':')?;
    let end = rest[colon + 1..].find(')')? + colon + 1;
    rest[colon + 1..end].parse().ok()
}

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

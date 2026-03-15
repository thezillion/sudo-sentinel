//! Audit record parsing.
//!
//! # Record accumulation
//!
//! A single `execve` event produces several netlink messages (SYSCALL, EXECVE,
//! CWD, PATH…) all carrying the same *serial* number.  `EventBuilder`
//! accumulates those records, and `build()` assembles a `SudoEvent` once the
//! EOE sentinel has been received.
//!
//! # Key-value parsing
//!
//! Each record's payload looks like:
//! ```text
//! audit(1745678901.000:42): key=value key="spaced value" key=(null)
//! ```
//! `parse_kv` converts the tail into a `HashMap<String, String>`.

use std::collections::HashMap;

// ── Parsed event ──────────────────────────────────────────────────────────────

/// A fully assembled sudo invocation event.
#[derive(Debug, Default)]
pub struct SudoEvent {
    pub serial: u64,
    /// Real UID of the process that called sudo.
    pub uid: u32,
    /// Login UID (set at PAM login, survives su/sudo chains).
    /// `4294967295` means no login session.
    pub auid: u32,
    /// Effective UID at exec time (typically 0 because sudo is setuid-root).
    pub euid: u32,
    /// PID of the sudo process.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// TTY name, or `"?"` / `"(none)"` if none.
    pub tty: String,
    /// Path of the executed binary (should be `/usr/bin/sudo`).
    pub exe: String,
    /// Decoded command-line arguments as passed to sudo.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Audit session ID.
    pub ses: u32,
    /// Whether the syscall succeeded.
    pub success: bool,
}

// ── Record accumulator ────────────────────────────────────────────────────────

/// Accumulates the individual audit records that belong to one serial number.
#[derive(Default)]
pub struct EventBuilder {
    pub syscall: Option<HashMap<String, String>>,
    pub execve: Option<HashMap<String, String>>,
    pub cwd: Option<String>,
    pub serial: u64,
}

impl EventBuilder {
    /// Attempt to build a `SudoEvent`.
    ///
    /// Returns `None` if:
    /// - The SYSCALL record is missing.
    /// - `exe` is not a sudo binary.
    pub fn build(&self) -> Option<SudoEvent> {
        let sys = self.syscall.as_ref()?;

        let exe = sys.get("exe").map(String::as_str).unwrap_or("");
        if !is_sudo_exe(exe) {
            return None;
        }

        let success = sys
            .get("success")
            .map(|s| s == "yes")
            .unwrap_or(false);

        // `auid` of 4294967295 (== u32::MAX) is the kernel sentinel meaning
        // "not set" (the process has no audit login session).
        let auid = parse_u32(sys.get("auid").map(String::as_str).unwrap_or("4294967295"));

        let mut event = SudoEvent {
            serial: self.serial,
            pid: parse_u32(sys.get("pid").map(String::as_str)?),
            ppid: parse_u32(sys.get("ppid").map(String::as_str).unwrap_or("0")),
            uid: parse_u32(sys.get("uid").map(String::as_str).unwrap_or("0")),
            auid,
            euid: parse_u32(sys.get("euid").map(String::as_str).unwrap_or("0")),
            tty: sys.get("tty").cloned().unwrap_or_else(|| "?".to_string()),
            exe: exe.to_string(),
            cwd: self.cwd.clone().unwrap_or_default(),
            ses: parse_u32(sys.get("ses").map(String::as_str).unwrap_or("0")),
            success,
            ..Default::default()
        };

        if let Some(execve_kv) = &self.execve {
            event.args = parse_execve_args(execve_kv);
        }

        Some(event)
    }
}

// ── Key-value parser ──────────────────────────────────────────────────────────

/// Parse the key=value pairs that follow the `audit(TS:SERIAL): ` prefix.
///
/// Handles:
/// - `key=unquoted` — value ends at the next space
/// - `key="quoted value"` — value may contain spaces
/// - `key=(null)` — emitted as the empty string
pub fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Skip the `audit(TIMESTAMP:SERIAL): ` header.
    let rest = match text.find("): ") {
        Some(pos) => &text[pos + 3..],
        None => text.trim(),
    };

    let mut input = rest.trim();

    while !input.is_empty() {
        // Find the next `=`.
        let eq = match input.find('=') {
            Some(p) => p,
            None => break,
        };

        // The key is everything left of `=`.  If there were prior value
        // characters that were accidentally glued on (shouldn't happen in
        // well-formed records), trim them.
        let key = input[..eq].trim().to_string();
        input = &input[eq + 1..];

        if input.is_empty() {
            map.insert(key, String::new());
            break;
        }

        let (value, tail) = if input.starts_with('"') {
            // Quoted value.
            let body = &input[1..];
            match body.find('"') {
                Some(end) => {
                    let val = body[..end].to_string();
                    let after = &body[end + 1..];
                    (val, skip_space(after))
                }
                None => {
                    // Unterminated quote — consume to end of input.
                    (body.to_string(), "")
                }
            }
        } else if input.starts_with('\'') {
            // Single-quoted value (e.g. USER_CMD inner msg).
            let body = &input[1..];
            match body.find('\'') {
                Some(end) => {
                    let val = body[..end].to_string();
                    (val, skip_space(&body[end + 1..]))
                }
                None => (body.to_string(), ""),
            }
        } else if input.starts_with('(') {
            // `(null)` style value.
            match input.find(')') {
                Some(end) => {
                    // Emit empty string for (null), otherwise the raw content.
                    let inner = &input[1..end];
                    let val = if inner == "null" {
                        String::new()
                    } else {
                        inner.to_string()
                    };
                    (val, skip_space(&input[end + 1..]))
                }
                None => (input.to_string(), ""),
            }
        } else {
            // Unquoted: value ends at the next space.
            let end = input.find(' ').unwrap_or(input.len());
            let val = input[..end].to_string();
            let after = if end < input.len() {
                &input[end + 1..]
            } else {
                ""
            };
            (val, after)
        };

        if !key.is_empty() {
            map.insert(key, value);
        }
        input = tail;
    }

    map
}

// ── EXECVE argument parsing ───────────────────────────────────────────────────

/// Reconstruct the argument list from the EXECVE audit record.
///
/// The kernel emits:
/// ```text
/// argc=3 a0="sudo" a1="vim" a2="/etc/passwd"
/// ```
/// For arguments containing non-printable bytes it uses hex encoding without
/// quotes: `a2=2F6574632F706173737764`.  We detect and decode those.
fn parse_execve_args(kv: &HashMap<String, String>) -> Vec<String> {
    let argc = kv
        .get("argc")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    (0..argc)
        .filter_map(|i| {
            let key = format!("a{i}");
            kv.get(&key).map(|v| decode_arg(v))
        })
        .collect()
}

/// Decode an argument value that may be hex-encoded by the kernel.
fn decode_arg(val: &str) -> String {
    // A hex-encoded argument has an even length and contains only hex digits.
    // The kernel never quotes hex-encoded values.
    if val.len() >= 2 && val.len() % 2 == 0 && val.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(decoded) = hex_decode(val) {
            return decoded;
        }
    }
    val.to_string()
}

fn hex_decode(s: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    bytes.and_then(|b| String::from_utf8(b).ok())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_u32(s: &str) -> u32 {
    s.parse().unwrap_or(0)
}

fn skip_space(s: &str) -> &str {
    s.trim_start_matches(' ')
}

/// Return `true` if `exe` is a known sudo binary path.
fn is_sudo_exe(exe: &str) -> bool {
    matches!(exe, "/usr/bin/sudo" | "/bin/sudo" | "/usr/local/bin/sudo")
}

// ── USER_CMD fallback (PAM/audit userspace) ───────────────────────────────────

/// Build a `SudoEvent` from a USER_CMD (type 1123) audit record.
///
/// When the kernel does not emit SYSCALL/EXECVE for execve (e.g. rule not active),
/// PAM and the audit plugin still emit USER_CMD with exe=, pid=, uid=, and cmd=
/// (hex-encoded command line). This allows detecting sudo invocations from that
/// record so rules and deadline tracking still work.
pub fn build_from_user_cmd(text: &str, serial: u64) -> Option<SudoEvent> {
    let outer = parse_kv(text);
    let pid: u32 = outer.get("pid").and_then(|s| s.parse().ok())?;
    let uid = parse_u32(outer.get("uid").map(String::as_str).unwrap_or("0"));
    let auid = parse_u32(outer.get("auid").map(String::as_str).unwrap_or("4294967295"));
    let ses = parse_u32(outer.get("ses").map(String::as_str).unwrap_or("0"));

    let msg_inner = outer.get("msg")?;
    // Inner msg has no "audit(ts:ser): " prefix; parse_kv uses rest = text when no "): ".
    let inner = parse_kv(msg_inner);
    let exe = inner.get("exe").map(String::as_str).unwrap_or("");
    if !is_sudo_exe(exe) {
        return None;
    }

    let cwd = inner.get("cwd").cloned().unwrap_or_default();
    let tty = inner
        .get("terminal")
        .cloned()
        .unwrap_or_else(|| "?".to_string());

    let cmd_val = inner.get("cmd").map(String::as_str).unwrap_or("");
    let decoded = parse_user_cmd_cmd(cmd_val);
    let args: Vec<String> = std::iter::once("sudo".to_string())
        .chain(decoded)
        .collect();

    Some(SudoEvent {
        serial,
        pid,
        ppid: 0,
        uid,
        auid,
        euid: 0,
        tty,
        exe: exe.to_string(),
        args,
        cwd,
        ses,
        success: true,
    })
}

/// Parse USER_CMD cmd= value: either hex-encoded (e.g. "2F7573722F62696E2F7368202D63206964"
/// → "/usr/bin/sh -c id") or a literal quoted string (e.g. "/usr/bin/sh"). Returns argv words.
fn parse_user_cmd_cmd(cmd: &str) -> Vec<String> {
    let s = cmd.trim();
    if s.is_empty() {
        return vec![];
    }
    // If it looks like hex (only 0-9a-fA-F, even length ≥ 2), decode then split.
    if s.len() >= 2
        && s.len() % 2 == 0
        && s.chars().all(|c| c.is_ascii_hexdigit())
    {
        if let Some(decoded) = decode_hex_cmd(s) {
            return decoded;
        }
    }
    // Otherwise treat as literal (e.g. cmd="/usr/bin/sh").
    s.split_whitespace().map(String::from).collect()
}

/// Decode hex string to string and split into words (e.g. "2F757372...6964" -> ["/usr/bin/sh", "-c", "id"]).
fn decode_hex_cmd(hex: &str) -> Option<Vec<String>> {
    let s = hex.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect::<Option<_>>()?;
    let decoded = String::from_utf8(bytes).ok()?;
    Some(decoded.split_whitespace().map(String::from).collect())
}

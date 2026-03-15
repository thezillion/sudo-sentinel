# sudo-sentinel

A daemon that monitors **sudo** invocations via the Linux Audit subsystem and enforces configurable rules: kill immediately (by UID, args, TTY, etc.) or track UID–command pairs with **deadlines** and kill only after the allowed time. Runs alongside `auditd`.

## Features

- **Immediate rules** — Match sudo by UID, UID range, args, TTY, and more. On match, send a signal (e.g. SIGKILL) to the sudo process and its process group.
- **Deadline rules** — Track (UID, command) pairs with a max runtime (e.g. `5m`). If the process is still running after the deadline, it is killed; if it exits earlier, tracking is dropped (with PAM USER_END and/or process-existence checks).
- **Dual detection** — Uses kernel audit SYSCALL/EXECVE when available; falls back to PAM USER_CMD when the execve audit rule is not active (e.g. on some Debian setups).
- **Safe PID handling** — Before killing at deadline, verifies the process by start time from `/proc` so a recycled PID is never killed.

## Requirements

- **Linux** with kernel audit support (`CONFIG_AUDIT`, `CONFIG_AUDITSYSCALL` for full behavior).
- **Root** — Must run as uid 0.
- **Capabilities** (when not full root): `CAP_KILL`, `CAP_AUDIT_CONTROL`, `CAP_AUDIT_WRITE`, `CAP_NET_ADMIN`.  
  - **CAP_AUDIT_CONTROL** — Required to change audit state: enable auditing (`AUDIT_SET`) and add/remove rules (`AUDIT_ADD_RULE_DATA`, `AUDIT_DEL_RULE_DATA`). The daemon needs this to install and remove its execve rule.  
  - **CAP_AUDIT_WRITE** — Required to *write* audit records (e.g. `audit_log_user_message`). This daemon only *reads* events and sends control messages; it does not write log records. It is often included in capability sets for audit-related daemons; you can try dropping it and only add it back if the kernel denies an operation.  
  - **CAP_NET_ADMIN** — Required to create and bind the **AF_NETLINK** socket used to talk to the kernel audit subsystem.

## Build

```bash
cargo build --release
```

Binary: `target/release/sudo-sentinel`.

## Install

1. Copy the binary and config:

   ```bash
   sudo cp target/release/sudo-sentinel /usr/local/sbin/
   sudo mkdir -p /etc/sudo-sentinel
   sudo cp config.toml /etc/sudo-sentinel/config.toml
   ```

2. Optional — systemd:

   ```bash
   sudo cp sudo-sentinel.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now sudo-sentinel
   ```

## Configuration

Config path: `/etc/sudo-sentinel/config.toml` (override with the first CLI argument).

### Daemon

```toml
[daemon]
log_level = "info"   # or trace, debug, warn, error
# pid_file = "/run/sudo-sentinel.pid"
```

`RUST_LOG` overrides `log_level` when set (e.g. `RUST_LOG=debug`).

### Immediate rules

Each `[[rules]]` has:

- **`name`** — Log label.
- **`[rules.match]`** — Optional: `uids`, `uid_range`, `exclude_uids`, `args_contain`, `args_not_contain`, `no_tty`, `tty`, `match_all`, etc.
- **`[rules.action]`** — `signal` (SIGKILL/SIGTERM), `kill_children`, `log`.
- **`stop_on_match`** — If true, no further rules are evaluated after a match.

### Deadline rules

Each `[[deadline_rules]]` has:

- **`name`**, **`uids`** or **`uid_range`**, **`command`** — Command is the executable (first arg after sudo); matching supports suffix (e.g. `sh` matches `/bin/sh`).
- **`deadline`** — Max runtime, e.g. `30s`, `5m`, `1h`.
- **`action`** — Same as immediate rules (signal, kill_children, log).

Matching invocations are tracked; they are killed only when the deadline is exceeded. Tracking is cleared when the process exits (USER_END or process no longer exists) or when the deadline passes (after verifying the PID by start time).

## Run

```bash
sudo sudo-sentinel [/path/to/config.toml]
```

Send **SIGTERM** or **SIGINT** for a clean shutdown (audit rule removed on exit).

## Testing in a container

See **TEST-RHEL8-CONTAINER.md** for building and running in a RHEL8-compatible container with the right capabilities.

## Limitations

- Only **sudo** is monitored (not `su`, `run0`, or other privilege escalation).
- Only known sudo paths are recognized: `/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo` (see `event.rs`).
- Runs in the audit/PAM context of the host (or container); processes in other namespaces may not be visible.
- Root can stop the daemon or change config; this is a policy layer and not root-proof.
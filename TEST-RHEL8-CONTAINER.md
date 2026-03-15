# Testing sudo-sentinel in a RHEL8 container

sudo-sentinel uses the **Linux Audit (netlink)** subsystem. The container must run with the capabilities needed for audit and for killing processes.

## 1. Build the image

From the project root (where `Cargo.toml` and this Dockerfile live):

```bash
podman build -f Dockerfile.rhel8 -t sudo-sentinel-test .
# or
docker build -f Dockerfile.rhel8 -t sudo-sentinel-test .
```

If you don’t have `Cargo.lock`, the build will still work; remove `Cargo.lock*` from the Dockerfile `COPY` line if it fails.

## 2. Run the container with required capabilities

The daemon needs **CAP_AUDIT_CONTROL**, **CAP_AUDIT_WRITE**, **CAP_NET_ADMIN**, and **CAP_KILL**. Run in the foreground so you see logs:

```bash
podman run --rm -it \
  --cap-add=CAP_AUDIT_CONTROL \
  --cap-add=CAP_AUDIT_WRITE \
  --cap-add=CAP_NET_ADMIN \
  --cap-add=CAP_KILL \
  --name sudo-sentinel-test \
  sudo-sentinel-test
```

With Docker:

```bash
docker run --rm -it \
  --cap-add=CAP_AUDIT_CONTROL \
  --cap-add=CAP_AUDIT_WRITE \
  --cap-add=CAP_NET_ADMIN \
  --cap-add=CAP_KILL \
  --name sudo-sentinel-test \
  sudo-sentinel-test
```

If audit still doesn’t work (e.g. “Failed to open NETLINK_AUDIT socket”), try running **privileged** once to confirm behavior:

```bash
podman run --rm -it --privileged --name sudo-sentinel-test sudo-sentinel-test
```

## 3. Trigger sudo in another terminal

In a second terminal, exec into the same container and run sudo so the sentinel can see it:

```bash
podman exec -it sudo-sentinel-test bash
# inside container:
sudo id
sudo cat /etc/hosts
```

Or one-liner:

```bash
podman exec -it sudo-sentinel-test sudo id
```

In the first terminal you should see sudo-sentinel log the event and, if a rule matches, take action (e.g. kill the process).

## 4. Test with a matching rule

The included `config.toml` has rules such as:

- **block-contractors**: UIDs 2000–2999 → SIGKILL
- **block-editing-sudoers**: args containing `/etc/sudoers` → SIGKILL
- **block-specific-uids**: UIDs 1042, 1099 → SIGKILL
- **block-headless-sudo**: no TTY and not root → SIGTERM

Examples:

```bash
# Run as a “contractor” UID (should be killed if rule is active)
podman exec -it sudo-sentinel-test su -s /bin/bash user2000 -c "sudo id"   # if user2000 has uid 2000

# Or run sudo with args that match “block-editing-sudoers”
podman exec -it sudo-sentinel-test sudo cat /etc/sudoers
```

Adjust `config.toml` or add test users (e.g. `useradd -u 2000 user2000`) in the image to match the rules you want to test.

## 5. Run as a systemd service (optional)

To test the unit file inside the container, use a systemd-capable base and run the service:

- Use an image that runs systemd (e.g. `registry.access.redhat.com/ubi8/ubi-init` or a custom image with systemd).
- Copy `sudo-sentinel.service` to `/etc/systemd/system/`, run `systemctl daemon-reload`, then `systemctl start sudo-sentinel`.

For a quick functional test, running the binary in the foreground (step 2) is enough.

## Requirements

- **Host**: RHEL8 (or another distro with a kernel that has `CONFIG_AUDIT=y` and netlink audit support).
- **Container runtime**: Podman or Docker with support for `--cap-add` (and optionally `--privileged` for debugging).

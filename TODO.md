# TODO — Future Features

Feature ideas to enhance TunnelDeck beyond the MVP. Each item lists
what it is, why it matters, and a rough shape of the implementation.
None of these are urgent bugs — those go in issues/commits, not here.

## CLI

### `tunneldeck update`

Self-update to the latest GitHub release.

- Check `https://api.github.com/repos/<owner>/tunneldeck/releases/latest`
  for the newest `tag_name`.
- If current `main.version` is older: download the matching
  `tunneldeck-linux-<arch>` asset, verify against `SHA256SUMS.txt`,
  atomically replace `/usr/local/bin/tunneldeck`, `systemctl restart
  tunneldeck`.
- Safety: keep previous binary as `tunneldeck.old` for rollback;
  `tunneldeck rollback` command to swap back.
- Optional: `--check` flag prints "update available: v0.2.0" without
  doing anything. Useful for a dashboard banner.

### `tunneldeck backup` / `tunneldeck restore`

Dump SQLite state + current managed nft table to a tarball so the user
can move/restore the gateway.

- `backup --out <file>.tar.gz` → DB snapshot + rendered nft + wg0.conf.
- `restore <file>.tar.gz --dry-run` → show diff, don't apply.

### `tunneldeck doctor --fix`

Offer to fix the simple issues it finds (enable ip_forward, add missing
sysctl line, install missing packages) after explicit confirmation.

## Web UI

### First-run setup wizard

Instead of printing the admin password in the log, redirect to a
`/setup` page on first boot that lets the user set their own password
(single-use, auto-disabled once a user exists). The current random
password is fine as a bootstrap but puts friction on non-technical
users.

### Password change / user management

Currently there's one admin user created at install. Add:
- `/settings/account` to change password.
- Optional read-only "viewer" role for status dashboards.

### Reverse-proxy friendly mode

For users who want to expose the UI under their own domain behind
Caddy/Traefik/nginx:
- Opt-in setting to trust `X-Forwarded-For` / `X-Forwarded-Proto`.
- Subpath support (`/tunneldeck/` prefix).
- Setting for "my public URL" so redirects and cookies work right.

### Web UI dark/light toggle

Tailwind already set up for dark. Light mode for preference.

### Active connections viewer (conntrack)

For each enabled forward, show live connection count and recent source
IPs via `conntrack -L`. Useful for seeing Minecraft players or attackers.

- Poll every N seconds, render into Forwards page.
- Filter: only connections touching managed nft table.

### Traffic graph

Per-forward and per-node packet/byte counters over time. nft counters
already exist; just need to sample + render a small sparkline.

### Debug tcpdump capture

Button "Start capture (30s)" on a forward. Runs `tcpdump -i <wan> -w
<tmp> port <N>` bounded by time, returns a summary + downloadable pcap.

## Node management

### Auto-join flow

Currently adding a node = manual wg0.conf paste. Improve to:
- User clicks "Add node" → gets a one-time token.
- Node installs agent (`tunneldeck-agent`) that generates its keypair
  locally, POSTs public key to gateway over HTTPS with the token.
- Gateway adds peer via `wg set`, persists to wg0.conf, node downloads
  its finished wg0.conf.
- Zero private key transmission.

### Node health checks

TCP dial / ICMP ping from gateway to node WG IP. Show latency
sparkline in Nodes list. Alert threshold when a forward target doesn't
respond.

### Per-node bandwidth limit

Optional `tc`-based rate limiting per node. Protect gateway bandwidth
from runaway nodes.

## Forwards

### Per-forward source-IP allowlist

Allow the user to restrict a forward to specific source networks
(e.g. only Cloudflare IPs, only my home IP). Rendered as an extra
`ip saddr @<set>` in the nft rule.

### Forward groups / templates

Minecraft server, SSH relay, generic web — preset templates that create
multiple related forwards at once with sensible defaults.

### Scheduled enable/disable

Turn a forward on only between 18:00–23:00 local time. Useful for
hobby game servers that don't need to be public 24/7.

## Observability

### Prometheus metrics endpoint

`/metrics` (behind auth) exposing: forwards count, per-forward pkt/byte
counters, per-peer handshake age, wg rx/tx, login-attempt counters.

### Alerting

Webhook on events: node offline > N minutes, forward counter drops to
zero while enabled, login brute-force, nft apply failure.

## Security hardening

### TLS out of the box

Automatic self-signed cert or Let's Encrypt via embedded
`autocert.Manager`. Trade-off: Let's Encrypt needs port 80/443 on the
gateway, which the user may already have NAT'd.

### 2FA

TOTP for admin login. `otp.Key` + QR code at `/settings/account/2fa`.

### Audit log UI

Currently a plain table. Add filtering by actor/action/date-range and
CSV export.

## Installer

### Upgrade path

When install.sh detects an existing install:
- If binary version differs: prompt "Update from vX.Y.Z → vA.B.C?"
- If /etc/tunneldeck/settings has changed schema: run migrations.
- If systemd unit changed: show diff, let user accept.

### Non-systemd systems

Support OpenRC (Alpine) and runit (Void). Same template, different
service definition.

## Platform

### Multiple gateway support

Federate multiple gateways: `tunneldeck-gateway-us`, `tunneldeck-gateway-sg`.
UI shows all; forwards can be assigned to specific gateways. v1.0-level.

### Docker image

`ghcr.io/<owner>/tunneldeck:vX.Y.Z`. Useful for users who run
everything in containers. Note: needs `--cap-add=NET_ADMIN` + host
network mode because nft needs real kernel access.

## Docs

### Video walkthrough

Screen recording of adopt flow end-to-end on a real Biznet-style VPS.

### Troubleshooting page

Common issues + fixes: `ERR_CONNECTION_REFUSED` (UI bind), SSH timeout
after forward (wrong port), nft apply fails (conflicting table name).

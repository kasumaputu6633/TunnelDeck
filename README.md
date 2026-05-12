# TunnelDeck

Self-hosted control plane for a WireGuard + nftables DNAT gateway.

Route public traffic from a VPS to home/backend servers through a WireGuard tunnel, with port forwards managed from a web UI. The data plane stays in the Linux kernel (nftables DNAT → WireGuard) so latency stays low enough for game servers.

**Status:** v0.1.1 — actively developed, not yet production-hardened.

## What it does

- **Gateway**: the public VPS. Owns WireGuard server, nftables DNAT, web UI, SQLite DB.
- **Node**: a home/backend server connected to the gateway over WireGuard. No public IP needed. Works on Linux, macOS, Windows, or any device with a WireGuard client.
- **Forward**: a rule mapping `gateway_public:port` → `node_wg_ip:port` via nftables DNAT.

TunnelDeck is **only the control plane**. Traffic never goes through the Go process.

## Install

Download the script and run it interactively — the installer detects your host state, recommends a mode, and asks where to bind the Web UI:

```bash
curl -fsSL https://github.com/kasumaputu6633/tunneldeck/releases/latest/download/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

Or non-interactive (CI / automation):

```bash
# existing WireGuard/nftables setup? import it safely
curl -fsSL https://github.com/kasumaputu6633/tunneldeck/releases/latest/download/install.sh \
  | sudo bash -s -- --adopt

# clean VPS? let the installer set everything up
curl -fsSL https://github.com/kasumaputu6633/tunneldeck/releases/latest/download/install.sh \
  | sudo bash -s -- --fresh

# just look, never write
curl -fsSL https://github.com/kasumaputu6633/tunneldeck/releases/latest/download/install.sh \
  | sudo bash -s -- --monitor-only
```

The `curl | bash` pattern can't prompt interactively (stdin is the curl pipe, not your terminal), so you need to pass the mode flag up front.

## First login

After install, open `http://<your-vps-ip>:9443` (or use an SSH tunnel if you chose localhost bind).

The login page shows the default credentials:

```
username: admin
password: tunneldeck
```

You will be prompted to change your password immediately after the first login. The credentials file at `/etc/tunneldeck/credentials` is deleted automatically once you set a new password.

## After install — adopt the existing setup

The `--adopt` flag at install time only enables pre-install file backups. The actual import of your existing WireGuard peers and nftables DNAT rules happens through the Web UI so you can review what will be imported first.

Once logged in:

1. Open the **Inspect** page. You'll see detected peers, nft tables, and DNAT rules.
2. Verify the list matches what you expect.
3. Under **Adopt & manage**, pick `reuse existing table` (recommended when DNAT rules are detected) and click the orange **Adopt & manage** button.
4. Dashboard will switch to `MODE: ADOPTED`; Nodes and Forwards pages will populate from the imported state.

## Accessing the Web UI

The installer asks where to bind the Web UI:

**Option A — localhost only (recommended):**

```bash
ssh -L 9443:127.0.0.1:9443 user@your-vps
# then open http://127.0.0.1:9443 in your laptop's browser
# keep the SSH window open while you use the UI
```

**Option B — public bind (simpler, no TLS):**

Choose `0.0.0.0` during install, or edit the systemd unit afterward:

```bash
sudo sed -i 's|--bind 127.0.0.1|--bind 0.0.0.0|' /etc/systemd/system/tunneldeck.service
sudo systemctl daemon-reload
sudo systemctl restart tunneldeck
```

Then open `http://<your-vps-ip>:9443`.

## Install modes

Two ways to run the installer:

1. **Interactive** (recommended when you have a TTY). Run `sudo ./install.sh` after downloading it. The installer inspects the host, prints a summary, recommends a mode, asks for bind address, and asks you to confirm.
2. **Non-interactive** (one-liners, CI, automation). Pass exactly one mode flag. Add `-y` / `--yes` to skip confirmation, or `--no-interactive` to fail instead of prompting.

Modes:

- `--fresh` — clean VPS, sets up WireGuard + nftables + systemd.
- `--adopt` — existing manual setup is detected, imported read-only, and only managed after you confirm in the Web UI.
- `--monitor-only` — detect and display, never modify.

## Setting up a node

TunnelDeck manages the **gateway** side only. The node (your home server, another VPS, or any Linux/macOS/Windows machine) joins WireGuard manually — but the Web UI gives you a pre-filled `wg0.conf` and the exact commands you need.

On the gateway (Web UI):

1. Go to **Nodes** → **Add node**, enter a name, click **Allocate & create**.
2. You'll be redirected to a setup page with per-OS instructions (Linux, macOS, Windows).
3. Generate a keypair on the node, paste the public key into the **Register peer** form — TunnelDeck runs `wg set` and appends to `wg0.conf` automatically. No SSH to the gateway required.
4. Bring up the tunnel on the node. The status widget on the setup page polls every 5s and flips green when the tunnel comes up.

## Self-update

Check for updates:

```bash
sudo tunneldeck update --check
```

Apply an update:

```bash
sudo tunneldeck update
```

Or click **Update now** in the Web UI banner that appears when a new version is available. The binary is downloaded, SHA256-verified, atomically swapped, and the service is restarted automatically.

## Web UI pages

| Page | Description |
|------|-------------|
| **Dashboard** | Gateway info, node/forward counts, WireGuard peer stats, recent audit log. Live-updates every 5s. |
| **Nodes** | List connected nodes with status, handshake, RX/TX. Add node with setup tutorial. |
| **Forwards** | Port forward rules with nft packet/byte counters. Pending-apply badge when DB and nft are out of sync. |
| **Inspect** | Read-only view of detected wg/nft state. Entry point for the Adopt flow. |
| **Logs** | Paginated audit log with human-readable action names. |
| **Doctor** | Visual checklist of gateway health (wg installed, ip_forward, nft tables, UFW, etc.). |
| **Settings** | Gateway config, bind address, managed nft table, change password. |

## Safety rules

- Never flushes the global nftables ruleset. Manages a dedicated table only.
- Always backs up `/etc/wireguard/wg0.conf` and `/etc/nftables.conf` before touching them.
- Validates every nft change with `nft -c -f` before applying.
- Flushes conntrack entries when a forward is disabled/deleted so active sessions actually drop.
- Binds the web UI to `127.0.0.1:9443` by default. Access via `ssh -L 9443:127.0.0.1:9443 user@vps`.
- Warns before forwarding protected ports (SSH, WG, UI, common DB ports).

## Stack

Go, SQLite (pure-Go driver), chi router, server-rendered templates + HTMX + Tailwind, systemd.

## CLI

```
tunneldeck serve              start the Web UI
tunneldeck update             self-update to latest release
tunneldeck update --check     check if an update is available
tunneldeck doctor             run diagnostic checks
tunneldeck inspect            print detected host state as JSON
tunneldeck status             one-line status for scripts
tunneldeck version            print version
```

## Install from source (developers)

```bash
git clone https://github.com/kasumaputu6633/tunneldeck
cd tunneldeck
GOOS=linux GOARCH=amd64 go build -o tunneldeck ./cmd/tunneldeck
scp tunneldeck scripts/install.sh user@your-vps:~/
ssh user@your-vps 'sudo bash install.sh --binary ./tunneldeck'
```

# TunnelDeck

Self-hosted control plane for a WireGuard + nftables DNAT gateway.

Route public traffic from a VPS to home/backend servers through a WireGuard tunnel, with port forwards managed from a web UI. The data plane stays in the Linux kernel (nftables DNAT → WireGuard) so latency stays low enough for game servers.

**Status:** MVP in development. Not yet production-ready.

## What it does

- **Gateway**: the public VPS. Owns WireGuard server, nftables DNAT, web UI, SQLite DB.
- **Node**: a home/backend server connected to the gateway over WireGuard. No public IP needed.
- **Forward**: a rule mapping `gateway_public:port` → `node_wg_ip:port` via nftables DNAT.

TunnelDeck is **only the control plane**. Traffic never goes through the Go process.

## Install

**On your VPS (gateway)** — pick the mode that matches your setup:

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

**Prefer an interactive prompt?** Download the script first, then run it:

```bash
curl -fsSL https://github.com/kasumaputu6633/tunneldeck/releases/latest/download/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer inspects the host, prints a summary, recommends a mode, and asks you to confirm. Either way, the binary is downloaded from the same GitHub release.

**From your laptop (connect to the UI):**

```bash
ssh -L 9443:127.0.0.1:9443 user@your-vps
# then open http://127.0.0.1:9443
```

The first-run admin password is printed once in the service log:

```bash
sudo journalctl -u tunneldeck | grep -A5 first-run
```

## After install — adopt the existing setup

The `--adopt` flag at install time only enables pre-install file backups and monitor-friendly defaults. The actual import of your existing WireGuard peers and nftables DNAT rules happens through the Web UI so you can review what will be imported first.

Once logged in:

1. Open the **Inspect** page. You'll see detected peers, nft tables, and DNAT rules.
2. Verify the list matches what you expect.
3. Under **Adopt & manage**, pick `reuse existing table` (recommended when DNAT rules are detected) and click the orange **Adopt & manage** button.
4. Dashboard will switch to `MODE: ADOPTED`; Nodes and Forwards pages will populate from the imported state.

## Accessing the Web UI from outside the VPS

The UI binds to `127.0.0.1:9443` by default. You have two options:

**Option A — SSH tunnel (recommended, no TLS needed):**

```bash
ssh -L 9443:127.0.0.1:9443 user@your-vps
# then open http://127.0.0.1:9443 in your laptop's browser
# keep the SSH window open while you use the UI
```

**Option B — public bind (simpler, but weaker without TLS):**

Edit the systemd unit and replace the bind address:

```bash
sudo sed -i 's|--bind 127.0.0.1|--bind 0.0.0.0|' /etc/systemd/system/tunneldeck.service
sudo systemctl daemon-reload
sudo systemctl restart tunneldeck
```

Then open `http://<your-vps-ip>:9443`. The UI is still protected by login, rate-limited, and CSRF-guarded — but HTTP traffic is unencrypted, so do this only if your VPS provider firewall allows 9443 and you're OK with bootstrap traffic being plaintext until TLS lands in a later release.

## Install modes

Two ways to run the installer:

1. **Interactive** (recommended when you have a TTY). Run `sudo ./install.sh` after downloading it. The installer inspects the host (wg interfaces, nft tables, DNAT rules, `wg0.conf`, `ip_forward`), prints a summary, recommends a mode, and asks you to confirm.
2. **Non-interactive** (one-liners, CI, automation). Pass exactly one mode flag. Add `-y` / `--yes` to skip the final confirmation, or `--no-interactive` to fail instead of prompting.

Modes:

- `--fresh` — clean VPS, sets up WireGuard + nftables + systemd.
- `--adopt` — existing manual setup is detected, imported read-only, and only managed after you confirm in the Web UI.
- `--monitor-only` — detect and display, never modify.

## Install from source (developers)

```bash
git clone https://github.com/kasumaputu6633/tunneldeck
cd tunneldeck
GOOS=linux GOARCH=amd64 go build -o tunneldeck ./cmd/tunneldeck
scp tunneldeck scripts/install.sh user@your-vps:~/
ssh user@your-vps 'sudo bash install.sh --binary ./tunneldeck'
```

## Safety rules

- Never flushes the global nftables ruleset. Manages a dedicated table only.
- Always backs up `/etc/wireguard/wg0.conf` and `/etc/nftables.conf` before touching them.
- Validates every nft change with `nft -c -f` before applying.
- Binds the web UI to `127.0.0.1:9443` by default. Access via `ssh -L 9443:127.0.0.1:9443 user@vps`.
- Warns before forwarding protected ports (SSH, WG, UI, common DB ports).

## Stack

Go, SQLite (pure-Go driver), chi router, server-rendered templates + HTMX + Tailwind, systemd.

## CLI

```
tunneldeck serve
tunneldeck doctor
tunneldeck inspect
tunneldeck adopt
tunneldeck status
```

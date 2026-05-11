#!/usr/bin/env bash
#
# TunnelDeck installer for Ubuntu/Debian gateways.
#
# Two ways to invoke:
#
#   1. Interactive (recommended for humans):
#         sudo bash install.sh
#      The script inspects wg/nft state on this host, prints a summary,
#      recommends a mode, and asks you to confirm.
#
#   2. Non-interactive (automation, CI, kickstart scripts):
#         sudo bash install.sh --fresh
#         sudo bash install.sh --adopt
#         sudo bash install.sh --monitor-only
#      Pass exactly one mode flag. --yes skips the final confirmation.
#      --no-interactive errors out if no mode flag was provided, for CI
#      where we must never block on a prompt.
#
# Modes:
#   --fresh         Clean VPS. Installs wg + nft, enables ip_forward,
#                   creates systemd unit. Starts in 'fresh' mode.
#   --adopt         VPS already has wg/nft configured. Detected state is
#                   imported read-only; you confirm Adopt in the Web UI
#                   before TunnelDeck writes anything.
#   --monitor-only  Read-only forever. TunnelDeck never writes nft/wg.
#
# Safety (all modes):
#   - Never runs `nft flush ruleset`.
#   - Never overwrites /etc/wireguard/wg0.conf.
#   - Backs up /etc/nftables.conf + /etc/wireguard/wg0.conf before install.
#   - UI binds to 127.0.0.1:9443 by default.

set -euo pipefail

# --- Defaults --------------------------------------------------------------

MODE=""
MODE_FROM_FLAG="no"
BIND_FROM_FLAG=""
BIND="127.0.0.1"
PORT="9443"
STATE_DIR="/var/lib/tunneldeck"
CONFIG_DIR="/etc/tunneldeck"
LOG_DIR="/var/log/tunneldeck"
BIN_PATH="/usr/local/bin/tunneldeck"
UNIT_PATH="/etc/systemd/system/tunneldeck.service"
BIN_SOURCE=""
RELEASE_TAG="${TUNNELDECK_RELEASE:-latest}"
RELEASE_REPO="${TUNNELDECK_REPO:-kasumaputu6633/tunneldeck}"
ASSUME_YES="no"
ALLOW_INTERACTIVE="yes"

# --- Flag parsing ----------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fresh)          MODE="fresh"; MODE_FROM_FLAG="yes"; shift ;;
        --adopt)          MODE="adopt"; MODE_FROM_FLAG="yes"; shift ;;
        --monitor-only)   MODE="monitor-only"; MODE_FROM_FLAG="yes"; shift ;;
        --bind)           BIND="$2"; BIND_FROM_FLAG="yes"; shift 2 ;;
        --port)           PORT="$2"; shift 2 ;;
        --binary)         BIN_SOURCE="$2"; shift 2 ;;
        --release)        RELEASE_TAG="$2"; shift 2 ;;
        --repo)           RELEASE_REPO="$2"; shift 2 ;;
        -y|--yes)         ASSUME_YES="yes"; shift ;;
        --no-interactive) ALLOW_INTERACTIVE="no"; shift ;;
        -h|--help)
            sed -n '1,40p' "$0"
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (use sudo)" >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "error: /etc/os-release missing; this script targets Ubuntu/Debian" >&2
    exit 1
fi
. /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) echo "warning: unsupported distro '$ID'; continuing best-effort" ;;
esac

# --- Detection -------------------------------------------------------------

# Fills these globals: HAS_WG_BIN, HAS_NFT_BIN, WG_IFACES, WG_PEERS_COUNT,
# NFT_TABLES_COUNT, NFT_DNAT_COUNT, WG_CONF_PRESENT, IP_FORWARD,
# RECOMMENDED_MODE, RECOMMEND_REASON.
detect_state() {
    HAS_WG_BIN="no"; command -v wg  >/dev/null 2>&1 && HAS_WG_BIN="yes"
    HAS_NFT_BIN="no"; command -v nft >/dev/null 2>&1 && HAS_NFT_BIN="yes"

    WG_IFACES=""
    WG_PEERS_COUNT=0
    if [[ "$HAS_WG_BIN" == "yes" ]]; then
        WG_IFACES=$(wg show interfaces 2>/dev/null | tr '\n' ' ' | sed 's/ $//' || true)
        if [[ -n "$WG_IFACES" ]]; then
            # Count peer lines across all interfaces (each peer block starts "peer:")
            WG_PEERS_COUNT=$(wg show all 2>/dev/null | grep -c '^peer:' || true)
        fi
    fi

    NFT_TABLES_COUNT=0
    NFT_DNAT_COUNT=0
    if [[ "$HAS_NFT_BIN" == "yes" ]]; then
        NFT_TABLES_COUNT=$(nft list tables 2>/dev/null | wc -l | tr -d ' ')
        NFT_DNAT_COUNT=$(nft list ruleset 2>/dev/null | grep -c 'dnat to ' || true)
    fi

    WG_CONF_PRESENT="no"
    [[ -f /etc/wireguard/wg0.conf ]] && WG_CONF_PRESENT="yes"

    IP_FORWARD="0"
    [[ -r /proc/sys/net/ipv4/ip_forward ]] && IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)

    # Decide recommendation. "Existing setup" = at least one of:
    # live wg peers, detected DNAT rules, or wg0.conf on disk.
    if (( WG_PEERS_COUNT > 0 )) || (( NFT_DNAT_COUNT > 0 )) || [[ "$WG_CONF_PRESENT" == "yes" ]]; then
        RECOMMENDED_MODE="adopt"
        RECOMMEND_REASON="existing wg/nft state detected — adopt preserves and imports it safely"
    else
        RECOMMENDED_MODE="fresh"
        RECOMMEND_REASON="no existing wg/nft state detected — fresh install is safe"
    fi
}

print_detection_summary() {
    cat <<EOF

=== Host state summary ===
  wg binary:         ${HAS_WG_BIN}
  nft binary:        ${HAS_NFT_BIN}
  wg interfaces:     ${WG_IFACES:-<none>}
  wg peers (live):   ${WG_PEERS_COUNT}
  nft tables:        ${NFT_TABLES_COUNT}
  nft DNAT rules:    ${NFT_DNAT_COUNT}
  /etc/wireguard/wg0.conf present: ${WG_CONF_PRESENT}
  ip_forward:        ${IP_FORWARD}

Recommended mode:    ${RECOMMENDED_MODE}
Reason:              ${RECOMMEND_REASON}
EOF
}

# Prompt the user to pick a mode. Sets $MODE.
choose_mode_interactive() {
    echo
    echo "Choose install mode:"
    echo "  1) adopt          (recommended when existing wg/nft is detected)"
    echo "  2) fresh          (clean VPS — installs and configures everything)"
    echo "  3) monitor-only   (read-only forever, never writes nft/wg changes)"
    echo "  q) quit"
    echo
    local default="1"
    [[ "$RECOMMENDED_MODE" == "fresh" ]] && default="2"

    local choice
    read -r -p "Selection [${default}]: " choice || true
    choice="${choice:-$default}"

    case "$choice" in
        1|adopt)         MODE="adopt" ;;
        2|fresh)         MODE="fresh" ;;
        3|monitor-only)  MODE="monitor-only" ;;
        q|quit)          echo "aborted."; exit 0 ;;
        *) echo "unrecognized choice: $choice" >&2; exit 2 ;;
    esac
}

# Prompt the user to choose where the Web UI binds.
# Skipped when --bind was passed explicitly or when stdin isn't a TTY.
choose_bind_interactive() {
    [[ -n "$BIND_FROM_FLAG" ]] && return 0
    [[ ! -t 0 ]] && return 0
    [[ "$ASSUME_YES" == "yes" ]] && return 0

    echo
    echo "Where should the Web UI listen?"
    echo "  1) 127.0.0.1:${PORT}  — localhost only (recommended)"
    echo "     Access via: ssh -L ${PORT}:127.0.0.1:${PORT} <user>@<this-host>"
    echo "  2) 0.0.0.0:${PORT}    — all interfaces (accessible from your browser directly)"
    echo "     WARNING: the UI will be reachable on the public IP without TLS."
    echo "     Only choose this if you understand the risk or are behind a firewall."
    echo
    local choice
    read -r -p "Selection [1]: " choice || true
    choice="${choice:-1}"

    case "$choice" in
        1|localhost|127*) BIND="127.0.0.1" ;;
        2|0.0.0.0|public) BIND="0.0.0.0" ;;
        *) echo "unrecognized choice, defaulting to 127.0.0.1"; BIND="127.0.0.1" ;;
    esac
}

# Confirm before running a destructive mode. Skipped for monitor-only,
# when -y was passed, when stdin isn't a TTY (curl|bash can't prompt),
# or when the mode was passed explicitly via CLI flag — an explicit flag
# is itself the user's confirmation.
confirm_mode() {
    [[ "$ASSUME_YES" == "yes" ]] && return 0
    [[ "$MODE" == "monitor-only" ]] && return 0
    [[ "$MODE_FROM_FLAG" == "yes" ]] && return 0
    [[ ! -t 0 ]] && return 0

    local warn=""
    if [[ "$MODE" == "fresh" ]]; then
        if (( WG_PEERS_COUNT > 0 )) || (( NFT_DNAT_COUNT > 0 )) || [[ "$WG_CONF_PRESENT" == "yes" ]]; then
            warn="WARNING: existing wg/nft state was detected, but you selected 'fresh'.
The installer itself will NOT flush your rules or overwrite wg0.conf, but
once TunnelDeck runs it will manage its own nftables table and assume a
clean slate. 'adopt' is safer if you want to keep the existing setup."
        fi
    fi
    if [[ -n "$warn" ]]; then
        echo
        echo "$warn"
    fi

    local reply
    read -r -p "Proceed with mode '${MODE}'? [y/N] " reply || true
    case "${reply:-N}" in
        y|Y|yes|YES) return 0 ;;
        *) echo "aborted."; exit 0 ;;
    esac
}

# --- Resolve mode ---------------------------------------------------------

detect_state
print_detection_summary

if [[ -z "$MODE" ]]; then
    if [[ "$ALLOW_INTERACTIVE" != "yes" ]]; then
        echo "error: no mode flag given and --no-interactive was set." >&2
        echo "       pass one of --fresh, --adopt, --monitor-only." >&2
        exit 2
    fi
    if [[ ! -t 0 ]]; then
        # Stdin isn't a TTY (e.g. `curl | bash`). Refuse to guess silently.
        echo "error: not running on a TTY; pass a mode flag (--fresh/--adopt/--monitor-only) or use --yes with one." >&2
        exit 2
    fi
    choose_mode_interactive
fi

confirm_mode
choose_bind_interactive

# --- Install --------------------------------------------------------------

echo "=> installing dependencies (only missing packages)"
# NOTE: any command the TunnelDeck binary shells out to at runtime must be
# listed here. Current call sites (internal/*/*.go → sysexec.Runner.Run):
#   wg, wg-quick          → wireguard, wireguard-tools
#   nft                   → nftables
#   conntrack             → conntrack (needed to flush sessions on forward
#                           disable/delete so existing flows actually drop)
#   ip                    → iproute2
#   ping                  → iputils-ping
#   curl (install only)   → typically preinstalled; ca-certificates for TLS
# If you add a new runtime command, add its package here too.
REQUIRED=(wireguard wireguard-tools nftables conntrack iproute2 iputils-ping ca-certificates)
MISSING=()
for p in "${REQUIRED[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
        MISSING+=("$p")
    fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    apt-get update -qq
    # DEBIAN_FRONTEND=noninteractive suppresses needrestart and other
    # interactive prompts that can hang or exit non-zero in CI/scripts.
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${MISSING[@]}" || true
else
    echo "   all required packages already installed"
fi

echo "=> creating directories"
install -d -m 0750 "$STATE_DIR" "$CONFIG_DIR" "$LOG_DIR" "$STATE_DIR/backups"

if [[ "$MODE" == "fresh" ]]; then
    echo "=> enabling net.ipv4.ip_forward=1"
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi

# Pre-install backup of any file TunnelDeck might later manage.
TS=$(date -u +%Y%m%dT%H%M%SZ)
if [[ -f /etc/nftables.conf ]]; then
    cp -a /etc/nftables.conf "$STATE_DIR/backups/${TS}-nftables.conf"
fi
if [[ -f /etc/wireguard/wg0.conf ]]; then
    cp -a /etc/wireguard/wg0.conf "$STATE_DIR/backups/${TS}-wg0.conf"
fi
echo "   pre-install backups at $STATE_DIR/backups"

echo "=> installing binary"
if [[ -n "$BIN_SOURCE" ]]; then
    install -m 0755 "$BIN_SOURCE" "$BIN_PATH"
elif [[ -x "./tunneldeck" ]]; then
    install -m 0755 "./tunneldeck" "$BIN_PATH"
else
    # Fall back to downloading from GitHub releases. This is the path the
    # `curl | sudo bash` one-liner uses.
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ASSET="tunneldeck-linux-amd64" ;;
        aarch64|arm64) ASSET="tunneldeck-linux-arm64" ;;
        *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    if [[ "$RELEASE_TAG" == "latest" ]]; then
        URL="https://github.com/${RELEASE_REPO}/releases/latest/download/${ASSET}"
    else
        URL="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_TAG}/${ASSET}"
    fi

    echo "   downloading ${URL}"
    TMPBIN=$(mktemp)
    trap 'rm -f "$TMPBIN"' EXIT
    if ! curl -fsSL "$URL" -o "$TMPBIN"; then
        cat >&2 <<EOF
error: failed to download binary from ${URL}
       if you have the binary locally, pass --binary /path/to/tunneldeck
       or build from source: go build -o tunneldeck ./cmd/tunneldeck
EOF
        exit 1
    fi
    install -m 0755 "$TMPBIN" "$BIN_PATH"
fi

echo "=> writing systemd unit"
DRYNFT_FLAG=""
if [[ "$MODE" == "monitor-only" ]]; then
    DRYNFT_FLAG=" --dry-nft"
fi

cat > "$UNIT_PATH" <<EOF
[Unit]
Description=TunnelDeck control plane
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} serve --bind ${BIND} --port ${PORT} --state ${STATE_DIR}${DRYNFT_FLAG}
Restart=on-failure
RestartSec=2

# We need root for wg/nft. Tight process sandbox, but no user= drop,
# because those tools require CAP_NET_ADMIN.
ProtectSystem=strict
ReadWritePaths=${STATE_DIR} ${LOG_DIR} /etc/wireguard /etc/nftables.conf /usr/local/bin
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tunneldeck.service

# Grab the one-time admin password from the service log. On first boot
# TunnelDeck prints a "=== TunnelDeck first-run ===" block to stdout,
# which systemd captures. We retry for up to 15s because journald may
# take a moment to index the new unit's output.
ADMIN_PASSWORD=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    ADMIN_PASSWORD=$(journalctl -u tunneldeck.service --no-pager -n 50 2>/dev/null \
        | grep -oP '(?<=password: )[a-f0-9]+' | head -1)
    [[ -n "$ADMIN_PASSWORD" ]] && break
    sleep 1
done

echo
echo "=> done"
echo "   mode:        $MODE"
echo "   UI:          http://${BIND}:${PORT}"
if [[ "$BIND" == "127.0.0.1" || "$BIND" == "localhost" ]]; then
    echo "   tunnel in:   ssh -L ${PORT}:127.0.0.1:${PORT} <user>@<this-host>"
    echo "                then open http://127.0.0.1:${PORT} in your laptop's browser"
else
    echo "   WARNING:     UI is not bound to localhost. Ensure this address is not publicly reachable."
fi

if [[ -n "$ADMIN_PASSWORD" ]]; then
    echo
    echo "   ================ first-run admin credentials ================"
    echo "   username: admin"
    echo "   password: $ADMIN_PASSWORD"
    echo "   Save this now; it won't be displayed again."
    echo "   =============================================================="
else
    # Fallback if we couldn't read the log (service still starting, journald
    # not populated yet, custom logging setup, etc).
    echo "   admin password (if first run): journalctl -u tunneldeck | grep -A1 first-run"
fi

echo
if [[ "$MODE" == "adopt" ]]; then
    echo "   next: open the Web UI and visit /inspect to review detected state before clicking 'Adopt & manage'."
fi

// Package wgops applies WireGuard peer changes to a running interface and
// persists them to wg0.conf with a pre-write backup.
//
// Adding a peer:
//   1. Validate the public key looks well-formed.
//   2. `wg set <iface> peer <pubkey> allowed-ips <ip>/32 persistent-keepalive <N>`
//      — takes effect immediately, no interface restart.
//   3. Append a `[Peer]` block to /etc/wireguard/<iface>.conf so the peer
//      survives a reboot. The file is timestamp-backed up first.
package wgops

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

// AddPeerInput is what RegisterNodePeer needs.
type AddPeerInput struct {
	Iface       string // e.g. "wg0"
	ConfPath    string // /etc/wireguard/<iface>.conf
	BackupDir   string
	NodeName    string
	NodeWGIP    string // "10.66.66.2" (no mask)
	PublicKey   string
	Keepalive   int
}

type AddPeerResult struct {
	BackupPath string
}

// RegisterNodePeer performs both the runtime `wg set` and the persistent
// wg0.conf append. If either step fails, the other is attempted to be
// rolled back so the gateway doesn't end up in a half-configured state.
func RegisterNodePeer(ctx context.Context, runner sysexec.Runner, in AddPeerInput) (AddPeerResult, error) {
	if err := ValidatePublicKey(in.PublicKey); err != nil {
		return AddPeerResult{}, err
	}
	if in.Iface == "" {
		return AddPeerResult{}, errors.New("iface is required")
	}
	if in.NodeWGIP == "" {
		return AddPeerResult{}, errors.New("node WG IP is required")
	}
	if in.Keepalive <= 0 {
		in.Keepalive = 25
	}

	// 1) runtime: wg set
	args := []string{
		"set", in.Iface,
		"peer", in.PublicKey,
		"allowed-ips", in.NodeWGIP + "/32",
		"persistent-keepalive", fmt.Sprintf("%d", in.Keepalive),
	}
	if r := runner.Run(ctx, "wg", args, ""); r.Err != nil || r.ExitCode != 0 {
		return AddPeerResult{}, fmt.Errorf("wg set failed (exit=%d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}

	// 2) persist: append to wg0.conf (after backup)
	res := AddPeerResult{}
	if in.ConfPath != "" {
		backup, err := backupFile(in.ConfPath, in.BackupDir, "wg0.conf")
		if err != nil {
			// Runtime peer is live but we failed to persist — remove the
			// runtime peer so state doesn't drift on reboot.
			_ = runner.Run(ctx, "wg", []string{"set", in.Iface, "peer", in.PublicKey, "remove"}, "")
			return AddPeerResult{}, fmt.Errorf("backup wg0.conf: %w", err)
		}
		res.BackupPath = backup
		block := renderPeerBlock(in)
		if err := appendToFile(in.ConfPath, block); err != nil {
			_ = runner.Run(ctx, "wg", []string{"set", in.Iface, "peer", in.PublicKey, "remove"}, "")
			return AddPeerResult{}, fmt.Errorf("append to wg0.conf: %w", err)
		}
	}
	return res, nil
}

// ValidatePublicKey checks that the string looks like a WireGuard public key:
// 32 bytes, base64-encoded = exactly 44 characters ending in '='.
func ValidatePublicKey(k string) error {
	k = strings.TrimSpace(k)
	if len(k) != 44 || !strings.HasSuffix(k, "=") {
		return errors.New("not a valid WireGuard public key (expected 44-char base64 ending in '=')")
	}
	decoded, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(decoded) != 32 {
		return errors.New("public key decodes to wrong length (expected 32 bytes)")
	}
	return nil
}

func renderPeerBlock(in AddPeerInput) string {
	return fmt.Sprintf("\n[Peer]\n# tunneldeck:node=%s\nPublicKey = %s\nAllowedIPs = %s/32\nPersistentKeepalive = %d\n",
		in.NodeName, in.PublicKey, in.NodeWGIP, in.Keepalive)
}

func backupFile(path, backupDir, label string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil // nothing to back up, file will be created
		}
		return "", err
	}
	if err := os.MkdirAll(backupDir, 0o750); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dst := filepath.Join(backupDir, fmt.Sprintf("%s-%s", stamp, label))
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return "", err
	}
	return dst, nil
}

func appendToFile(path, body string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(body)
	return err
}
// Package adopt turns an inspect.Report into DB state that TunnelDeck will
// manage. Always call this behind an explicit user confirmation; it writes
// timestamped backups of /etc/wireguard/wg0.conf and the pre-existing
// nftables ruleset before anything else.
package adopt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/inspect"
	"github.com/kasumaputu6633/tunneldeck/internal/nft"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

type Options struct {
	BackupDir  string
	PublicIP   string
	Actor      string
	WGConfPath string
	// NFTStrategy:
	//   "reuse"  — manage the existing table name (e.g. wg_dnat).
	//   "switch" — create our own table; user removes the old one manually.
	NFTStrategy string
}

type Result struct {
	BackedUp         []string
	NodesImported    int
	ForwardsImported int
	ManagedTable     string
	Warnings         []string
}

type Runner struct {
	DB       *db.DB
	Runner   sysexec.Runner
	ReadFile func(string) ([]byte, error)
}

// Run performs the adoption. Partial writes are safe on retry because
// nodes.wg_ip and forwards(proto, public_port) are UNIQUE in the DB.
func (r Runner) Run(ctx context.Context, rep inspect.Report, opt Options) (Result, error) {
	if r.DB == nil {
		return Result{}, errors.New("adopt: DB is nil")
	}
	if opt.BackupDir == "" {
		return Result{}, errors.New("adopt: BackupDir required")
	}
	if err := os.MkdirAll(opt.BackupDir, 0o750); err != nil {
		return Result{}, fmt.Errorf("mkdir backup: %w", err)
	}

	res := Result{}

	wgConfPath := opt.WGConfPath
	if wgConfPath == "" {
		wgConfPath = rep.WGConfPath
	}
	if wgConfPath == "" {
		wgConfPath = "/etc/wireguard/wg0.conf"
	}
	if r.ReadFile != nil {
		if b, err := r.ReadFile(wgConfPath); err == nil {
			p, err := r.backup(ctx, opt.BackupDir, "wg0.conf", b)
			if err == nil {
				res.BackedUp = append(res.BackedUp, p)
			} else {
				res.Warnings = append(res.Warnings, "wg0.conf backup failed: "+err.Error())
			}
		}

		if b, err := r.ReadFile("/etc/nftables.conf"); err == nil {
			p, err := r.backup(ctx, opt.BackupDir, "nftables.conf", b)
			if err == nil {
				res.BackedUp = append(res.BackedUp, p)
			} else {
				res.Warnings = append(res.Warnings, "nftables.conf backup failed: "+err.Error())
			}
		}
	}

	for _, pt := range rep.NFTDetected {
		raw := renderParsedForLog(pt)
		if p, err := r.backup(ctx, opt.BackupDir, "nft-"+pt.Name+".txt", []byte(raw)); err == nil {
			res.BackedUp = append(res.BackedUp, p)
		}
	}

	g, err := r.DB.GetGateway(ctx)
	if err != nil {
		return res, fmt.Errorf("get gateway: %w", err)
	}
	if rep.WGPrimary != "" {
		g.WGIf = rep.WGPrimary
	}
	if rep.WGGatewayIP != "" {
		g.WGIP = rep.WGGatewayIP
	}
	if rep.WGListenPort != 0 {
		g.WGPort = rep.WGListenPort
	}
	if rep.WGPublicKey != "" {
		g.WGPublicKey = rep.WGPublicKey
	}
	if rep.DefaultWANIf != "" {
		g.WANIf = rep.DefaultWANIf
	}
	// Opt.PublicIP (from the form) wins; otherwise fall back to whatever
	// inspect guessed from `ip addr show`. Only overwrite the stored value
	// if we actually have something — don't blank out a previously-set IP.
	if opt.PublicIP != "" {
		g.PublicIP = opt.PublicIP
	} else if g.PublicIP == "" && rep.PublicIPGuess != "" {
		g.PublicIP = rep.PublicIPGuess
	}

	switch opt.NFTStrategy {
	case "switch":
	case "reuse", "":
		if t := pickLargestNFTTable(rep.NFTDetected); t != "" {
			g.ManagedNFTTable = t
		}
	}
	res.ManagedTable = g.ManagedNFTTable

	now := time.Now()
	g.AdoptMode = "adopted"
	g.AdoptConfirmedAt = &now
	if err := r.DB.UpdateGateway(ctx, g); err != nil {
		return res, fmt.Errorf("update gateway: %w", err)
	}

	nodesByIP := map[string]int64{}
	for _, p := range rep.WGPeers {
		hostIP := firstHost(p.AllowedIPs)
		if hostIP == "" {
			continue
		}
		if n, err := r.DB.GetNodeByWGIP(ctx, hostIP); err == nil {
			nodesByIP[hostIP] = n.ID
			continue
		}
		name := fmt.Sprintf("adopted-%s", strings.ReplaceAll(hostIP, ".", "-"))
		id, err := r.DB.CreateNode(ctx, db.Node{
			Name:      name,
			WGIP:      hostIP,
			PublicKey: p.PublicKey,
			Keepalive: nonZero(p.PersistentKeepalive, 25),
			Adopted:   true,
		})
		if err != nil {
			res.Warnings = append(res.Warnings, "import peer "+hostIP+": "+err.Error())
			continue
		}
		nodesByIP[hostIP] = id
		res.NodesImported++
	}

	for _, pt := range rep.NFTDetected {
		for _, pf := range pt.Forwards {
			nodeID, ok := nodesByIP[pf.TargetIP]
			if !ok {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("skipped %s/%d → %s:%d (no matching wg peer)",
						pf.Proto, pf.PublicPort, pf.TargetIP, pf.TargetPort))
				continue
			}
			name := fmt.Sprintf("adopted-%s-%d", pf.Proto, pf.PublicPort)
			_, err := r.DB.CreateForward(ctx, db.Forward{
				Name:       name,
				Proto:      pf.Proto,
				PublicPort: pf.PublicPort,
				NodeID:     nodeID,
				TargetPort: pf.TargetPort,
				Enabled:    true,
				LogMode:    "counter",
			})
			if err != nil {
				if !strings.Contains(err.Error(), "UNIQUE") {
					res.Warnings = append(res.Warnings,
						fmt.Sprintf("import %s/%d: %s", pf.Proto, pf.PublicPort, err))
				}
				continue
			}
			res.ForwardsImported++
		}
	}

	detail := fmt.Sprintf(`{"nodes":%d,"forwards":%d,"managed_table":%q,"backups":%d}`,
		res.NodesImported, res.ForwardsImported, res.ManagedTable, len(res.BackedUp))
	_ = r.DB.AuditWrite(ctx, opt.Actor, "gateway.adopt", g.WGIf, detail)

	return res, nil
}

func (r Runner) backup(ctx context.Context, dir, label string, data []byte) (string, error) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	path := filepath.Join(dir, fmt.Sprintf("%s-%s", stamp, label))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if r.DB != nil {
		_ = r.DB.RecordSnapshot(ctx, "adopt:"+label, path, hex.EncodeToString(sum[:]), "adopt pre-write backup")
	}
	return path, nil
}

func pickLargestNFTTable(detected []nft.ParsedTable) string {
	best := ""
	bestN := 0
	for _, t := range detected {
		if n := len(t.Forwards); n > bestN {
			bestN = n
			best = t.Name
		}
	}
	return best
}

func firstHost(allowed []string) string {
	for _, a := range allowed {
		if i := strings.Index(a, "/"); i > 0 {
			return a[:i]
		}
		return a
	}
	return ""
}

func nonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func renderParsedForLog(pt nft.ParsedTable) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# parsed table %s %s\n", pt.Family, pt.Name)
	for _, f := range pt.Forwards {
		fmt.Fprintf(&b, "%s dport %d -> %s:%d\n", f.Proto, f.PublicPort, f.TargetIP, f.TargetPort)
	}
	for _, u := range pt.Unknown {
		fmt.Fprintf(&b, "unknown: %s\n", u)
	}
	return b.String()
}

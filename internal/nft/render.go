// Package nft renders and applies nftables rules scoped to a single managed
// table. It never flushes the global ruleset — rendered scripts recreate the
// managed table atomically via `delete table` + `table ...`, leaving every
// other table untouched.
package nft

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

// RenderSpec is derived from DB state by the caller.
type RenderSpec struct {
	TableName string
	WANIf     string
	WGIf      string
	WGSubnet  string
	Forwards  []db.Forward
}

// Render produces the nftables script body for the managed table.
// The script begins with `table ip X {}` (ensure exists) followed by
// `delete table ip X` and a fresh definition, so `nft -f` swaps atomically.
func Render(s RenderSpec) string {
	var b strings.Builder

	fmt.Fprintln(&b, "# TunnelDeck managed nftables table")
	fmt.Fprintln(&b, "# Only this table is touched; other tables are left alone.")
	fmt.Fprintln(&b, "#")
	fmt.Fprintf(&b, "table ip %s {}\n", s.TableName)
	fmt.Fprintf(&b, "delete table ip %s\n", s.TableName)
	fmt.Fprintf(&b, "table ip %s {\n", s.TableName)

	fmt.Fprintln(&b, "\tchain prerouting {")
	fmt.Fprintln(&b, "\t\ttype nat hook prerouting priority -100; policy accept;")
	for _, f := range sortedForwards(s.Forwards) {
		fmt.Fprintf(&b,
			"\t\tiifname \"%s\" %s dport %d counter dnat to %s:%d comment \"td:fwd=%d %s\"\n",
			s.WANIf, f.Proto, f.PublicPort, f.NodeWGIP, f.TargetPort, f.ID, sanitizeComment(f.Name),
		)
	}
	fmt.Fprintln(&b, "\t}")

	// postrouting masquerade ensures reply packets for DNATed sessions leave
	// via the wg interface with the gateway's source address.
	fmt.Fprintln(&b, "\tchain postrouting {")
	fmt.Fprintln(&b, "\t\ttype nat hook postrouting priority 100; policy accept;")
	if s.WGIf != "" && s.WGSubnet != "" {
		fmt.Fprintf(&b, "\t\toifname \"%s\" ip daddr %s counter masquerade comment \"td:masq\"\n", s.WGIf, s.WGSubnet)
	}
	fmt.Fprintln(&b, "\t}")

	fmt.Fprintln(&b, "}")
	return b.String()
}

// sortedForwards returns a deterministic order so rendered output is
// byte-stable, which matters for diffing snapshots.
func sortedForwards(in []db.Forward) []db.Forward {
	out := make([]db.Forward, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].PublicPort < out[j].PublicPort
	})
	return out
}

func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, `\`, "")
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

type Client struct {
	Runner sysexec.Runner
}

// Check runs `nft -c -f -` with script on stdin.
func (c Client) Check(ctx context.Context, script string) error {
	r := c.Runner.Run(ctx, "nft", []string{"-c", "-f", "-"}, script)
	if r.Err != nil || r.ExitCode != 0 {
		return fmt.Errorf("nft check failed (exit=%d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	return nil
}

// DumpTable runs `nft list table ip <name>`. Returns "" (no error) when the
// table doesn't exist, since some nft versions exit non-zero in that case.
func (c Client) DumpTable(ctx context.Context, table string) (string, error) {
	r := c.Runner.Run(ctx, "nft", []string{"list", "table", "ip", table}, "")
	if r.Err != nil && strings.Contains(strings.ToLower(r.Stderr), "no such") {
		return "", nil
	}
	if r.Err != nil || r.ExitCode != 0 {
		return "", fmt.Errorf("nft list failed (exit=%d): %s", r.ExitCode, strings.TrimSpace(r.Stderr))
	}
	return r.Stdout, nil
}

// ListRuleset returns the full ruleset for snapshot/backup.
func (c Client) ListRuleset(ctx context.Context) (string, error) {
	r := c.Runner.Run(ctx, "nft", []string{"list", "ruleset"}, "")
	if r.Err != nil || r.ExitCode != 0 {
		return "", fmt.Errorf("nft list ruleset failed: %s", strings.TrimSpace(r.Stderr))
	}
	return r.Stdout, nil
}

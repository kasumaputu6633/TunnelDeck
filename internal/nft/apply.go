package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

type ApplyInput struct {
	Spec      RenderSpec
	BackupDir string
	DB        *db.DB
	Actor     string
	DryRun    bool
}

type ApplyResult struct {
	Script       string
	BackupPath   string
	Applied      bool
	DryRun       bool
	CheckWarning string

	// Removed lists forwards that disappeared from the managed table in
	// this apply. Populated after a successful non-dry-run apply. Used to
	// drive conntrack flushing so existing game sessions / ssh tunnels on
	// a disabled forward actually get torn down.
	Removed []ParsedForward
	// FlushedConnections is the total number of conntrack entries we
	// removed across all ports in Removed. 0 if conntrack isn't installed
	// or there was nothing to flush.
	FlushedConnections int
}

// Apply renders, validates, snapshots, applies. On any failure after
// validation it attempts to restore from the pre-apply snapshot. With
// DryRun=true it stops after the check.
func (c Client) Apply(ctx context.Context, in ApplyInput) (ApplyResult, error) {
	res := ApplyResult{DryRun: in.DryRun}
	res.Script = Render(in.Spec)

	if err := c.Check(ctx, res.Script); err != nil {
		return res, fmt.Errorf("nft check: %w", err)
	}

	prior, err := c.DumpTable(ctx, in.Spec.TableName)
	if err != nil {
		return res, fmt.Errorf("snapshot table: %w", err)
	}
	if err := os.MkdirAll(in.BackupDir, 0o750); err != nil {
		return res, fmt.Errorf("mkdir backup: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(in.BackupDir, fmt.Sprintf("nft-%s-%s.nft", in.Spec.TableName, stamp))
	if err := os.WriteFile(backupPath, []byte(prior), 0o600); err != nil {
		return res, fmt.Errorf("write backup: %w", err)
	}
	res.BackupPath = backupPath

	if in.DB != nil {
		sum := sha256.Sum256([]byte(prior))
		_ = in.DB.RecordSnapshot(ctx, "nft-table", backupPath, hex.EncodeToString(sum[:]), "pre-apply "+in.Spec.TableName)
	}

	if in.DryRun {
		return res, nil
	}

	if err := c.applyRaw(ctx, res.Script); err != nil {
		if prior != "" {
			_ = c.applyRaw(ctx, "delete table ip "+in.Spec.TableName+"\n"+prior+"\n")
		}
		return res, fmt.Errorf("nft apply failed, rolled back: %w", err)
	}
	res.Applied = true

	// Figure out which (proto, public_port) tuples were removed from the
	// managed table. Without this step, existing connections that already
	// have a DNAT entry in conntrack keep flowing after their rule is
	// gone, because the kernel rewrites packets from the cached entry
	// rather than re-evaluating rules. Flushing conntrack on the removed
	// ports severs those sessions so "disable" / "delete" actually takes
	// effect on the active traffic, not just future connections.
	res.Removed = diffRemoved(prior, in.Spec)
	for _, r := range res.Removed {
		n := c.flushConntrack(ctx, r.Proto, r.PublicPort)
		res.FlushedConnections += n
	}

	if in.DB != nil {
		_ = in.DB.AuditWrite(ctx, in.Actor, "nft.apply", in.Spec.TableName,
			fmt.Sprintf(`{"backup":%q,"forwards":%d,"removed":%d,"flushed":%d}`,
				backupPath, len(in.Spec.Forwards), len(res.Removed), res.FlushedConnections))
	}
	return res, nil
}

// diffRemoved returns forwards that were in the prior snapshot but are not
// in the new spec. The matching key is (proto, public_port) — the same
// uniqueness constraint the DB enforces.
func diffRemoved(priorSnapshot string, spec RenderSpec) []ParsedForward {
	prior := ParseTable(spec.TableName, "ip", priorSnapshot)
	now := map[string]bool{}
	for _, f := range spec.Forwards {
		now[f.Proto+":"+strconv.Itoa(f.PublicPort)] = true
	}
	var out []ParsedForward
	for _, pf := range prior.Forwards {
		if !now[pf.Proto+":"+strconv.Itoa(pf.PublicPort)] {
			out = append(out, pf)
		}
	}
	return out
}

// flushConntrack runs `conntrack -D -p <proto> --orig-port-dst <port>`. The
// command is best-effort: if conntrack isn't installed, or there are no
// matching entries, we silently return 0. stdout from conntrack-tools looks
// like "tcp ... src=... dst=..." per entry followed by a summary line
// "conntrack v1.4.x: 4 flow entries have been deleted." which we scan for.
func (c Client) flushConntrack(ctx context.Context, proto string, port int) int {
	if !sysexec.Which("conntrack") {
		return 0
	}
	r := c.Runner.Run(ctx, "conntrack", []string{
		"-D", "-p", proto, "--orig-port-dst", strconv.Itoa(port),
	}, "")
	if r.Err != nil || r.ExitCode != 0 {
		// Exit 1 with "0 flow entries have been deleted" is fine; nothing to do.
		return 0
	}
	// Parse the trailing summary if present: "... N flow entries have been deleted."
	// We look at stderr because conntrack prints the summary there.
	return parseConntrackFlushed(r.Stderr)
}

func parseConntrackFlushed(stderr string) int {
	// Typical line: "conntrack v1.4.6 (conntrack-tools): 4 flow entries have been deleted."
	const marker = "flow entries have been deleted"
	idx := indexOf(stderr, marker)
	if idx < 0 {
		return 0
	}
	// Walk backward from marker to find the number.
	end := idx - 1
	for end > 0 && stderr[end] == ' ' {
		end--
	}
	start := end
	for start > 0 && stderr[start-1] >= '0' && stderr[start-1] <= '9' {
		start--
	}
	if start == end+1 {
		return 0
	}
	n, err := strconv.Atoi(stderr[start : end+1])
	if err != nil {
		return 0
	}
	return n
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func (c Client) applyRaw(ctx context.Context, script string) error {
	r := c.Runner.Run(ctx, "nft", []string{"-f", "-"}, script)
	if r.Err != nil || r.ExitCode != 0 {
		return fmt.Errorf("nft -f failed (exit=%d): %s", r.ExitCode, r.Stderr)
	}
	return nil
}

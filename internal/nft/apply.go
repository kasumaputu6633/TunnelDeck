package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tunneldeck/tunneldeck/internal/db"
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

	if in.DB != nil {
		_ = in.DB.AuditWrite(ctx, in.Actor, "nft.apply", in.Spec.TableName,
			fmt.Sprintf(`{"backup":%q,"forwards":%d}`, backupPath, len(in.Spec.Forwards)))
	}
	return res, nil
}

func (c Client) applyRaw(ctx context.Context, script string) error {
	r := c.Runner.Run(ctx, "nft", []string{"-f", "-"}, script)
	if r.Err != nil || r.ExitCode != 0 {
		return fmt.Errorf("nft -f failed (exit=%d): %s", r.ExitCode, r.Stderr)
	}
	return nil
}

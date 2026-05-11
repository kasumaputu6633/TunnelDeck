// Package db opens and migrates the SQLite state file.
//
// Uses modernc.org/sqlite (pure Go, no CGO) so the binary cross-compiles
// cleanly from Windows and runs on small Linux VPSes.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type DB struct {
	*sql.DB
}

// Open opens (or creates) the SQLite file at path and applies the schema.
// Safe to call on an already-migrated DB.
func Open(path string) (*DB, error) {
	// PRAGMAs in the DSN run on every new connection, not just the first.
	// busy_timeout avoids transient "database is locked" under contention.
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Single writer avoids "database is locked" under write contention; reads
	// still go through the same handle and are fast enough for control-plane state.
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	d := &DB{sqldb}
	if err := d.migrate(context.Background()); err != nil {
		_ = sqldb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	var v int
	err := d.QueryRowContext(ctx, `SELECT version FROM schema_version WHERE version=1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = d.ExecContext(ctx, `INSERT INTO schema_version(version, applied_at) VALUES (1, ?)`, time.Now().Unix())
	}
	if err != nil {
		return err
	}
	// v2: add last_seen_at to nodes (existing DBs won't have it).
	var v2 int
	err2 := d.QueryRowContext(ctx, `SELECT version FROM schema_version WHERE version=2`).Scan(&v2)
	if errors.Is(err2, sql.ErrNoRows) {
		if _, err := d.ExecContext(ctx, `ALTER TABLE nodes ADD COLUMN last_seen_at INTEGER`); err != nil {
			// Column may already exist if schema.sql was applied fresh — ignore.
			if !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migrate v2: %w", err)
			}
		}
		_, _ = d.ExecContext(ctx, `INSERT INTO schema_version(version, applied_at) VALUES (2, ?)`, time.Now().Unix())
	}
	return nil
}

// EnsureGatewayRow seeds the singleton gateway row if absent. Called once at
// startup; adopt/fresh install flows overwrite fields later.
func (d *DB) EnsureGatewayRow(ctx context.Context, wgIf, wgSubnet, uiBind string, uiPort int, managedTable string) error {
	now := time.Now().Unix()
	_, err := d.ExecContext(ctx, `
		INSERT INTO gateway (id, wg_if, wg_subnet, ui_bind, ui_port, managed_nft_table, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, wgIf, wgSubnet, uiBind, uiPort, managedTable, now, now)
	return err
}

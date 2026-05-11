package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Node represents a WireGuard peer managed by TunnelDeck.
type Node struct {
	ID           int64
	Name         string
	WGIP         string // "10.66.66.2" (host only, no /32)
	PublicKey    string // empty until node joins
	EndpointHint string
	Keepalive    int
	Adopted      bool
	LastSeenAt   *time.Time
	CreatedAt    time.Time
}

// Forward is a public-port-on-gateway → node-wg-ip:target-port rule.
type Forward struct {
	ID          int64
	Name        string
	Proto       string // "tcp" | "udp"
	PublicPort  int
	NodeID      int64
	TargetPort  int
	Description string
	Enabled     bool
	LogMode     string // "counter" | "connlog" | "debug"
	CreatedAt   time.Time

	// Joined fields (optional; populated by ListForwardsWithNode).
	NodeName string
	NodeWGIP string
}

// Gateway is the singleton row describing the local gateway.
type Gateway struct {
	PublicIP         string
	WANIf            string
	WGIf             string
	WGIP             string // "10.66.66.1/24"
	WGPort           int
	WGSubnet         string // "10.66.66.0/24"
	WGPublicKey      string
	UIBind           string
	UIPort           int
	ManagedNFTTable  string
	AdoptMode        string // "fresh" | "monitor-only" | "adopted"
	AdoptConfirmedAt *time.Time
}

// -------- Gateway --------

func (d *DB) GetGateway(ctx context.Context) (Gateway, error) {
	var g Gateway
	var confirmed sql.NullInt64
	err := d.QueryRowContext(ctx, `
		SELECT public_ip, wan_if, wg_if, wg_ip, wg_port, wg_subnet, wg_public_key,
		       ui_bind, ui_port, managed_nft_table, adopt_mode, adopt_confirmed_at
		FROM gateway WHERE id=1
	`).Scan(&g.PublicIP, &g.WANIf, &g.WGIf, &g.WGIP, &g.WGPort, &g.WGSubnet, &g.WGPublicKey,
		&g.UIBind, &g.UIPort, &g.ManagedNFTTable, &g.AdoptMode, &confirmed)
	if err != nil {
		return g, err
	}
	if confirmed.Valid {
		t := time.Unix(confirmed.Int64, 0)
		g.AdoptConfirmedAt = &t
	}
	return g, nil
}

func (d *DB) UpdateGateway(ctx context.Context, g Gateway) error {
	var confirmed sql.NullInt64
	if g.AdoptConfirmedAt != nil {
		confirmed = sql.NullInt64{Int64: g.AdoptConfirmedAt.Unix(), Valid: true}
	}
	_, err := d.ExecContext(ctx, `
		UPDATE gateway SET
			public_ip=?, wan_if=?, wg_if=?, wg_ip=?, wg_port=?, wg_subnet=?, wg_public_key=?,
			ui_bind=?, ui_port=?, managed_nft_table=?, adopt_mode=?, adopt_confirmed_at=?,
			updated_at=?
		WHERE id=1
	`, g.PublicIP, g.WANIf, g.WGIf, g.WGIP, g.WGPort, g.WGSubnet, g.WGPublicKey,
		g.UIBind, g.UIPort, g.ManagedNFTTable, g.AdoptMode, confirmed,
		time.Now().Unix())
	return err
}

// -------- Nodes --------

func (d *DB) CreateNode(ctx context.Context, n Node) (int64, error) {
	res, err := d.ExecContext(ctx, `
		INSERT INTO nodes (name, wg_ip, public_key, endpoint_hint, keepalive, adopted, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, n.Name, n.WGIP, n.PublicKey, n.EndpointHint, n.Keepalive, boolToInt(n.Adopted), time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT id, name, wg_ip, public_key, endpoint_hint, keepalive, adopted, last_seen_at, created_at
		FROM nodes ORDER BY wg_ip
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var adopted int
		var createdAt int64
		var lastSeen sql.NullInt64
		if err := rows.Scan(&n.ID, &n.Name, &n.WGIP, &n.PublicKey, &n.EndpointHint, &n.Keepalive, &adopted, &lastSeen, &createdAt); err != nil {
			return nil, err
		}
		n.Adopted = adopted != 0
		n.CreatedAt = time.Unix(createdAt, 0)
		if lastSeen.Valid {
			t := time.Unix(lastSeen.Int64, 0)
			n.LastSeenAt = &t
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (d *DB) GetNodeByWGIP(ctx context.Context, wgIP string) (Node, error) {
	var n Node
	var adopted int
	var createdAt int64
	var lastSeen sql.NullInt64
	err := d.QueryRowContext(ctx, `
		SELECT id, name, wg_ip, public_key, endpoint_hint, keepalive, adopted, last_seen_at, created_at
		FROM nodes WHERE wg_ip=?
	`, wgIP).Scan(&n.ID, &n.Name, &n.WGIP, &n.PublicKey, &n.EndpointHint, &n.Keepalive, &adopted, &lastSeen, &createdAt)
	if err != nil {
		return n, err
	}
	n.Adopted = adopted != 0
	n.CreatedAt = time.Unix(createdAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		n.LastSeenAt = &t
	}
	return n, nil
}

func (d *DB) GetNodeByPublicKey(ctx context.Context, pk string) (Node, error) {
	var n Node
	var adopted int
	var createdAt int64
	var lastSeen sql.NullInt64
	err := d.QueryRowContext(ctx, `
		SELECT id, name, wg_ip, public_key, endpoint_hint, keepalive, adopted, last_seen_at, created_at
		FROM nodes WHERE public_key=?
	`, pk).Scan(&n.ID, &n.Name, &n.WGIP, &n.PublicKey, &n.EndpointHint, &n.Keepalive, &adopted, &lastSeen, &createdAt)
	if err != nil {
		return n, err
	}
	n.Adopted = adopted != 0
	n.CreatedAt = time.Unix(createdAt, 0)
	if lastSeen.Valid {
		t := time.Unix(lastSeen.Int64, 0)
		n.LastSeenAt = &t
	}
	return n, nil
}

// UpdateNodeLastSeen records the current time as last_seen_at for the node
// with the given WG IP. Called by the nodes handler whenever a live peer
// handshake is detected. Best-effort: errors are silently ignored.
func (d *DB) UpdateNodeLastSeen(ctx context.Context, wgIP string) {
	_, _ = d.ExecContext(ctx, `UPDATE nodes SET last_seen_at=? WHERE wg_ip=?`, time.Now().Unix(), wgIP)
}

func (d *DB) DeleteNode(ctx context.Context, id int64) error {
	// Block deletion if forwards reference it. Caller should surface this.
	var count int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM forwards WHERE node_id=?`, id).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return errors.New("node has forwards; delete them first")
	}
	_, err := d.ExecContext(ctx, `DELETE FROM nodes WHERE id=?`, id)
	return err
}

// -------- Forwards --------

func (d *DB) CreateForward(ctx context.Context, f Forward) (int64, error) {
	res, err := d.ExecContext(ctx, `
		INSERT INTO forwards (name, proto, public_port, node_id, target_port, description, enabled, log_mode, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.Name, f.Proto, f.PublicPort, f.NodeID, f.TargetPort, f.Description, boolToInt(f.Enabled), f.LogMode, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) ListForwardsWithNode(ctx context.Context) ([]Forward, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT f.id, f.name, f.proto, f.public_port, f.node_id, f.target_port,
		       f.description, f.enabled, f.log_mode, f.created_at,
		       n.name, n.wg_ip
		FROM forwards f
		JOIN nodes n ON n.id = f.node_id
		ORDER BY f.proto, f.public_port
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		var enabled int
		var createdAt int64
		if err := rows.Scan(&f.ID, &f.Name, &f.Proto, &f.PublicPort, &f.NodeID, &f.TargetPort,
			&f.Description, &enabled, &f.LogMode, &createdAt, &f.NodeName, &f.NodeWGIP); err != nil {
			return nil, err
		}
		f.Enabled = enabled != 0
		f.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (d *DB) SetForwardEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := d.ExecContext(ctx, `UPDATE forwards SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	return err
}

func (d *DB) DeleteForward(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM forwards WHERE id=?`, id)
	return err
}

// -------- Audit --------

func (d *DB) AuditWrite(ctx context.Context, actor, action, target, detailJSON string) error {
	if detailJSON == "" {
		detailJSON = "{}"
	}
	_, err := d.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)
	`, time.Now().Unix(), actor, action, target, detailJSON)
	return err
}

type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

func (d *DB) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, ts, actor, action, target, detail FROM audit_log
		ORDER BY ts DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// -------- Snapshots --------

func (d *DB) RecordSnapshot(ctx context.Context, kind, path, sha string, note string) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO snapshots (ts, kind, path, sha256, note) VALUES (?, ?, ?, ?, ?)
	`, time.Now().Unix(), kind, path, sha, note)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

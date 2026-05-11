package db

import (
	"context"
	"time"
)

// Page describes a pagination slice request. Page is 1-based; callers that
// receive an out-of-range page should clamp with Normalize.
type Page struct {
	Page    int // 1-based
	PerPage int
}

// Normalize clamps Page and PerPage into sane defaults. Called by every
// paginated list query so handlers can forward query-string values directly
// without validation.
func (p Page) Normalize() Page {
	if p.PerPage <= 0 {
		p.PerPage = 10
	}
	if p.PerPage > 100 {
		p.PerPage = 100
	}
	if p.Page < 1 {
		p.Page = 1
	}
	return p
}

// Offset returns the SQL OFFSET for this page.
func (p Page) Offset() int { return (p.Page - 1) * p.PerPage }

// PageResult is the envelope every paginated list returns. TotalPages is
// derived from Total and PerPage; it's 1 when Total is 0 so the UI always
// has at least one page label.
type PageResult struct {
	Page       int
	PerPage    int
	Total      int
	TotalPages int
}

// NewPageResult constructs a PageResult given the raw count.
func NewPageResult(p Page, total int) PageResult {
	p = p.Normalize()
	pages := (total + p.PerPage - 1) / p.PerPage
	if pages < 1 {
		pages = 1
	}
	return PageResult{Page: p.Page, PerPage: p.PerPage, Total: total, TotalPages: pages}
}

// -------- Nodes --------

// ListNodesPage returns nodes for the given page plus a PageResult.
// Ordering matches ListNodes (wg_ip asc) for deterministic pagination.
func (d *DB) ListNodesPage(ctx context.Context, p Page) ([]Node, PageResult, error) {
	p = p.Normalize()
	var total int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&total); err != nil {
		return nil, PageResult{}, err
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, name, wg_ip, public_key, endpoint_hint, keepalive, adopted, created_at
		FROM nodes
		ORDER BY wg_ip
		LIMIT ? OFFSET ?
	`, p.PerPage, p.Offset())
	if err != nil {
		return nil, PageResult{}, err
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		var n Node
		var adopted int
		var createdAt int64
		if err := rows.Scan(&n.ID, &n.Name, &n.WGIP, &n.PublicKey, &n.EndpointHint, &n.Keepalive, &adopted, &createdAt); err != nil {
			return nil, PageResult{}, err
		}
		n.Adopted = adopted != 0
		n.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, n)
	}
	return out, NewPageResult(p, total), rows.Err()
}

// -------- Forwards --------

// ListForwardsWithNodePage is the paginated variant of ListForwardsWithNode.
func (d *DB) ListForwardsWithNodePage(ctx context.Context, p Page) ([]Forward, PageResult, error) {
	p = p.Normalize()
	var total int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM forwards`).Scan(&total); err != nil {
		return nil, PageResult{}, err
	}
	rows, err := d.QueryContext(ctx, `
		SELECT f.id, f.name, f.proto, f.public_port, f.node_id, f.target_port,
		       f.description, f.enabled, f.log_mode, f.created_at,
		       n.name, n.wg_ip
		FROM forwards f
		JOIN nodes n ON n.id = f.node_id
		ORDER BY f.proto, f.public_port
		LIMIT ? OFFSET ?
	`, p.PerPage, p.Offset())
	if err != nil {
		return nil, PageResult{}, err
	}
	defer rows.Close()

	var out []Forward
	for rows.Next() {
		var f Forward
		var enabled int
		var createdAt int64
		if err := rows.Scan(&f.ID, &f.Name, &f.Proto, &f.PublicPort, &f.NodeID, &f.TargetPort,
			&f.Description, &enabled, &f.LogMode, &createdAt, &f.NodeName, &f.NodeWGIP); err != nil {
			return nil, PageResult{}, err
		}
		f.Enabled = enabled != 0
		f.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, f)
	}
	return out, NewPageResult(p, total), rows.Err()
}

// -------- Audit --------

// ListAuditPage is the paginated variant of ListAudit. Ordering is ts desc,
// so page 1 always shows the most recent entries.
func (d *DB) ListAuditPage(ctx context.Context, p Page) ([]AuditEntry, PageResult, error) {
	p = p.Normalize()
	var total int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, PageResult{}, err
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, ts, actor, action, target, detail
		FROM audit_log
		ORDER BY ts DESC
		LIMIT ? OFFSET ?
	`, p.PerPage, p.Offset())
	if err != nil {
		return nil, PageResult{}, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, PageResult{}, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, NewPageResult(p, total), rows.Err()
}
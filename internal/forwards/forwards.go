// Package forwards owns validation and IP allocation for port-forward rules.
// It sits between the HTTP handlers and the DB; callers are responsible for
// re-rendering nftables after a successful Create/Delete.
package forwards

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/tunneldeck/tunneldeck/internal/db"
)

// ProtectedPort is a port that TunnelDeck refuses to forward, or warns on.
//
// Refuse tier: gateway SSH, WireGuard port, Web UI port — forwarding any of
// these cuts off our own control plane.
// Warn tier: common DB ports, where exposure is usually wrong but sometimes
// intentional.
type ProtectedPort struct {
	Port  int
	Proto string
	Why   string
	Level string // "refuse" | "warn"
}

// BuildProtectedList assembles the protected-port list from the current
// gateway settings. SSH/WG/UI are dynamic so we compute this at validation time.
func BuildProtectedList(sshPort, wgPort, uiPort int) []ProtectedPort {
	if sshPort == 0 {
		sshPort = 22
	}
	return []ProtectedPort{
		{Port: sshPort, Proto: "tcp", Why: "gateway SSH — forwarding this would lock you out", Level: "refuse"},
		{Port: wgPort, Proto: "udp", Why: "WireGuard listen port — forwarding breaks the tunnel", Level: "refuse"},
		{Port: uiPort, Proto: "tcp", Why: "TunnelDeck Web UI — exposing this publicly is unsafe", Level: "refuse"},

		{Port: 3306, Proto: "tcp", Why: "MySQL/MariaDB — exposing a DB publicly is rarely intended", Level: "warn"},
		{Port: 5432, Proto: "tcp", Why: "PostgreSQL — exposing a DB publicly is rarely intended", Level: "warn"},
		{Port: 6379, Proto: "tcp", Why: "Redis — exposing a DB publicly is rarely intended", Level: "warn"},
		{Port: 27017, Proto: "tcp", Why: "MongoDB — exposing a DB publicly is rarely intended", Level: "warn"},
		{Port: 9200, Proto: "tcp", Why: "Elasticsearch — exposing a DB publicly is rarely intended", Level: "warn"},
	}
}

type Issue struct {
	Severity string // "error" | "warn"
	Field    string
	Message  string
}

type Input struct {
	Name        string
	Proto       string
	PublicPort  int
	NodeID      int64
	TargetPort  int
	Description string
	LogMode     string
}

// Validate returns all issues found. An empty slice means the forward is safe
// to create. Callers typically proceed on any result with no error-severity
// issue, surfacing warn-severity issues in the UI for explicit confirmation.
func Validate(ctx context.Context, in Input, existing []db.Forward, nodes []db.Node, protected []ProtectedPort, editingID int64) []Issue {
	var out []Issue

	if strings.TrimSpace(in.Name) == "" {
		out = append(out, Issue{Severity: "error", Field: "name", Message: "name is required"})
	}

	switch in.Proto {
	case "tcp", "udp":
	default:
		out = append(out, Issue{Severity: "error", Field: "proto", Message: "proto must be tcp or udp"})
	}

	if err := checkPort(in.PublicPort); err != nil {
		out = append(out, Issue{Severity: "error", Field: "public_port", Message: err.Error()})
	}
	if err := checkPort(in.TargetPort); err != nil {
		out = append(out, Issue{Severity: "error", Field: "target_port", Message: err.Error()})
	}

	if in.NodeID == 0 {
		out = append(out, Issue{Severity: "error", Field: "node_id", Message: "select a node"})
	} else {
		found := false
		for _, n := range nodes {
			if n.ID == in.NodeID {
				found = true
				break
			}
		}
		if !found {
			out = append(out, Issue{Severity: "error", Field: "node_id", Message: "node not found"})
		}
	}

	for _, f := range existing {
		if f.ID == editingID {
			continue
		}
		if f.Proto == in.Proto && f.PublicPort == in.PublicPort {
			out = append(out, Issue{
				Severity: "error",
				Field:    "public_port",
				Message:  fmt.Sprintf("%s/%d is already forwarded (forward #%d)", in.Proto, in.PublicPort, f.ID),
			})
			break
		}
	}

	// Protected ports: "refuse" maps to error so HasErrors blocks the save.
	for _, p := range protected {
		if p.Port != in.PublicPort {
			continue
		}
		if p.Proto != "any" && p.Proto != in.Proto {
			continue
		}
		sev := "warn"
		if p.Level == "refuse" {
			sev = "error"
		}
		out = append(out, Issue{
			Severity: sev,
			Field:    "public_port",
			Message:  p.Why,
		})
	}

	switch in.LogMode {
	case "", "counter", "connlog", "debug":
	default:
		out = append(out, Issue{Severity: "error", Field: "log_mode", Message: "log_mode must be counter, connlog, or debug"})
	}

	return out
}

func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

func checkPort(p int) error {
	if p < 1 || p > 65535 {
		return errors.New("port must be 1..65535")
	}
	return nil
}

// AllocateNextIP returns the next unused host IP in subnet, skipping the
// gateway's address and any already-assigned node. IPv4 only.
func AllocateNextIP(subnet string, gatewayIP string, used []string) (string, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("bad subnet %q: %w", subnet, err)
	}
	taken := map[string]bool{gatewayIP: true}
	for _, u := range used {
		taken[stripMask(u)] = true
	}

	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)

	// Start at .2 (skip network .0 and gateway .1 by convention).
	inc(ip)
	inc(ip)
	for ipnet.Contains(ip) {
		if ip[len(ip)-1] == 255 {
			break
		}
		if !taken[ip.String()] {
			return ip.String(), nil
		}
		inc(ip)
	}
	return "", errors.New("subnet is full")
}

func stripMask(s string) string {
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i]
	}
	return s
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

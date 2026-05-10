package nft

import (
	"context"
	"fmt"
	"strings"

	"github.com/tunneldeck/tunneldeck/internal/sysexec"
)

// ParsedForward is a DNAT rule recovered from an existing nft table.
// Used by the Adopt flow to import pre-existing rules into the DB.
//
// The parser only recognises the subset TunnelDeck itself emits, plus the
// common manual pattern:
//
//	iifname "eth0" tcp dport 25577 dnat to 10.66.66.2:25577
//
// Anything it can't recognise is reported as "unknown".
type ParsedForward struct {
	IIfName    string
	Proto      string
	PublicPort int
	TargetIP   string
	TargetPort int
	HasCounter bool
	Raw        string
}

type ParsedTable struct {
	Name     string
	Family   string
	Forwards []ParsedForward
	Unknown  []string
}

// ParseTable extracts DNAT rules from the stdout of `nft list table ip <name>`.
func ParseTable(name, family, raw string) ParsedTable {
	pt := ParsedTable{Name: name, Family: family}
	for _, ln := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "table ") ||
			strings.HasPrefix(trimmed, "chain ") ||
			strings.HasPrefix(trimmed, "type ") ||
			trimmed == "}" || trimmed == "{" {
			continue
		}
		if strings.Contains(trimmed, "dnat to ") {
			if pf, ok := parseDNATRule(trimmed); ok {
				pt.Forwards = append(pt.Forwards, pf)
				continue
			}
			pt.Unknown = append(pt.Unknown, trimmed)
		}
	}
	return pt
}

// parseDNATRule matches: [iifname "IF"] (tcp|udp) dport NUM [counter ...] dnat to IP[:PORT]
func parseDNATRule(line string) (ParsedForward, bool) {
	pf := ParsedForward{Raw: line}
	tokens := tokenize(line)

	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch tok {
		case "iifname":
			if i+1 < len(tokens) {
				pf.IIfName = strings.Trim(tokens[i+1], `"`)
				i++
			}
		case "tcp", "udp":
			if i+2 < len(tokens) && tokens[i+1] == "dport" {
				pf.Proto = tok
				if _, err := fmt.Sscanf(tokens[i+2], "%d", &pf.PublicPort); err != nil {
					return pf, false
				}
				i += 2
			}
		case "counter":
			pf.HasCounter = true
		case "dnat":
			if i+2 < len(tokens) && tokens[i+1] == "to" {
				target := tokens[i+2]
				ip, port, ok := splitIPPort(target)
				if !ok {
					return pf, false
				}
				pf.TargetIP = ip
				pf.TargetPort = port
				i += 2
			}
		}
	}

	if pf.Proto == "" || pf.PublicPort == 0 || pf.TargetIP == "" {
		return pf, false
	}
	// If target port was omitted, DNAT keeps the original dport.
	if pf.TargetPort == 0 {
		pf.TargetPort = pf.PublicPort
	}
	return pf, true
}

// tokenize splits on whitespace but keeps quoted strings intact.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// splitIPPort handles "10.66.66.2:25577" and bare "10.66.66.2".
// Refuses IPv6 (more than one colon) since this parser is IPv4-only.
func splitIPPort(s string) (string, int, bool) {
	s = strings.TrimRight(s, ";}")
	if i := strings.LastIndex(s, ":"); i > 0 {
		if strings.Count(s, ":") > 1 {
			return "", 0, false
		}
		ip := s[:i]
		var port int
		if _, err := fmt.Sscanf(s[i+1:], "%d", &port); err != nil {
			return "", 0, false
		}
		return ip, port, true
	}
	return s, 0, true
}

func (c Client) InspectTable(ctx context.Context, name string) (ParsedTable, error) {
	raw, err := c.DumpTable(ctx, name)
	if err != nil {
		return ParsedTable{}, err
	}
	return ParseTable(name, "ip", raw), nil
}

// ListTables returns (family, name) pairs from `nft list tables`.
func (c Client) ListTables(ctx context.Context) ([][2]string, error) {
	r := c.Runner.Run(ctx, "nft", []string{"list", "tables"}, "")
	if r.Err != nil || r.ExitCode != 0 {
		return nil, fmt.Errorf("nft list tables failed: %s", strings.TrimSpace(r.Stderr))
	}
	var out [][2]string
	for _, ln := range strings.Split(r.Stdout, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "table ") {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) >= 3 {
			out = append(out, [2]string{parts[1], parts[2]})
		}
	}
	return out, nil
}

var _ = sysexec.Runner(nil)

package nft

import (
	"context"
	"strconv"
	"strings"
)

// RuleCounter is a per-rule packet/byte counter extracted from
// `nft list table ip <name>`. We identify a rule by the trailing
// `td:fwd=<id>` token we put in every DNAT rule's comment at render time.
type RuleCounter struct {
	ForwardID int64
	Packets   int64
	Bytes     int64
}

// ParseCounters walks the output of `nft list table ip <name>` and pulls
// packet/byte counters for every rule whose comment starts with td:fwd=.
// Unknown lines are skipped silently — we only care about the rules we
// rendered.
//
// Example input line:
//   iifname "eth0" tcp dport 25577 counter packets 12 bytes 1680 dnat to 10.66.66.2:25577 comment "td:fwd=3 mc-java"
func ParseCounters(raw string) []RuleCounter {
	var out []RuleCounter
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "td:fwd=") {
			continue
		}
		id := extractFwdID(line)
		if id == 0 {
			continue
		}
		pkts, bytes := extractCounterFields(line)
		out = append(out, RuleCounter{ForwardID: id, Packets: pkts, Bytes: bytes})
	}
	return out
}

// extractFwdID pulls the numeric id out of a td:fwd=<n> token inside a
// comment. Returns 0 if not found or not parseable.
func extractFwdID(line string) int64 {
	const marker = "td:fwd="
	i := strings.Index(line, marker)
	if i < 0 {
		return 0
	}
	rest := line[i+len(marker):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// extractCounterFields picks up the "packets N bytes M" sequence that nft
// emits after the word "counter" when stats are enabled on a rule.
// Returns 0,0 if the sequence isn't present (rule has no counter, or
// nft version without stats).
func extractCounterFields(line string) (int64, int64) {
	// Walk tokens so we tolerate commas and quoting.
	tokens := tokenize(line)
	var pkts, bytes int64
	for i := 0; i < len(tokens)-3; i++ {
		if tokens[i] == "counter" && tokens[i+1] == "packets" {
			p, err := strconv.ParseInt(strings.TrimRight(tokens[i+2], ","), 10, 64)
			if err != nil {
				return 0, 0
			}
			if tokens[i+3] != "bytes" || i+4 >= len(tokens) {
				return 0, 0
			}
			b, err := strconv.ParseInt(strings.TrimRight(tokens[i+4], ","), 10, 64)
			if err != nil {
				return 0, 0
			}
			pkts, bytes = p, b
			break
		}
	}
	return pkts, bytes
}

// CountersByForwardID fetches the managed table and returns a map
// forwardID -> counter for O(1) lookup in handlers.
func (c Client) CountersByForwardID(ctx context.Context, table string) (map[int64]RuleCounter, error) {
	raw, err := c.DumpTable(ctx, table)
	if err != nil {
		return nil, err
	}
	m := map[int64]RuleCounter{}
	for _, rc := range ParseCounters(raw) {
		m[rc.ForwardID] = rc
	}
	return m, nil
}
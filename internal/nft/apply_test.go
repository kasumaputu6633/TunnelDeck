package nft

import (
	"strings"
	"testing"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
)

func TestDiffRemoved_DetectsDroppedPorts(t *testing.T) {
	// Prior snapshot contains 25577 and 19132.
	prior := `table ip tunneldeck_nat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
			iifname "eth0" tcp dport 25577 counter dnat to 10.66.66.2:25577
			iifname "eth0" udp dport 19132 counter dnat to 10.66.66.2:19132
		}
	}`
	// New spec keeps 25577 only — so 19132/udp must be reported as removed.
	spec := RenderSpec{
		TableName: "tunneldeck_nat",
		Forwards: []db.Forward{
			{Proto: "tcp", PublicPort: 25577, NodeWGIP: "10.66.66.2", TargetPort: 25577},
		},
	}
	removed := diffRemoved(prior, spec)
	if len(removed) != 1 {
		t.Fatalf("want 1 removed, got %d: %+v", len(removed), removed)
	}
	if removed[0].Proto != "udp" || removed[0].PublicPort != 19132 {
		t.Fatalf("wrong removed entry: %+v", removed[0])
	}
}

func TestDiffRemoved_EmptyWhenUnchanged(t *testing.T) {
	prior := `table ip tunneldeck_nat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
			iifname "eth0" tcp dport 25577 counter dnat to 10.66.66.2:25577
		}
	}`
	spec := RenderSpec{
		TableName: "tunneldeck_nat",
		Forwards: []db.Forward{
			{Proto: "tcp", PublicPort: 25577, NodeWGIP: "10.66.66.2", TargetPort: 25577},
		},
	}
	if removed := diffRemoved(prior, spec); len(removed) != 0 {
		t.Fatalf("want 0 removed, got %+v", removed)
	}
}

func TestParseConntrackFlushed(t *testing.T) {
	samples := map[string]int{
		"conntrack v1.4.6 (conntrack-tools): 4 flow entries have been deleted.\n": 4,
		"conntrack v1.4.6 (conntrack-tools): 0 flow entries have been deleted.\n": 0,
		"conntrack v1.4.6 (conntrack-tools): 17 flow entries have been deleted.": 17,
		"":                    0,
		"something unrelated": 0,
	}
	for input, want := range samples {
		if got := parseConntrackFlushed(input); got != want {
			t.Errorf("parseConntrackFlushed(%q) = %d, want %d", strings.TrimSpace(input), got, want)
		}
	}
}

package nft

import (
	"strings"
	"testing"

	"github.com/tunneldeck/tunneldeck/internal/db"
)

func TestRender_UsesDedicatedTable_NoGlobalFlush(t *testing.T) {
	out := Render(RenderSpec{
		TableName: "tunneldeck_nat",
		WANIf:     "eth0",
		WGIf:      "wg0",
		WGSubnet:  "10.66.66.0/24",
	})

	// Hard safety rule: we must never emit `flush ruleset`.
	if strings.Contains(out, "flush ruleset") {
		t.Fatal("render must never contain 'flush ruleset'")
	}
	// Must scope to our own table.
	if !strings.Contains(out, "table ip tunneldeck_nat {") {
		t.Fatalf("expected managed table block:\n%s", out)
	}
	if !strings.Contains(out, "delete table ip tunneldeck_nat") {
		t.Fatalf("expected atomic delete of managed table:\n%s", out)
	}
}

func TestRender_ForwardProducesDNATWithCounter(t *testing.T) {
	fwds := []db.Forward{
		{ID: 1, Name: "mc-java", Proto: "tcp", PublicPort: 25577, TargetPort: 25577, NodeWGIP: "10.66.66.2", Enabled: true},
		{ID: 2, Name: "mc-bedrock", Proto: "udp", PublicPort: 19132, TargetPort: 19132, NodeWGIP: "10.66.66.2", Enabled: true},
		{ID: 3, Name: "ssh-relay", Proto: "tcp", PublicPort: 2222, TargetPort: 22, NodeWGIP: "10.66.66.2", Enabled: true},
	}
	out := Render(RenderSpec{
		TableName: "tunneldeck_nat",
		WANIf:     "eth0",
		WGIf:      "wg0",
		WGSubnet:  "10.66.66.0/24",
		Forwards:  fwds,
	})
	mustContainAll(t, out,
		`iifname "eth0" tcp dport 25577 counter dnat to 10.66.66.2:25577`,
		`iifname "eth0" udp dport 19132 counter dnat to 10.66.66.2:19132`,
		`iifname "eth0" tcp dport 2222 counter dnat to 10.66.66.2:22`,
		`oifname "wg0" ip daddr 10.66.66.0/24 counter masquerade`,
	)
}

func TestRender_DeterministicOrder(t *testing.T) {
	a := []db.Forward{
		{ID: 2, Name: "b", Proto: "tcp", PublicPort: 25577, TargetPort: 25577, NodeWGIP: "10.66.66.2"},
		{ID: 1, Name: "a", Proto: "tcp", PublicPort: 2222, TargetPort: 22, NodeWGIP: "10.66.66.2"},
		{ID: 3, Name: "c", Proto: "udp", PublicPort: 19132, TargetPort: 19132, NodeWGIP: "10.66.66.2"},
	}
	out1 := Render(RenderSpec{TableName: "t", WANIf: "eth0", WGIf: "wg0", WGSubnet: "10.66.66.0/24", Forwards: a})

	// Shuffle.
	b := []db.Forward{a[2], a[0], a[1]}
	out2 := Render(RenderSpec{TableName: "t", WANIf: "eth0", WGIf: "wg0", WGSubnet: "10.66.66.0/24", Forwards: b})

	if out1 != out2 {
		t.Fatalf("render not deterministic:\n--- a ---\n%s\n--- b ---\n%s", out1, out2)
	}
}

func TestRender_SanitizesComment(t *testing.T) {
	fwds := []db.Forward{
		{ID: 1, Name: `my "evil" \name`, Proto: "tcp", PublicPort: 80, TargetPort: 80, NodeWGIP: "10.66.66.2"},
	}
	out := Render(RenderSpec{TableName: "t", WANIf: "eth0", Forwards: fwds, WGIf: "wg0", WGSubnet: "10.66.66.0/24"})
	if strings.Contains(out, `"evil"`) || strings.Contains(out, `\name`) {
		t.Fatalf("comment not sanitized:\n%s", out)
	}
}

func mustContainAll(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("missing rule: %q\n--- full output ---\n%s", n, haystack)
		}
	}
}

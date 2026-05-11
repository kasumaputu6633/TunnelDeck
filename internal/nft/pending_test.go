package nft

import (
	"context"
	"testing"

	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

func TestCheckPending_NoPending(t *testing.T) {
	raw := `table ip tunneldeck_nat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
			iifname "eth0" tcp dport 25577 counter packets 10 bytes 600 dnat to 10.66.66.2:25577 comment "td:fwd=1 mc"
		}
	}`
	m := sysexec.NewMockRunner(map[string]sysexec.Result{
		"nft list table ip tunneldeck_nat": {Stdout: raw},
	})
	c := Client{Runner: m}
	db := []DBForwardSummary{{ID: 1, Proto: "tcp", PublicPort: 25577, Enabled: true}}
	ps := c.CheckPending(context.Background(), db, "tunneldeck_nat")
	if ps.HasPending {
		t.Fatalf("expected no pending, got missing=%v stale=%v", ps.Missing, ps.Stale)
	}
}

func TestCheckPending_MissingInNFT(t *testing.T) {
	raw := `table ip tunneldeck_nat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
		}
	}`
	m := sysexec.NewMockRunner(map[string]sysexec.Result{
		"nft list table ip tunneldeck_nat": {Stdout: raw},
	})
	c := Client{Runner: m}
	db := []DBForwardSummary{{ID: 1, Proto: "tcp", PublicPort: 25577, Enabled: true}}
	ps := c.CheckPending(context.Background(), db, "tunneldeck_nat")
	if !ps.HasPending {
		t.Fatal("expected pending (missing forward)")
	}
	if len(ps.Missing) != 1 || ps.Missing[0] != "tcp/25577" {
		t.Fatalf("wrong missing: %v", ps.Missing)
	}
}

func TestCheckPending_StaleInNFT(t *testing.T) {
	raw := `table ip tunneldeck_nat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
			iifname "eth0" tcp dport 25577 counter packets 0 bytes 0 dnat to 10.66.66.2:25577 comment "td:fwd=1 mc"
		}
	}`
	m := sysexec.NewMockRunner(map[string]sysexec.Result{
		"nft list table ip tunneldeck_nat": {Stdout: raw},
	})
	c := Client{Runner: m}
	db := []DBForwardSummary{{ID: 1, Proto: "tcp", PublicPort: 25577, Enabled: false}}
	ps := c.CheckPending(context.Background(), db, "tunneldeck_nat")
	if !ps.HasPending {
		t.Fatal("expected pending (stale rule)")
	}
	if len(ps.Stale) != 1 || ps.Stale[0] != "tcp/25577" {
		t.Fatalf("wrong stale: %v", ps.Stale)
	}
}

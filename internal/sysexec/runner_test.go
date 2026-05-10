package sysexec

import (
	"context"
	"strings"
	"testing"
)

func TestMockRunner_ReturnsCannedResponse(t *testing.T) {
	m := NewMockRunner(map[string]Result{
		"wg show wg0": {Stdout: "peer ABC\n  latest handshake: 10 seconds ago\n"},
	})

	r := m.Run(context.Background(), "wg", []string{"show", "wg0"}, "")
	if r.Err != nil {
		t.Fatalf("unexpected err: %v", r.Err)
	}
	if !strings.Contains(r.Stdout, "peer ABC") {
		t.Fatalf("stdout wrong: %q", r.Stdout)
	}
	if len(m.Calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(m.Calls))
	}
}

func TestMockRunner_UnknownCommandErrors(t *testing.T) {
	m := NewMockRunner(nil)
	r := m.Run(context.Background(), "nft", []string{"list", "ruleset"}, "")
	if r.Err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
	if r.ExitCode != -1 {
		t.Fatalf("want exit -1, got %d", r.ExitCode)
	}
}

func TestDryRunner_RecordsButDoesNotExecute(t *testing.T) {
	d := &DryRunner{}
	d.Run(context.Background(), "nft", []string{"-f", "/tmp/x"}, "")
	d.Run(context.Background(), "systemctl", []string{"reload", "nftables"}, "")

	if len(d.Calls) != 2 {
		t.Fatalf("want 2 recorded calls, got %d", len(d.Calls))
	}
	if d.Calls[0].ExitCode != 0 {
		t.Fatalf("dry runner should default to exit 0")
	}
}

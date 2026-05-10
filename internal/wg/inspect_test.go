package wg

import (
	"context"
	"testing"

	"github.com/tunneldeck/tunneldeck/internal/sysexec"
)

func TestParseDump_TypicalOutput(t *testing.T) {
	// First line = interface: privkey \t pubkey \t port \t fwmark
	// Following lines = peers
	out := "PRIV_GW\tPUB_GW\t51820\toff\n" +
		"PUB_NODE1\t(none)\t203.0.113.9:51820\t10.66.66.2/32\t1715000000\t123\t456\t25\n" +
		"PUB_NODE2\t(none)\t(none)\t10.66.66.3/32\t0\t0\t0\toff\n"

	iface, peers, err := parseDump("wg0", out)
	if err != nil {
		t.Fatalf("parseDump: %v", err)
	}
	if iface.PublicKey != "PUB_GW" || iface.ListenPort != 51820 {
		t.Fatalf("iface wrong: %+v", iface)
	}
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}
	if peers[0].PublicKey != "PUB_NODE1" || peers[0].LatestHandshakeUnix != 1715000000 {
		t.Fatalf("peer0 wrong: %+v", peers[0])
	}
	if peers[0].PersistentKeepalive != 25 {
		t.Fatalf("keepalive parse: got %d", peers[0].PersistentKeepalive)
	}
	if got := FirstAllowedHost(peers[0]); got != "10.66.66.2" {
		t.Fatalf("FirstAllowedHost=%q want 10.66.66.2", got)
	}
	if peers[1].PersistentKeepalive != 0 {
		t.Fatalf("off should map to 0, got %d", peers[1].PersistentKeepalive)
	}
}

func TestParseDump_Empty(t *testing.T) {
	if _, _, err := parseDump("wg0", ""); err == nil {
		t.Fatal("expected error on empty dump")
	}
}

func TestInspector_ListInterfaces(t *testing.T) {
	m := sysexec.NewMockRunner(map[string]sysexec.Result{
		"wg show interfaces": {Stdout: "wg0 wg1\n"},
	})
	ins := Inspector{Runner: m}
	names, err := ins.ListInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "wg0" {
		t.Fatalf("got %v", names)
	}
}

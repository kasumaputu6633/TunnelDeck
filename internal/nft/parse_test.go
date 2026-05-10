package nft

import (
	"strings"
	"testing"
)

// Realistic fragment of `nft list table ip wg_dnat` that matches the user's
// manual Biznet setup (see project_environment memory).
const sampleWGDNATDump = `table ip wg_dnat {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
		iifname "eth0" tcp dport 25565 dnat to 10.66.66.2:25565
		iifname "eth0" tcp dport 25577 counter dnat to 10.66.66.2:25577
		iifname "eth0" udp dport 19132 dnat to 10.66.66.2:19132
		iifname "eth0" tcp dport 2222 dnat to 10.66.66.2:22
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oifname "wg0" ip daddr 10.66.66.0/24 masquerade
	}
}
`

func TestParseTable_ImportsExistingUserRules(t *testing.T) {
	pt := ParseTable("wg_dnat", "ip", sampleWGDNATDump)

	if len(pt.Forwards) != 4 {
		t.Fatalf("want 4 DNAT forwards, got %d:\n%+v", len(pt.Forwards), pt.Forwards)
	}
	byPort := map[int]ParsedForward{}
	for _, f := range pt.Forwards {
		byPort[f.PublicPort] = f
	}

	cases := []struct {
		port       int
		proto      string
		ip         string
		targetPort int
		counter    bool
	}{
		{25565, "tcp", "10.66.66.2", 25565, false},
		{25577, "tcp", "10.66.66.2", 25577, true}, // counter present
		{19132, "udp", "10.66.66.2", 19132, false},
		{2222, "tcp", "10.66.66.2", 22, false},
	}
	for _, c := range cases {
		got, ok := byPort[c.port]
		if !ok {
			t.Errorf("missing forward for %s/%d", c.proto, c.port)
			continue
		}
		if got.Proto != c.proto || got.TargetIP != c.ip || got.TargetPort != c.targetPort || got.HasCounter != c.counter {
			t.Errorf("port %d: got %+v, want proto=%s ip=%s tport=%d counter=%v", c.port, got, c.proto, c.ip, c.targetPort, c.counter)
		}
	}
}

func TestParseTable_IgnoresMasqueradeAndStructural(t *testing.T) {
	pt := ParseTable("wg_dnat", "ip", sampleWGDNATDump)
	if len(pt.Unknown) != 0 {
		t.Errorf("expected no unknown rules, got: %#v", pt.Unknown)
	}
}

func TestParseTable_CollectsUnknownDNAT(t *testing.T) {
	raw := `table ip wg_dnat {
		chain prerouting {
			type nat hook prerouting priority -100; policy accept;
			ip saddr 1.2.3.4 dnat to 10.0.0.1:80
		}
	}`
	pt := ParseTable("wg_dnat", "ip", raw)
	if len(pt.Forwards) != 0 {
		t.Fatalf("unexpected parse: %+v", pt.Forwards)
	}
	if len(pt.Unknown) != 1 || !strings.Contains(pt.Unknown[0], "saddr 1.2.3.4") {
		t.Fatalf("want the odd rule recorded as unknown, got %+v", pt.Unknown)
	}
}

func TestSplitIPPort(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
		ok   bool
	}{
		{"10.66.66.2:25577", "10.66.66.2", 25577, true},
		{"10.66.66.2", "10.66.66.2", 0, true},
		{"10.66.66.2:25577;", "10.66.66.2", 25577, true},
		{"::1:80", "", 0, false}, // refuse IPv6 ambiguity in this limited parser
	}
	for _, c := range cases {
		ip, port, ok := splitIPPort(c.in)
		if ok != c.ok || ip != c.ip || port != c.port {
			t.Errorf("splitIPPort(%q)=(%q,%d,%v) want (%q,%d,%v)", c.in, ip, port, ok, c.ip, c.port, c.ok)
		}
	}
}

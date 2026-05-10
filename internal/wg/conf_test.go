package wg

import (
	"strings"
	"testing"
)

func TestParseConf_RoundTrips(t *testing.T) {
	src := `[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = PRIV_GW_XXXX
# a user comment we must not crash on
MTU = 1380

[Peer]
# tunneldeck:node=home1
PublicKey = PUB_NODE1
AllowedIPs = 10.66.66.2/32
PersistentKeepalive = 25

[Peer]
PublicKey = PUB_NODE2
AllowedIPs = 10.66.66.3/32, 10.66.66.4/32
Endpoint = 203.0.113.9:51820
`
	c, err := ParseConf(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Address) != 1 || c.Address[0] != "10.66.66.1/24" {
		t.Fatalf("address: %+v", c.Address)
	}
	if c.ListenPort != 51820 {
		t.Fatalf("listen: %d", c.ListenPort)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("peers: %d", len(c.Peers))
	}
	if c.Peers[0].PublicKey != "PUB_NODE1" || c.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("peer0: %+v", c.Peers[0])
	}
	if len(c.Peers[1].AllowedIPs) != 2 {
		t.Fatalf("peer1 allowedips: %+v", c.Peers[1].AllowedIPs)
	}
}

func TestRenderNodeConfig_ContainsExpected(t *testing.T) {
	out := RenderNodeConfig(
		"10.66.66.2/24",
		"<PASTE_NODE_PRIVKEY>",
		"PUB_GW",
		"103.129.148.182:51820",
		"10.66.66.1/32",
		25, 1380,
	)
	for _, want := range []string{
		"[Interface]",
		"Address = 10.66.66.2/24",
		"PrivateKey = <PASTE_NODE_PRIVKEY>",
		"[Peer]",
		"PublicKey = PUB_GW",
		"Endpoint = 103.129.148.182:51820",
		"AllowedIPs = 10.66.66.1/32",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n---\n%s", want, out)
		}
	}
}

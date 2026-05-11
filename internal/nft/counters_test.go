package nft

import "testing"

func TestParseCounters(t *testing.T) {
	raw := `table ip wg_dnat {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
		iifname "eth0" tcp dport 25565 counter packets 10 bytes 600 dnat to 10.66.66.2:25565 comment "td:fwd=1 mc-vanilla"
		iifname "eth0" tcp dport 25577 counter packets 1200 bytes 85000 dnat to 10.66.66.2:25577 comment "td:fwd=2 mc-java"
		iifname "eth0" udp dport 19132 dnat to 10.66.66.2:19132
		iifname "eth0" tcp dport 2222 counter packets 5 bytes 260 dnat to 10.66.66.2:22 comment "td:fwd=4 ssh-relay"
	}
}`
	got := ParseCounters(raw)
	if len(got) != 3 {
		t.Fatalf("want 3 counters (only td:fwd rules), got %d: %+v", len(got), got)
	}

	want := map[int64]RuleCounter{
		1: {ForwardID: 1, Packets: 10, Bytes: 600},
		2: {ForwardID: 2, Packets: 1200, Bytes: 85000},
		4: {ForwardID: 4, Packets: 5, Bytes: 260},
	}
	for _, rc := range got {
		w, ok := want[rc.ForwardID]
		if !ok {
			t.Errorf("unexpected forwardID=%d", rc.ForwardID)
			continue
		}
		if rc != w {
			t.Errorf("fwd=%d got %+v want %+v", rc.ForwardID, rc, w)
		}
	}
}

func TestParseCounters_NoCounterMeansZero(t *testing.T) {
	raw := `iifname "eth0" tcp dport 25565 dnat to 10.66.66.2:25565 comment "td:fwd=7 no-counter"`
	got := ParseCounters(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].ForwardID != 7 || got[0].Packets != 0 || got[0].Bytes != 0 {
		t.Fatalf("rule without counter should parse with 0,0; got %+v", got[0])
	}
}

func TestExtractFwdID(t *testing.T) {
	cases := map[string]int64{
		`comment "td:fwd=42 my-thing"`: 42,
		`comment "td:fwd=1"`:           1,
		`comment "no marker here"`:     0,
		`td:fwd=abc bad`:               0,
	}
	for in, want := range cases {
		if got := extractFwdID(in); got != want {
			t.Errorf("extractFwdID(%q)=%d, want %d", in, got, want)
		}
	}
}

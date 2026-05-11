package updater

import "testing"

func TestParseSHA256SumsFor(t *testing.T) {
	body := `564c3ad9558f5bab62b67287858dc0b939658f9727d7dcdf91fac8a8d0dfa60a  tunneldeck-linux-amd64
3d73d167aed644010734e19674c466d333811bcffd89482052aff5feb776ebae *tunneldeck-linux-arm64
3ff7d75e480bddef7e0a4d34f2a2a28a1166f6f465afdfa2ce32a335e905c4c7 install.sh
`
	cases := map[string]string{
		"tunneldeck-linux-amd64": "564c3ad9558f5bab62b67287858dc0b939658f9727d7dcdf91fac8a8d0dfa60a",
		"tunneldeck-linux-arm64": "3d73d167aed644010734e19674c466d333811bcffd89482052aff5feb776ebae",
		"install.sh":             "3ff7d75e480bddef7e0a4d34f2a2a28a1166f6f465afdfa2ce32a335e905c4c7",
		"does-not-exist":         "",
	}
	for name, want := range cases {
		if got := parseSHA256SumsFor(body, name); got != want {
			t.Errorf("parseSHA256SumsFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseSHA256SumsFor_IgnoresBlankLinesAndJunk(t *testing.T) {
	body := `
# leading comment with single field

abc123
abcdef  tunneldeck-linux-amd64
`
	if got := parseSHA256SumsFor(body, "tunneldeck-linux-amd64"); got != "abcdef" {
		t.Errorf("got %q, want abcdef", got)
	}
}

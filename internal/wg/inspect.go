// Package wg reads and manages a local WireGuard interface. All shelling out
// happens through sysexec.Runner so tests run on any OS.
package wg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tunneldeck/tunneldeck/internal/sysexec"
)

// Peer is one line of `wg show <iface> dump`:
//
//	PUBLIC_KEY \t PRESHARED_KEY \t ENDPOINT \t ALLOWED_IPS \t LATEST_HANDSHAKE \t RX \t TX \t PERSISTENT_KEEPALIVE
type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshakeUnix int64
	RxBytes             int64
	TxBytes             int64
	PersistentKeepalive int
}

// Interface is the first line of `wg show <iface> dump`.
type Interface struct {
	Name       string
	PublicKey  string
	ListenPort int
}

type Inspector struct {
	Runner sysexec.Runner
}

func (ins Inspector) ListInterfaces(ctx context.Context) ([]string, error) {
	r := ins.Runner.Run(ctx, "wg", []string{"show", "interfaces"}, "")
	if r.Err != nil {
		return nil, fmt.Errorf("wg show interfaces: %w (stderr=%q)", r.Err, r.Stderr)
	}
	return strings.Fields(strings.TrimSpace(r.Stdout)), nil
}

func (ins Inspector) Dump(ctx context.Context, iface string) (Interface, []Peer, error) {
	r := ins.Runner.Run(ctx, "wg", []string{"show", iface, "dump"}, "")
	if r.Err != nil {
		return Interface{}, nil, fmt.Errorf("wg show %s dump: %w (stderr=%q)", iface, r.Err, r.Stderr)
	}
	return parseDump(iface, r.Stdout)
}

func parseDump(iface, out string) (Interface, []Peer, error) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return Interface{}, nil, errors.New("empty wg dump")
	}

	head := strings.Split(lines[0], "\t")
	if len(head) < 4 {
		return Interface{}, nil, fmt.Errorf("malformed interface line: %q", lines[0])
	}
	port, err := strconv.Atoi(head[2])
	if err != nil {
		return Interface{}, nil, fmt.Errorf("bad listen port %q: %w", head[2], err)
	}
	iinfo := Interface{Name: iface, PublicKey: head[1], ListenPort: port}

	var peers []Peer
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return Interface{}, nil, fmt.Errorf("malformed peer line: %q", line)
		}
		p := Peer{
			PublicKey:    f[0],
			PresharedKey: normalizeNone(f[1]),
			Endpoint:     f[2],
		}
		if f[3] != "(none)" && f[3] != "" {
			for _, aip := range strings.Split(f[3], ",") {
				p.AllowedIPs = append(p.AllowedIPs, strings.TrimSpace(aip))
			}
		}
		if hs, err := strconv.ParseInt(f[4], 10, 64); err == nil {
			p.LatestHandshakeUnix = hs
		}
		if rx, err := strconv.ParseInt(f[5], 10, 64); err == nil {
			p.RxBytes = rx
		}
		if tx, err := strconv.ParseInt(f[6], 10, 64); err == nil {
			p.TxBytes = tx
		}
		if ka, err := strconv.Atoi(strings.TrimSpace(f[7])); err == nil {
			p.PersistentKeepalive = ka
		} else if strings.TrimSpace(f[7]) == "off" {
			p.PersistentKeepalive = 0
		}
		peers = append(peers, p)
	}
	return iinfo, peers, nil
}

func normalizeNone(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

// FirstAllowedHost returns the first AllowedIPs entry without its CIDR mask
// ("10.66.66.2/32" → "10.66.66.2"). Empty string if the peer has none.
func FirstAllowedHost(p Peer) string {
	for _, aip := range p.AllowedIPs {
		if i := strings.Index(aip, "/"); i > 0 {
			return aip[:i]
		}
		return aip
	}
	return ""
}

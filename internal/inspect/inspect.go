// Package inspect collects a read-only view of the host's WireGuard,
// nftables, and network state. Output feeds the Adopt wizard.
package inspect

import (
	"context"
	"strings"

	"github.com/tunneldeck/tunneldeck/internal/nft"
	"github.com/tunneldeck/tunneldeck/internal/sysexec"
	"github.com/tunneldeck/tunneldeck/internal/wg"
)

type Report struct {
	IsLinux       bool
	IsRoot        bool
	DefaultWANIf  string
	PublicIPGuess string

	WGInstalled   bool
	WGInterfaces  []string
	WGPrimary     string
	WGPublicKey   string
	WGListenPort  int
	WGGatewayIP   string
	WGPeers       []wg.Peer
	WGConfPresent bool
	WGConfPath    string

	NFTInstalled bool
	NFTTables    [][2]string
	NFTDetected  []nft.ParsedTable

	IPForward bool
	UFWActive bool
}

type Host struct {
	Runner     sysexec.Runner
	WGConfPath string
	ReadFile   func(path string) ([]byte, error)
	IsUIDZero  func() bool
}

// Run performs the detection. Probe failures are not fatal — each section is
// filled in independently, so missing tools just leave empty fields.
func (h Host) Run(ctx context.Context) Report {
	r := Report{}
	r.IsLinux = sysexec.Which("uname")

	if h.IsUIDZero != nil {
		r.IsRoot = h.IsUIDZero()
	}

	if res := h.Runner.Run(ctx, "ip", []string{"-4", "route", "show", "default"}, ""); res.Err == nil {
		r.DefaultWANIf = parseDefaultWAN(res.Stdout)
	}

	if sysexec.Which("wg") {
		r.WGInstalled = true
		ins := wg.Inspector{Runner: h.Runner}
		if ifaces, err := ins.ListInterfaces(ctx); err == nil {
			r.WGInterfaces = ifaces
			r.WGPrimary = pickPrimary(ifaces)
		}
		if r.WGPrimary != "" {
			if info, peers, err := ins.Dump(ctx, r.WGPrimary); err == nil {
				r.WGPublicKey = info.PublicKey
				r.WGListenPort = info.ListenPort
				r.WGPeers = peers
			}
		}
	}

	// wg0.conf on disk often reveals Address/ListenPort even when the
	// interface itself is down.
	confPath := h.WGConfPath
	if confPath == "" {
		confPath = "/etc/wireguard/wg0.conf"
	}
	r.WGConfPath = confPath
	if h.ReadFile != nil {
		if b, err := h.ReadFile(confPath); err == nil {
			if c, err := wg.ParseConf(strings.NewReader(string(b))); err == nil {
				r.WGConfPresent = true
				if len(c.Address) > 0 {
					r.WGGatewayIP = c.Address[0]
				}
				if r.WGListenPort == 0 {
					r.WGListenPort = c.ListenPort
				}
			}
		}
	}

	if sysexec.Which("nft") {
		r.NFTInstalled = true
		nc := nft.Client{Runner: h.Runner}
		if tables, err := nc.ListTables(ctx); err == nil {
			r.NFTTables = tables
			for _, tf := range tables {
				if tf[0] != "ip" {
					continue
				}
				if pt, err := nc.InspectTable(ctx, tf[1]); err == nil && len(pt.Forwards)+len(pt.Unknown) > 0 {
					r.NFTDetected = append(r.NFTDetected, pt)
				}
			}
		}
	}

	if h.ReadFile != nil {
		if b, err := h.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
			r.IPForward = strings.TrimSpace(string(b)) == "1"
		}
	}

	if sysexec.Which("ufw") {
		if res := h.Runner.Run(ctx, "ufw", []string{"status"}, ""); res.Err == nil {
			r.UFWActive = strings.Contains(strings.ToLower(res.Stdout), "status: active")
		}
	}

	return r
}

// parseDefaultWAN extracts "dev <IF>" from `ip route show default`.
// Example input: "default via 103.129.148.1 dev eth0 proto static"
func parseDefaultWAN(s string) string {
	f := strings.Fields(s)
	for i := 0; i < len(f)-1; i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

func pickPrimary(ifaces []string) string {
	for _, i := range ifaces {
		if i == "wg0" {
			return "wg0"
		}
	}
	if len(ifaces) > 0 {
		return ifaces[0]
	}
	return ""
}

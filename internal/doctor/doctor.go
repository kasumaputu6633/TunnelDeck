// Package doctor runs read-only diagnostic checks on the local host.
// Consumed by the `tunneldeck doctor` CLI and future UI pages. Checks never
// fail fast — the full result list is returned so the user sees every issue
// at once.
package doctor

import (
	"context"
	"os"
	"strings"

	"github.com/kasumaputu6633/tunneldeck/internal/nft"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
)

type Level string

const (
	OK    Level = "ok"
	Warn  Level = "warn"
	Error Level = "error"
	Info  Level = "info"
)

type Result struct {
	Level  Level
	Name   string
	Detail string
}

func Run(ctx context.Context, runner sysexec.Runner) []Result {
	var out []Result
	add := func(l Level, n, d string) { out = append(out, Result{Level: l, Name: n, Detail: d}) }

	for _, bin := range []string{"wg", "nft", "ip", "ping"} {
		if sysexec.Which(bin) {
			add(OK, "bin:"+bin, "found on PATH")
		} else {
			add(Warn, "bin:"+bin, "not found; some features will be disabled")
		}
	}

	if os.Geteuid() == 0 {
		add(OK, "privilege", "running as root")
	} else {
		add(Warn, "privilege", "not running as root; wg/nft changes will require sudo")
	}

	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			add(OK, "ip_forward", "enabled")
		} else {
			add(Error, "ip_forward", "disabled — DNAT won't work until 'sysctl -w net.ipv4.ip_forward=1'")
		}
	} else {
		add(Info, "ip_forward", "couldn't read /proc (non-Linux?)")
	}

	if r := runner.Run(ctx, "ip", []string{"-4", "route", "show", "default"}, ""); r.Err == nil && r.Stdout != "" {
		add(OK, "wan:route", strings.TrimSpace(firstLine(r.Stdout)))
	} else {
		add(Warn, "wan:route", "no default route detected")
	}

	if sysexec.Which("wg") {
		if r := runner.Run(ctx, "wg", []string{"show", "interfaces"}, ""); r.Err == nil {
			names := strings.Fields(strings.TrimSpace(r.Stdout))
			if len(names) == 0 {
				add(Warn, "wg:interfaces", "no wg interfaces up")
			} else {
				add(OK, "wg:interfaces", strings.Join(names, " "))
			}
		}
	}

	if sysexec.Which("nft") {
		nc := nft.Client{Runner: runner}
		if tables, err := nc.ListTables(ctx); err == nil {
			if len(tables) == 0 {
				add(Info, "nft:tables", "no nft tables present")
			} else {
				var parts []string
				for _, tf := range tables {
					parts = append(parts, tf[0]+" "+tf[1])
				}
				add(OK, "nft:tables", strings.Join(parts, ", "))
			}
		}
	}

	if sysexec.Which("ufw") {
		if r := runner.Run(ctx, "ufw", []string{"status"}, ""); r.Err == nil {
			first := strings.TrimSpace(firstLine(r.Stdout))
			lvl := Info
			if strings.Contains(strings.ToLower(first), "active") {
				lvl = Warn
			}
			add(lvl, "ufw", first)
		}
	} else {
		add(Info, "ufw", "not installed")
	}

	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

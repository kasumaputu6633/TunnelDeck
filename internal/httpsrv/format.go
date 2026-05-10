package httpsrv

import (
	"fmt"
	"time"
)

// formatBytes turns a byte count into a human-readable string with a
// dynamic unit: B, KB, MB, GB, TB. Binary (1024) not decimal, matching
// what `wg show` reports.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for rem := n / unit; rem >= unit; rem /= unit {
		div *= unit
		exp++
	}
	// Max exp index is 4 (TB); anything beyond that stays at TB.
	suffixes := [...]string{"KB", "MB", "GB", "TB", "PB"}
	if exp > len(suffixes)-1 {
		exp = len(suffixes) - 1
	}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(div), suffixes[exp])
}

// formatHandshake turns a unix timestamp into "N seconds/minutes/hours ago".
// Returns "never" when ts is 0 (wg's convention for "no handshake yet").
func formatHandshake(ts int64) string {
	if ts == 0 {
		return "never"
	}
	d := time.Since(time.Unix(ts, 0))
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

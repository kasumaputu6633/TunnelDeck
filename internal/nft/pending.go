package nft

import (
	"context"
	"sort"
	"strconv"
)

// PendingState describes whether the DB forward list matches what is
// currently loaded in the managed nft table.
type PendingState struct {
	// HasPending is true when at least one enabled DB forward is missing
	// from the live nft table, or a live nft rule has no matching enabled
	// DB forward (i.e. a delete hasn't been applied yet).
	HasPending bool
	// Missing are (proto, port) pairs enabled in DB but absent from nft.
	Missing []string
	// Stale are (proto, port) pairs present in nft but disabled/deleted in DB.
	Stale []string
}

// CheckPending compares the enabled DB forwards against the live nft table
// and returns a PendingState. Both slices are (proto/port) strings for
// display; the caller doesn't need to parse them.
//
// dbForwards: all forwards from the DB (enabled and disabled).
// table: the managed nft table name.
func (c Client) CheckPending(ctx context.Context, dbForwards []DBForwardSummary, table string) PendingState {
	live, err := c.CountersByForwardID(ctx, table)
	if err != nil {
		// If we can't read nft, assume pending so the user is prompted to apply.
		return PendingState{HasPending: true, Missing: []string{"(could not read nft table)"}}
	}

	// Build set of (proto:port) that are live in nft, keyed by forward ID.
	liveIDs := map[int64]bool{}
	for id := range live {
		liveIDs[id] = true
	}

	var missing, stale []string

	// Enabled DB forwards that are not in nft → need apply.
	for _, f := range dbForwards {
		if !f.Enabled {
			continue
		}
		if !liveIDs[f.ID] {
			missing = append(missing, f.Proto+"/"+strconv.Itoa(f.PublicPort))
		}
	}

	// nft rules whose forward ID is not enabled in DB → stale rule.
	enabledIDs := map[int64]bool{}
	for _, f := range dbForwards {
		if f.Enabled {
			enabledIDs[f.ID] = true
		}
	}
	for id := range liveIDs {
		if !enabledIDs[id] {
			// Find the proto/port for display.
			for _, f := range dbForwards {
				if f.ID == id {
					stale = append(stale, f.Proto+"/"+strconv.Itoa(f.PublicPort))
					break
				}
			}
		}
	}

	sort.Strings(missing)
	sort.Strings(stale)

	return PendingState{
		HasPending: len(missing) > 0 || len(stale) > 0,
		Missing:    missing,
		Stale:      stale,
	}
}

// DBForwardSummary is the minimal forward info CheckPending needs.
// Avoids importing the db package into nft (would create a cycle).
type DBForwardSummary struct {
	ID         int64
	Proto      string
	PublicPort int
	Enabled    bool
}

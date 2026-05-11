package httpsrv

import (
	"net/http"
	"strconv"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
)

// pageFromRequest parses ?page=N&per=M from the URL and normalizes them.
// Used by every paginated handler so query-string handling is consistent.
func pageFromRequest(r *http.Request) db.Page {
	p := db.Page{}
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil {
		p.Page = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("per")); err == nil {
		p.PerPage = v
	}
	return p.Normalize()
}
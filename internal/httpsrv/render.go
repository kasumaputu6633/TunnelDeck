package httpsrv

import (
	"bytes"
	"log"
	"net/http"
	"time"

	"github.com/kasumaputu6633/tunneldeck/internal/auth"
	"github.com/kasumaputu6633/tunneldeck/internal/updater"
)

type Flash struct {
	Kind string // "ok" | "warn" | "error"
	Text string
}

// updateBanner is the data the base template uses to render the top-of-page
// "update available" notification. Zero value = no banner.
type updateBanner struct {
	Available  bool
	Tag        string
	Reason     string
	LastCheck  time.Time
	CSRFToken  string
}

type pageData struct {
	Title   string
	Session *auth.Session
	Flash   *Flash
	Update  updateBanner
	Data    any
}

// render executes the named page with the standard envelope. Output is
// buffered so a template error doesn't leave the response half-written with
// a 200 status code.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page, title string, data any, flash *Flash) {
	t, ok := s.Templates[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	sess := sessionFromCtx(r.Context())
	pd := pageData{
		Title:   title,
		Session: sess,
		Flash:   flash,
		Update:  s.bannerFor(sess),
		Data:    data,
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", pd); err != nil {
		log.Printf("template %s: %v", page, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// bannerFor returns the update banner to show on this request. Only shown
// when the user is logged in AND the background check has said an update
// is available.
func (s *Server) bannerFor(sess *auth.Session) updateBanner {
	if sess == nil {
		return updateBanner{}
	}
	st, ts := s.updateStatus()
	if !st.UpdateAvailable {
		return updateBanner{}
	}
	return updateBanner{
		Available: true,
		Tag:       st.RemoteTag,
		Reason:    reasonSummary(st),
		LastCheck: ts,
		CSRFToken: sess.CSRFToken,
	}
}

func reasonSummary(st updater.Status) string {
	if st.RemoteSHA != "" && st.CurrentSHA != "" && st.RemoteSHA != st.CurrentSHA && st.RemoteTag == st.CurrentVersion {
		return "binary changed on the same tag — your build is stale"
	}
	return "a newer release has been published"
}

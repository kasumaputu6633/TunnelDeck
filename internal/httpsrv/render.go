package httpsrv

import (
	"bytes"
	"log"
	"net/http"

	"github.com/tunneldeck/tunneldeck/internal/auth"
)

type Flash struct {
	Kind string // "ok" | "warn" | "error"
	Text string
}

type pageData struct {
	Title   string
	Session *auth.Session
	Flash   *Flash
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
	pd := pageData{
		Title:   title,
		Session: sessionFromCtx(r.Context()),
		Flash:   flash,
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

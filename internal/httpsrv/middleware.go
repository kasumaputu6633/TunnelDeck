package httpsrv

import (
	"context"
	"net/http"

	"github.com/tunneldeck/tunneldeck/internal/auth"
)

func sessionFromCtx(ctx context.Context) *auth.Session {
	v, _ := ctx.Value(ctxSession).(*auth.Session)
	return v
}

// sessionMW attaches the current *auth.Session (if any) to the request
// context. requireAuth handles redirection — this middleware never rejects.
func (s *Server) sessionMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookie)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, _ := s.Deps.Auth.Lookup(r.Context(), c.Value)
		if sess != nil {
			ctx := context.WithValue(r.Context(), ctxSession, sess)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionFromCtx(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfMW enforces CSRF on every non-GET request. Forms submit the token in
// the "csrf" field; HTMX requests may use the X-CSRF-Token header.
func (s *Server) csrfMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		sess := sessionFromCtx(r.Context())
		if sess == nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			got = r.PostFormValue("csrf")
		}
		if got == "" || got != sess.CSRFToken {
			http.Error(w, "csrf token mismatch", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

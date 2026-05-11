// Package httpsrv wires the Web UI: router, middleware, templates, handlers.
package httpsrv

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/kasumaputu6633/tunneldeck/internal/auth"
	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/nft"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
	"github.com/kasumaputu6633/tunneldeck/internal/updater"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Deps struct {
	DB     *db.DB
	Auth   *auth.Service
	NFT    nft.Client
	Runner sysexec.Runner
	// TLSOn controls whether the session cookie sets Secure.
	TLSOn bool
	// DryRunNFT, when true, renders nftables changes but never applies them.
	DryRunNFT bool
	// UpdateRepo is where the updater polls for releases. Empty string
	// disables the background check entirely.
	UpdateRepo string
	// Version is the build-time version string (main.version). Used by the
	// update check to compare against GitHub release tags.
	Version string
}

// Server holds the router plus a per-page template map. One template tree per
// page lets multiple pages each define "content" without colliding.
type Server struct {
	Router    *chi.Mux
	Templates map[string]*template.Template
	Deps      Deps

	// Update-check state. Guarded by updMu. The background goroutine
	// refreshes lastUpdate every 6 hours; requireAuth middleware reads it
	// to render the UI banner.
	updMu      sync.RWMutex
	lastUpdate updater.Status
	updateAt   time.Time
}

// updateStatus returns a snapshot of the most recent update check, safe to
// consume from any handler.
func (s *Server) updateStatus() (updater.Status, time.Time) {
	s.updMu.RLock()
	defer s.updMu.RUnlock()
	return s.lastUpdate, s.updateAt
}

// StartBackgroundChecks kicks off goroutines that refresh the update cache.
// The first check fires 30s after boot to let the service settle; subsequent
// checks run every 6 hours. Safe to call once from main after New().
func (s *Server) StartBackgroundChecks(ctx context.Context) {
	if s.Deps.UpdateRepo == "" {
		return
	}
	go func() {
		// initial delay so boot logs stay clean
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		s.refreshUpdateStatus(ctx)

		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refreshUpdateStatus(ctx)
			}
		}
	}()
}

func (s *Server) refreshUpdateStatus(ctx context.Context) {
	binPath, err := os.Executable()
	if err != nil {
		log.Printf("updater: os.Executable: %v", err)
		return
	}
	st := updater.Check(ctx, s.Deps.UpdateRepo, binPath, s.Deps.Version)
	s.updMu.Lock()
	s.lastUpdate = st
	s.updateAt = time.Now()
	s.updMu.Unlock()
	if st.UpdateAvailable {
		log.Printf("updater: %s", st.Reason)
	}
}

type contextKey int

const ctxSession contextKey = 1

// New builds a Server with routes and middleware wired up.
func New(deps Deps) (*Server, error) {
	tmpls, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{Deps: deps, Templates: tmpls}

	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(s.sessionMW)

	sub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))

	r.Get("/login", s.getLogin)
	r.Post("/login", s.postLogin)
	r.Post("/logout", s.postLogout)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	r.Group(func(gr chi.Router) {
		gr.Use(s.requireAuth)
		gr.Use(s.csrfMW)

		gr.Get("/", s.dashboard)
		gr.Get("/dashboard/fragment", s.dashboardFragment)
		gr.Get("/nodes", s.listNodes)
		gr.Get("/nodes/fragment", s.nodesFragment)
		gr.Post("/nodes", s.createNode)
		gr.Get("/nodes/{id}/setup", s.nodeSetup)
		gr.Get("/nodes/{id}/status", s.nodeStatus)
		gr.Post("/nodes/{id}/register-pubkey", s.registerNodePubkey)
		gr.Post("/nodes/{id}/delete", s.deleteNode)

		gr.Get("/forwards", s.listForwards)
		gr.Get("/forwards/fragment", s.forwardsFragment)
		gr.Post("/forwards", s.createForward)
		gr.Post("/forwards/{id}/toggle", s.toggleForward)
		gr.Post("/forwards/{id}/delete", s.deleteForward)
		gr.Post("/forwards/apply", s.applyForwards)

		gr.Get("/inspect", s.getInspect)
		gr.Get("/inspect/fragment", s.inspectFragment)
		gr.Post("/adopt", s.postAdopt)

		gr.Get("/logs", s.logs)
		gr.Get("/logs/fragment", s.logsFragment)
		gr.Get("/settings", s.getSettings)
		gr.Post("/settings", s.postSettings)

		gr.Post("/admin/update", s.postAdminUpdate)
		gr.Get("/admin/update/status", s.getAdminUpdateStatus)
	})

	s.Router = r
	return s, nil
}

func parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"hasPrefix": func(s, prefix string) bool {
			return len(s) >= len(prefix) && s[:len(prefix)] == prefix
		},
		"stripCIDR": func(s string) string {
			if i := strings.Index(s, "/"); i > 0 {
				return s[:i]
			}
			return s
		},
		"formatBytes":     formatBytes,
		"formatHandshake": formatHandshake,
		"add":             func(a, b int) int { return a + b },
		"sub":             func(a, b int) int { return a - b },
		"seq": func(start, end int) []int {
			if end < start {
				return nil
			}
			out := make([]int, 0, end-start+1)
			for i := start; i <= end; i++ {
				out = append(out, i)
			}
			return out
		},
		// dict builds a map[string]any from alternating key/value pairs.
		// Used to pass named args to sub-templates like {{template "pagination" (dict "Page" .Page ...)}}.
		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, fmt.Errorf("dict: odd number of arguments")
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				k, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict: key %v is not a string", pairs[i])
				}
				m[k] = pairs[i+1]
			}
			return m, nil
		},
	}

	baseBytes, err := templatesFS.ReadFile("templates/_base.html")
	if err != nil {
		return nil, err
	}

	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}

	// First pass: collect partial templates (_partial_*.html). These
	// define named blocks (e.g. "pagination") that every page can {{template}}
	// include. Parsed into every tree below so the block name resolves.
	var partials []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		if strings.HasPrefix(e.Name(), "_partial_") {
			b, err := templatesFS.ReadFile("templates/" + e.Name())
			if err != nil {
				return nil, err
			}
			partials = append(partials, string(b))
		}
	}

	out := map[string]*template.Template{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") || e.Name() == "_base.html" {
			continue
		}
		if strings.HasPrefix(e.Name(), "_partial_") {
			continue
		}
		pageBytes, err := templatesFS.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(e.Name(), ".html")

		// Files starting with "_frag_" are HTMX fragments — no base layout.
		// They're rendered directly via ExecuteTemplate(w, "fragment", data).
		if strings.HasPrefix(e.Name(), "_frag_") {
			t, err := template.New(e.Name()).Funcs(funcs).Parse(string(pageBytes))
			if err != nil {
				return nil, err
			}
			for _, p := range partials {
				if _, err := t.Parse(p); err != nil {
					return nil, err
				}
			}
			out[strings.TrimPrefix(name, "_frag_")] = t
			continue
		}

		t, err := template.New(e.Name()).Funcs(funcs).Parse(string(baseBytes))
		if err != nil {
			return nil, err
		}
		if _, err := t.Parse(string(pageBytes)); err != nil {
			return nil, err
		}
		for _, p := range partials {
			if _, err := t.Parse(p); err != nil {
				return nil, err
			}
		}
		out[name] = t
	}
	return out, nil
}

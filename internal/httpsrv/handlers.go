package httpsrv

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tunneldeck/tunneldeck/internal/adopt"
	"github.com/tunneldeck/tunneldeck/internal/auth"
	"github.com/tunneldeck/tunneldeck/internal/db"
	"github.com/tunneldeck/tunneldeck/internal/forwards"
	"github.com/tunneldeck/tunneldeck/internal/inspect"
	"github.com/tunneldeck/tunneldeck/internal/nft"
	"github.com/tunneldeck/tunneldeck/internal/wg"
)

// ---- login / logout ----

type loginData struct{ Error string }

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if sessionFromCtx(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", "Sign in", loginData{}, nil)
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	sid, _, err := s.Deps.Auth.Login(r.Context(), user, pw, auth.ClientIP(r))
	if err != nil {
		s.render(w, r, "login", "Sign in", loginData{Error: err.Error()}, nil)
		return
	}
	auth.SetCookie(w, sid, s.Deps.TLSOn)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionFromCtx(r.Context()); sess != nil {
		// CSRF mw doesn't cover public routes — enforce here.
		if r.PostFormValue("csrf") != sess.CSRFToken {
			http.Error(w, "csrf token mismatch", http.StatusForbidden)
			return
		}
		_ = s.Deps.Auth.Logout(r.Context(), sess.ID)
	}
	auth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard ----

type dashboardData struct {
	Gateway        db.Gateway
	NodeCount      int
	OnlineCount    int
	ForwardCount   int
	EnabledCount   int
	RecentAudit    []db.AuditEntry
	WGPeers        []wg.Peer
	WGPeerMap      map[string]wg.Peer // keyed by WG IP host
	TotalRx        int64
	TotalTx        int64
	OnlineWindow   int // seconds
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)

	nodes, _ := s.Deps.DB.ListNodes(ctx)
	fwds, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	audits, _ := s.Deps.DB.ListAudit(ctx, 20)

	// Live peer data (may be empty on Windows dev / no wg).
	peers := liveWGPeers(ctx, s, g.WGIf)
	peerMap := map[string]wg.Peer{}
	for _, p := range peers {
		peerMap[wg.FirstAllowedHost(p)] = p
	}

	const onlineWindow = 120
	cutoff := time.Now().Add(-onlineWindow * time.Second).Unix()
	online := 0
	var totalRx, totalTx int64
	for _, p := range peers {
		if p.LatestHandshakeUnix >= cutoff {
			online++
		}
		totalRx += p.RxBytes
		totalTx += p.TxBytes
	}

	enabled := 0
	for _, f := range fwds {
		if f.Enabled {
			enabled++
		}
	}

	d := dashboardData{
		Gateway:      g,
		NodeCount:    len(nodes),
		OnlineCount:  online,
		ForwardCount: len(fwds),
		EnabledCount: enabled,
		RecentAudit:  audits,
		WGPeers:      peers,
		WGPeerMap:    peerMap,
		TotalRx:      totalRx,
		TotalTx:      totalTx,
		OnlineWindow: onlineWindow,
	}
	s.render(w, r, "dashboard", "Dashboard", d, flashFromQuery(r))
}

// ---- nodes ----

type nodesData struct {
	Gateway  db.Gateway
	Nodes    []nodeRow
	NextIP   string
	NewNode  nodeSetup
	Err      string
}

type nodeRow struct {
	Node          db.Node
	Online        bool
	LatestHS      string
	RxBytes       int64
	TxBytes       int64
}

type nodeSetup struct {
	Name         string
	WGIP         string
	JoinToken    string
	ConfigPreview string
	Show         bool
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	peers := liveWGPeers(ctx, s, g.WGIf)

	cutoff := time.Now().Add(-2 * time.Minute).Unix()
	rows := make([]nodeRow, 0, len(nodes))
	for _, n := range nodes {
		row := nodeRow{Node: n}
		for _, p := range peers {
			if wg.FirstAllowedHost(p) != n.WGIP {
				continue
			}
			row.Online = p.LatestHandshakeUnix >= cutoff
			if p.LatestHandshakeUnix > 0 {
				row.LatestHS = time.Since(time.Unix(p.LatestHandshakeUnix, 0)).Truncate(time.Second).String() + " ago"
			} else {
				row.LatestHS = "never"
			}
			row.RxBytes = p.RxBytes
			row.TxBytes = p.TxBytes
			break
		}
		rows = append(rows, row)
	}

	used := make([]string, 0, len(nodes))
	for _, n := range nodes {
		used = append(used, n.WGIP)
	}
	next, _ := forwards.AllocateNextIP(g.WGSubnet, stripCIDR(g.WGIP), used)

	s.render(w, r, "nodes", "Nodes", nodesData{
		Gateway: g,
		Nodes:   rows,
		NextIP:  next,
	}, flashFromQuery(r))
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/nodes?flash=error:name+required", http.StatusSeeOther)
		return
	}

	g, err := s.Deps.DB.GetGateway(ctx)
	if err != nil {
		http.Error(w, "gateway: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	used := make([]string, 0, len(nodes))
	for _, n := range nodes {
		used = append(used, n.WGIP)
	}
	wgIP, err := forwards.AllocateNextIP(g.WGSubnet, stripCIDR(g.WGIP), used)
	if err != nil {
		http.Redirect(w, r, "/nodes?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}

	id, err := s.Deps.DB.CreateNode(ctx, db.Node{
		Name:      name,
		WGIP:      wgIP,
		Keepalive: 25,
	})
	if err != nil {
		http.Redirect(w, r, "/nodes?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}

	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "node.add", fmt.Sprintf("%d", id),
		fmt.Sprintf(`{"name":%q,"wg_ip":%q}`, name, wgIP))

	http.Redirect(w, r, fmt.Sprintf("/nodes?flash=ok:node+%s+added+(%s)", name, wgIP), http.StatusSeeOther)
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.Deps.DB.DeleteNode(r.Context(), id); err != nil {
		http.Redirect(w, r, "/nodes?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	_ = s.Deps.DB.AuditWrite(r.Context(), currentActor(r), "node.delete", fmt.Sprintf("%d", id), "{}")
	http.Redirect(w, r, "/nodes?flash=ok:node+deleted", http.StatusSeeOther)
}

// ---- forwards ----

type forwardsData struct {
	Gateway  db.Gateway
	Forwards []db.Forward
	Nodes    []db.Node
	Issues   []forwards.Issue
	Form     forwards.Input
	ApplyPreview string
}

func (s *Server) listForwards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)
	fwds, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	s.render(w, r, "forwards", "Forwards", forwardsData{
		Gateway:  g,
		Forwards: fwds,
		Nodes:    nodes,
	}, flashFromQuery(r))
}

func (s *Server) createForward(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	in := forwards.Input{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Proto:       r.PostFormValue("proto"),
		Description: r.PostFormValue("description"),
		LogMode:     r.PostFormValue("log_mode"),
	}
	in.PublicPort, _ = strconv.Atoi(r.PostFormValue("public_port"))
	in.TargetPort, _ = strconv.Atoi(r.PostFormValue("target_port"))
	in.NodeID, _ = strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	confirmWarn := r.PostFormValue("confirm_warn") == "1"

	existing, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	g, _ := s.Deps.DB.GetGateway(ctx)
	protected := forwards.BuildProtectedList(22, g.WGPort, g.UIPort)

	issues := forwards.Validate(ctx, in, existing, nodes, protected, 0)
	if forwards.HasErrors(issues) || (hasWarn(issues) && !confirmWarn) {
		s.render(w, r, "forwards", "Forwards", forwardsData{
			Gateway: g, Forwards: existing, Nodes: nodes,
			Issues: issues, Form: in,
		}, &Flash{Kind: "warn", Text: "please review the issues below"})
		return
	}
	if in.LogMode == "" {
		in.LogMode = "counter"
	}
	id, err := s.Deps.DB.CreateForward(ctx, db.Forward{
		Name: in.Name, Proto: in.Proto, PublicPort: in.PublicPort,
		NodeID: in.NodeID, TargetPort: in.TargetPort,
		Description: in.Description, Enabled: true, LogMode: in.LogMode,
	})
	if err != nil {
		http.Redirect(w, r, "/forwards?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "forward.add", fmt.Sprintf("%d", id),
		fmt.Sprintf(`{"proto":%q,"public_port":%d,"target_port":%d}`, in.Proto, in.PublicPort, in.TargetPort))
	http.Redirect(w, r, "/forwards?flash=ok:forward+added+(remember+to+apply)", http.StatusSeeOther)
}

func (s *Server) toggleForward(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	enabled := r.PostFormValue("enabled") == "1"
	if err := s.Deps.DB.SetForwardEnabled(r.Context(), id, enabled); err != nil {
		http.Redirect(w, r, "/forwards?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	_ = s.Deps.DB.AuditWrite(r.Context(), currentActor(r), "forward.toggle",
		fmt.Sprintf("%d", id), fmt.Sprintf(`{"enabled":%v}`, enabled))
	http.Redirect(w, r, "/forwards?flash=ok:forward+toggled+(apply+to+take+effect)", http.StatusSeeOther)
}

func (s *Server) deleteForward(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := s.Deps.DB.DeleteForward(r.Context(), id); err != nil {
		http.Redirect(w, r, "/forwards?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	_ = s.Deps.DB.AuditWrite(r.Context(), currentActor(r), "forward.delete", fmt.Sprintf("%d", id), "{}")
	http.Redirect(w, r, "/forwards?flash=ok:forward+deleted+(apply+to+take+effect)", http.StatusSeeOther)
}

// applyForwards renders enabled forwards into nftables and applies them.
// DryRunNFT (or monitor-only adopt mode) renders without applying; the UI
// shows the resulting script.
func (s *Server) applyForwards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, err := s.Deps.DB.GetGateway(ctx)
	if err != nil {
		http.Error(w, "gateway: "+err.Error(), http.StatusInternalServerError)
		return
	}

	all, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	var enabled []db.Forward
	for _, f := range all {
		if f.Enabled {
			enabled = append(enabled, f)
		}
	}

	spec := nft.RenderSpec{
		TableName: g.ManagedNFTTable,
		WANIf:     g.WANIf,
		WGIf:      g.WGIf,
		WGSubnet:  g.WGSubnet,
		Forwards:  enabled,
	}

	dry := s.Deps.DryRunNFT || g.AdoptMode == "monitor-only"
	res, err := s.Deps.NFT.Apply(ctx, nft.ApplyInput{
		Spec:      spec,
		BackupDir: "/var/lib/tunneldeck/backups",
		DB:        s.Deps.DB,
		Actor:     currentActor(r),
		DryRun:    dry,
	})
	if err != nil {
		nodes, _ := s.Deps.DB.ListNodes(ctx)
		s.render(w, r, "forwards", "Forwards", forwardsData{
			Gateway: g, Forwards: all, Nodes: nodes, ApplyPreview: res.Script,
		}, &Flash{Kind: "error", Text: err.Error()})
		return
	}
	kind := "ok"
	msg := "nft applied (" + strconv.Itoa(len(enabled)) + " forwards, backup: " + res.BackupPath + ")"
	if res.DryRun {
		kind = "warn"
		msg = "dry-run: nft script rendered but not applied (monitor mode)"
	}
	http.Redirect(w, r, "/forwards?flash="+kind+":"+msg, http.StatusSeeOther)
}

// ---- inspect / adopt ----

type inspectData struct {
	Report inspect.Report
	Gateway db.Gateway
}

func (s *Server) getInspect(w http.ResponseWriter, r *http.Request) {
	g, _ := s.Deps.DB.GetGateway(r.Context())
	rep := inspect.Host{Runner: s.Deps.Runner}.Run(r.Context())
	s.render(w, r, "inspect", "Inspect", inspectData{Report: rep, Gateway: g}, flashFromQuery(r))
}

func (s *Server) postAdopt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rep := inspect.Host{Runner: s.Deps.Runner}.Run(ctx)

	runner := adopt.Runner{DB: s.Deps.DB, Runner: s.Deps.Runner}
	opts := adopt.Options{
		BackupDir:   "/var/lib/tunneldeck/backups",
		Actor:       currentActor(r),
		NFTStrategy: r.PostFormValue("nft_strategy"),
		PublicIP:    strings.TrimSpace(r.PostFormValue("public_ip")),
	}
	res, err := runner.Run(ctx, rep, opts)
	if err != nil {
		http.Redirect(w, r, "/inspect?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	msg := fmt.Sprintf("adopted: %d nodes, %d forwards, table=%s (backups=%d)",
		res.NodesImported, res.ForwardsImported, res.ManagedTable, len(res.BackedUp))
	http.Redirect(w, r, "/?flash=ok:"+msg, http.StatusSeeOther)
}

// ---- logs ----

type logsData struct{ Audit []db.AuditEntry }

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	audits, _ := s.Deps.DB.ListAudit(r.Context(), 500)
	s.render(w, r, "logs", "Logs", logsData{Audit: audits}, flashFromQuery(r))
}

// ---- settings ----

type settingsData struct{ Gateway db.Gateway }

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	g, _ := s.Deps.DB.GetGateway(r.Context())
	s.render(w, r, "settings", "Settings", settingsData{Gateway: g}, flashFromQuery(r))
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, err := s.Deps.DB.GetGateway(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if v := strings.TrimSpace(r.PostFormValue("public_ip")); v != "" {
		g.PublicIP = v
	}
	if v := strings.TrimSpace(r.PostFormValue("wan_if")); v != "" {
		g.WANIf = v
	}
	if v := strings.TrimSpace(r.PostFormValue("wg_if")); v != "" {
		g.WGIf = v
	}
	if v, err := strconv.Atoi(r.PostFormValue("wg_port")); err == nil && v > 0 {
		g.WGPort = v
	}
	if v := strings.TrimSpace(r.PostFormValue("wg_subnet")); v != "" {
		g.WGSubnet = v
	}
	if v := strings.TrimSpace(r.PostFormValue("managed_nft_table")); v != "" {
		g.ManagedNFTTable = v
	}
	if err := s.Deps.DB.UpdateGateway(ctx, g); err != nil {
		http.Redirect(w, r, "/settings?flash=error:"+err.Error(), http.StatusSeeOther)
		return
	}
	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "settings.update", "gateway", "{}")
	http.Redirect(w, r, "/settings?flash=ok:settings+saved", http.StatusSeeOther)
}

// ---- helpers ----

func liveWGPeers(ctx context.Context, s *Server, iface string) []wg.Peer {
	if iface == "" {
		return nil
	}
	ins := wg.Inspector{Runner: s.Deps.Runner}
	_, peers, err := ins.Dump(ctx, iface)
	if err != nil {
		return nil
	}
	return peers
}

func hasWarn(issues []forwards.Issue) bool {
	for _, i := range issues {
		if i.Severity == "warn" {
			return true
		}
	}
	return false
}

func stripCIDR(s string) string {
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i]
	}
	return s
}

func currentActor(r *http.Request) string {
	if sess := sessionFromCtx(r.Context()); sess != nil {
		return sess.Username
	}
	return "system"
}

// flashFromQuery parses "?flash=kind:text" set by handlers on redirect.
func flashFromQuery(r *http.Request) *Flash {
	raw := r.URL.Query().Get("flash")
	if raw == "" {
		return nil
	}
	if i := strings.Index(raw, ":"); i > 0 {
		return &Flash{Kind: raw[:i], Text: raw[i+1:]}
	}
	return &Flash{Kind: "ok", Text: raw}
}

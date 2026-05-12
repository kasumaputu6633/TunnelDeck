package httpsrv

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kasumaputu6633/tunneldeck/internal/adopt"
	"github.com/kasumaputu6633/tunneldeck/internal/auth"
	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/doctor"
	"github.com/kasumaputu6633/tunneldeck/internal/forwards"
	"github.com/kasumaputu6633/tunneldeck/internal/inspect"
	"github.com/kasumaputu6633/tunneldeck/internal/nft"
	"github.com/kasumaputu6633/tunneldeck/internal/updater"
	"github.com/kasumaputu6633/tunneldeck/internal/wg"
	"github.com/kasumaputu6633/tunneldeck/internal/wgops"
)

// ---- login / logout ----

type loginData struct {
	Error       string
	DefaultUser string
	DefaultPass string
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if sessionFromCtx(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	d := loginData{}
	// Read credentials file if it exists — show default credentials on login page.
	if s.Deps.CredentialsPath != "" {
		if b, err := os.ReadFile(s.Deps.CredentialsPath); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "username: ") {
					d.DefaultUser = strings.TrimPrefix(line, "username: ")
				}
				if strings.HasPrefix(line, "password: ") {
					d.DefaultPass = strings.TrimPrefix(line, "password: ")
				}
			}
		}
	}
	s.render(w, r, "login", "Sign in", d, nil)
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
	d := s.computeDashboard(r.Context())
	s.render(w, r, "dashboard", "Dashboard", d, flashFromQuery(r))
}

// dashboardFragment is the htmx-polled version of the dashboard body.
// Returns just the stat cards + peer table + recent audit strip.
func (s *Server) dashboardFragment(w http.ResponseWriter, r *http.Request) {
	d := s.computeDashboard(r.Context())
	s.renderFragment(w, "dashboard_live", d)
}

// computeDashboard gathers everything the dashboard renders. Shared by the
// full page and the htmx fragment so the two never drift.
func (s *Server) computeDashboard(ctx context.Context) dashboardData {
	g, _ := s.Deps.DB.GetGateway(ctx)

	nodes, _ := s.Deps.DB.ListNodes(ctx)
	fwds, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	audits, _ := s.Deps.DB.ListAudit(ctx, 10)

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

	return dashboardData{
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
}

// ---- nodes ----

type nodesData struct {
	Gateway  db.Gateway
	Nodes    []nodeRow
	NextIP   string
	NewNode  nodeSetup
	Err      string
	Pagination db.PageResult
}

type nodeRow struct {
	Node       db.Node
	Online     bool
	LatestHS   string
	LastSeen   string // human-readable "last seen X ago" for offline nodes
	RxBytes    int64
	TxBytes    int64
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
	p := pageFromRequest(r)
	nodes, pr, _ := s.Deps.DB.ListNodesPage(ctx, p)
	peers := liveWGPeers(ctx, s, g.WGIf)

	cutoff := time.Now().Add(-2 * time.Minute).Unix()
	rows := make([]nodeRow, 0, len(nodes))
	for _, n := range nodes {
		row := nodeRow{Node: n}
		for _, peer := range peers {
			if wg.FirstAllowedHost(peer) != n.WGIP {
				continue
			}
				row.Online = peer.LatestHandshakeUnix >= cutoff
			if peer.LatestHandshakeUnix > 0 {
				row.LatestHS = formatHandshake(peer.LatestHandshakeUnix)
				if peer.LatestHandshakeUnix >= cutoff {
					s.Deps.DB.UpdateNodeLastSeen(ctx, n.WGIP)
				}
			} else {
				row.LatestHS = "never"
			}
			if !row.Online && n.LastSeenAt != nil {
				row.LastSeen = formatHandshake(n.LastSeenAt.Unix())
			}
			row.RxBytes = peer.RxBytes
			row.TxBytes = peer.TxBytes
			break
		}
		rows = append(rows, row)
	}

	used := make([]string, 0, len(nodes))
	for _, n := range nodes {
		used = append(used, n.WGIP)
	}
	// For next-IP allocation we need all nodes, not just the current page.
	allNodes, _ := s.Deps.DB.ListNodes(ctx)
	allUsed := make([]string, 0, len(allNodes))
	for _, n := range allNodes {
		allUsed = append(allUsed, n.WGIP)
	}
	next, _ := forwards.AllocateNextIP(g.WGSubnet, stripCIDR(g.WGIP), allUsed)

	s.render(w, r, "nodes", "Nodes", nodesData{
		Gateway:    g,
		Nodes:      rows,
		NextIP:     next,
		Pagination: pr,
	}, flashFromQuery(r))
}

// nodesFragment is the htmx-polled tbody + pagination for the nodes table.
func (s *Server) nodesFragment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)
	p := pageFromRequest(r)
	nodes, pr, _ := s.Deps.DB.ListNodesPage(ctx, p)
	peers := liveWGPeers(ctx, s, g.WGIf)

	cutoff := time.Now().Add(-2 * time.Minute).Unix()
	rows := make([]nodeRow, 0, len(nodes))
	for _, n := range nodes {
		row := nodeRow{Node: n}
		for _, peer := range peers {
			if wg.FirstAllowedHost(peer) != n.WGIP {
				continue
			}
				row.Online = peer.LatestHandshakeUnix >= cutoff
			if peer.LatestHandshakeUnix > 0 {
				row.LatestHS = formatHandshake(peer.LatestHandshakeUnix)
				if peer.LatestHandshakeUnix >= cutoff {
					s.Deps.DB.UpdateNodeLastSeen(ctx, n.WGIP)
				}
			} else {
				row.LatestHS = "never"
			}
			if !row.Online && n.LastSeenAt != nil {
				row.LastSeen = formatHandshake(n.LastSeenAt.Unix())
			}
			row.RxBytes = peer.RxBytes
			row.TxBytes = peer.TxBytes
			break
		}
		rows = append(rows, row)
	}
	s.renderFragment(w, "nodes_live", struct {
		Rows       []nodeRow
		Pagination db.PageResult
		CSRF       string
	}{rows, pr, sessionFromCtx(r.Context()).CSRFToken})
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

	// Send the user to the setup page for this node so they can copy the
	// wg0.conf template and install commands.
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d/setup?flash=ok:node+%s+added+(%s)", id, name, wgIP), http.StatusSeeOther)
}

// nodeSetupData is what /nodes/{id}/setup renders.
type nodeSetupData struct {
	Node            db.Node
	Gateway         db.Gateway
	Endpoint        string // "<public_ip>:<wg_port>" or ":port" if IP missing
	NodeAddress     string // "10.66.66.2/24" for the node's own Address line
	GatewayAllowed  string // what AllowedIPs on the node points at (gateway /32 by default)
	Config          string // the rendered wg0.conf body
	HasPublicKey    bool   // true once the node has joined and we have its pubkey
}

func (s *Server) nodeSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	nodes, _ := s.Deps.DB.ListNodes(ctx)
	var node db.Node
	found := false
	for _, n := range nodes {
		if n.ID == id {
			node = n
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	g, err := s.Deps.DB.GetGateway(ctx)
	if err != nil {
		http.Error(w, "gateway: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Build the endpoint string. If the public IP hasn't been set yet, leave
	// a placeholder so the user notices.
	pubIP := g.PublicIP
	if pubIP == "" {
		pubIP = "<YOUR_GATEWAY_PUBLIC_IP>"
	}
	endpoint := fmt.Sprintf("%s:%d", pubIP, g.WGPort)

	// Node's Address is its /24 slot in the wg subnet; AllowedIPs on the
	// node side points at the gateway's /32 so only the tunnel carries
	// gateway traffic.
	nodeAddr := fmt.Sprintf("%s/24", node.WGIP)
	gwAllowed := stripCIDR(g.WGIP) + "/32"

	cfg := wg.RenderNodeConfig(
		nodeAddr,
		"<PASTE_NODE_PRIVATE_KEY>",
		defaultStr(g.WGPublicKey, "<GATEWAY_PUBLIC_KEY_NOT_DETECTED_YET>"),
		endpoint,
		gwAllowed,
		node.Keepalive,
		1380,
	)

	s.render(w, r, "node_setup", "Node setup — "+node.Name, nodeSetupData{
		Node:           node,
		Gateway:        g,
		Endpoint:       endpoint,
		NodeAddress:    nodeAddr,
		GatewayAllowed: gwAllowed,
		Config:         cfg,
		HasPublicKey:   node.PublicKey != "",
	}, flashFromQuery(r))
}

// getAdminUpdateStatus returns a small HTML fragment describing the current
// self-update state. Polled by the banner's progress panel after the user
// clicks "Update now". States:
//
//   - waiting — the service is about to restart (the 1s-delayed goroutine
//     hasn't run yet).
//   - restarting — post doesn't get here because the service has already
//     torn down before the next poll; the browser's poll will fail for a
//     few seconds until the new process is listening. That's the "user
//     knows something is happening" signal.
//   - up-to-date — the background check has re-run and reports we match
//     the latest release. This is the "success" state.
//   - still stale — the background check ran but the local SHA still
//     differs from remote (which shouldn't happen under normal flow).
//
// Because the first post-restart request also triggers a fresh Check(),
// the banner will go green the moment a poll hits and the new check
// returns up-to-date.
func (s *Server) getAdminUpdateStatus(w http.ResponseWriter, r *http.Request) {
	st, _ := s.updateStatus()
	// Force a refresh so the caller's next poll reflects reality (useful
	// right after a service restart when the cached status is still
	// "stale"). Cheap in the not-available case.
	if st.UpdateAvailable {
		go s.refreshUpdateStatus(context.Background())
	}

	t, ok := s.Templates["admin_update_status"]
	if !ok {
		http.Error(w, "unknown fragment", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "fragment", st)
}

// registerNodePubkey takes a node public key pasted in the UI and runs the
// two gateway-side steps the user would otherwise do via SSH:
//
//   1. wg set <iface> peer <pk> allowed-ips <nodeWGIP>/32 persistent-keepalive N
//   2. append a [Peer] block to /etc/wireguard/<iface>.conf (backup first)
//
// Both happen inside RegisterNodePeer with rollback on partial failure.
// On success we also persist the public key on the nodes row so the UI
// reflects the peer binding even if the tunnel isn't up yet.
func (s *Server) registerNodePubkey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	nodes, _ := s.Deps.DB.ListNodes(ctx)
	var node db.Node
	found := false
	for _, n := range nodes {
		if n.ID == id {
			node = n
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d/setup?flash=error:bad+form", id), http.StatusSeeOther)
		return
	}
	pubkey := strings.TrimSpace(r.PostFormValue("public_key"))

	g, err := s.Deps.DB.GetGateway(ctx)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d/setup?flash=error:gateway+lookup+failed", id), http.StatusSeeOther)
		return
	}

	confPath := "/etc/wireguard/" + g.WGIf + ".conf"
	res, err := wgops.RegisterNodePeer(ctx, s.Deps.Runner, wgops.AddPeerInput{
		Iface:     g.WGIf,
		ConfPath:  confPath,
		BackupDir: "/var/lib/tunneldeck/backups",
		NodeName:  node.Name,
		NodeWGIP:  node.WGIP,
		PublicKey: pubkey,
		Keepalive: node.Keepalive,
	})
	if err != nil {
		_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "node.register-pubkey.fail",
			fmt.Sprintf("%d", id), fmt.Sprintf(`{"err":%q}`, err.Error()))
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d/setup?flash=error:register+failed:+%s", id, err.Error()), http.StatusSeeOther)
		return
	}

	// Persist public key on the node row so subsequent renders don't ask for it again.
	if _, err := s.Deps.DB.ExecContext(ctx, `UPDATE nodes SET public_key=? WHERE id=?`, pubkey, id); err != nil {
		// Non-fatal: runtime peer is already live and persisted; the DB row
		// is informational. Log via audit and continue.
		_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "node.register-pubkey.db-write-failed",
			fmt.Sprintf("%d", id), fmt.Sprintf(`{"err":%q}`, err.Error()))
	}

	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "node.register-pubkey", fmt.Sprintf("%d", id),
		fmt.Sprintf(`{"backup":%q,"pubkey_prefix":%q}`, res.BackupPath, shortPubkey(pubkey)))

	http.Redirect(w, r, fmt.Sprintf("/nodes/%d/setup?flash=ok:public+key+registered;+bring+up+the+tunnel+next", id), http.StatusSeeOther)
}

// shortPubkey returns the first few chars of a WG public key for logs —
// full keys aren't secret but are long and noisy in audit output.
func shortPubkey(k string) string {
	if len(k) < 8 {
		return k
	}
	return k[:8] + "…"
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// nodeStatus is polled by the setup page's HTMX widget every few seconds.
// Returns an HTML fragment (not a full page) with the node's current
// handshake/online state so the user can verify the tunnel came up
// without leaving the tutorial.
func (s *Server) nodeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	var node db.Node
	found := false
	for _, n := range nodes {
		if n.ID == id {
			node = n
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	g, _ := s.Deps.DB.GetGateway(ctx)
	peers := liveWGPeers(ctx, s, g.WGIf)

	var matched *wg.Peer
	for i := range peers {
		if wg.FirstAllowedHost(peers[i]) == node.WGIP {
			matched = &peers[i]
			break
		}
	}

	data := struct {
		Node     db.Node
		Peer     *wg.Peer
		Online   bool
		Handshake string
	}{Node: node, Peer: matched}

	if matched != nil {
		cutoff := time.Now().Add(-2 * time.Minute).Unix()
		data.Online = matched.LatestHandshakeUnix >= cutoff
		if matched.LatestHandshakeUnix > 0 {
			data.Handshake = formatHandshake(matched.LatestHandshakeUnix)
		} else {
			data.Handshake = "never"
		}
	}

	// Render the small fragment template without the base layout.
	t, ok := s.Templates["node_status"]
	if !ok {
		http.Error(w, "unknown fragment", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "fragment", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
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
	Gateway      db.Gateway
	Forwards     []db.Forward
	Nodes        []db.Node
	Issues       []forwards.Issue
	Form         forwards.Input
	ApplyPreview string
	Pagination   db.PageResult
	Counters     map[int64]nft.RuleCounter
	Pending      nft.PendingState
}

func (s *Server) listForwards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)
	p := pageFromRequest(r)
	fwds, pr, _ := s.Deps.DB.ListForwardsWithNodePage(ctx, p)
	nodes, _ := s.Deps.DB.ListNodes(ctx)
	counters, _ := s.Deps.NFT.CountersByForwardID(ctx, g.ManagedNFTTable)

	// Build summary for pending-check (all forwards, not just current page).
	allFwds, _ := s.Deps.DB.ListForwardsWithNode(ctx)
	summaries := make([]nft.DBForwardSummary, len(allFwds))
	for i, f := range allFwds {
		summaries[i] = nft.DBForwardSummary{ID: f.ID, Proto: f.Proto, PublicPort: f.PublicPort, Enabled: f.Enabled}
	}
	pending := s.Deps.NFT.CheckPending(ctx, summaries, g.ManagedNFTTable)

	s.render(w, r, "forwards", "Forwards", forwardsData{
		Gateway:    g,
		Forwards:   fwds,
		Nodes:      nodes,
		Pagination: pr,
		Counters:   counters,
		Pending:    pending,
	}, flashFromQuery(r))
}

// forwardsFragment is the htmx-polled tbody + counters + pagination.
func (s *Server) forwardsFragment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, _ := s.Deps.DB.GetGateway(ctx)
	p := pageFromRequest(r)
	fwds, pr, _ := s.Deps.DB.ListForwardsWithNodePage(ctx, p)
	counters, _ := s.Deps.NFT.CountersByForwardID(ctx, g.ManagedNFTTable)
	sess := sessionFromCtx(r.Context())
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	s.renderFragment(w, "forwards_live", struct {
		Forwards   []db.Forward
		Pagination db.PageResult
		Counters   map[int64]nft.RuleCounter
		CSRF       string
	}{fwds, pr, counters, csrf})
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
	} else if len(res.Removed) > 0 {
		msg += fmt.Sprintf("; flushed %d active connection(s) from %d removed port(s)",
			res.FlushedConnections, len(res.Removed))
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
	rep := inspect.Host{Runner: s.Deps.Runner, ReadFile: os.ReadFile}.Run(r.Context())
	s.render(w, r, "inspect", "Inspect", inspectData{Report: rep, Gateway: g}, flashFromQuery(r))
}

// inspectFragment is polled every 10s to refresh peer + nft table data.
func (s *Server) inspectFragment(w http.ResponseWriter, r *http.Request) {
	rep := inspect.Host{Runner: s.Deps.Runner, ReadFile: os.ReadFile}.Run(r.Context())
	s.renderFragment(w, "inspect_live", rep)
}

func (s *Server) postAdopt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rep := inspect.Host{Runner: s.Deps.Runner, ReadFile: os.ReadFile}.Run(ctx)

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

// ---- doctor ----

type doctorData struct {
	Results []doctor.Result
}

func (s *Server) doctorPage(w http.ResponseWriter, r *http.Request) {
	results := doctor.Run(r.Context(), s.Deps.Runner)
	s.render(w, r, "doctor", "Doctor", doctorData{Results: results}, nil)
}

type logsData struct {
	Audit      []db.AuditEntry
	Pagination db.PageResult
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	p := pageFromRequest(r)
	audits, pr, _ := s.Deps.DB.ListAuditPage(r.Context(), p)
	s.render(w, r, "logs", "Logs", logsData{Audit: audits, Pagination: pr}, flashFromQuery(r))
}

// logsFragment is polled only on page 1 (newest entries).
func (s *Server) logsFragment(w http.ResponseWriter, r *http.Request) {
	p := pageFromRequest(r)
	audits, pr, _ := s.Deps.DB.ListAuditPage(r.Context(), p)
	sess := sessionFromCtx(r.Context())
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	s.renderFragment(w, "logs_live", struct {
		Audit      []db.AuditEntry
		Pagination db.PageResult
		CSRF       string
	}{audits, pr, csrf})
}

// ---- settings ----

type settingsData struct{ Gateway db.Gateway }

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	g, _ := s.Deps.DB.GetGateway(r.Context())
	s.render(w, r, "settings", "Settings", settingsData{Gateway: g}, flashFromQuery(r))
}

// ---- change password ----

type changePasswordData struct {
	MustChange bool
	Error      string
}

func (s *Server) getChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r.Context())
	must := sess != nil && sess.MustChangePassword
	s.render(w, r, "change_password", "Change password", changePasswordData{MustChange: must}, flashFromQuery(r))
}

func (s *Server) postChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionFromCtx(ctx)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	newPW := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	if newPW != confirm {
		s.render(w, r, "change_password", "Change password",
			changePasswordData{MustChange: sess.MustChangePassword, Error: "passwords do not match"}, nil)
		return
	}
	if err := s.Deps.Auth.ChangePassword(ctx, sess.UserID, newPW, s.Deps.CredentialsPath); err != nil {
		s.render(w, r, "change_password", "Change password",
			changePasswordData{MustChange: sess.MustChangePassword, Error: err.Error()}, nil)
		return
	}
	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "settings.password-change", "", "{}")
	http.Redirect(w, r, "/?flash=ok:password+changed", http.StatusSeeOther)
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

// postAdminUpdate downloads the latest release, verifies its SHA256,
// atomically swaps the binary, and schedules a service restart.
//
// Responds with an HTML fragment (targetted via hx-swap) that polls
// /admin/update/status every 2 seconds. While the service is restarting
// the poll will fail briefly — that's the visible "restarting" state to
// the user. Once the new process is up and the background check re-runs,
// the fragment flips to "up to date" in green.
func (s *Server) postAdminUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.Deps.UpdateRepo == "" {
		writeUpdateError(w, "update not configured")
		return
	}
	binPath, err := os.Executable()
	if err != nil {
		writeUpdateError(w, "resolve binary: "+err.Error())
		return
	}

	res, err := updater.Apply(ctx, s.Deps.UpdateRepo, binPath)
	if err != nil {
		_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "update.fail", "", fmt.Sprintf(`{"err":%q}`, err.Error()))
		writeUpdateError(w, err.Error())
		return
	}
	_ = s.Deps.DB.AuditWrite(ctx, currentActor(r), "update.apply", "",
		fmt.Sprintf(`{"binary":%q,"backup":%q,"sha":%q}`, res.NewBinaryPath, res.BackupPath, res.NewSHA))

	go func() {
		time.Sleep(1 * time.Second)
		_ = s.Deps.Runner.Run(context.Background(), "systemctl", []string{"restart", "tunneldeck"}, "")
	}()

	// Return a progress widget that htmx will poll until the service is
	// back and reports up-to-date.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`
<div class="rounded border border-amber-800 bg-amber-950 text-amber-200 px-3 py-2 text-sm"
     hx-get="/admin/update/status"
     hx-trigger="load delay:2s, every 2s"
     hx-swap="innerHTML">
    <div class="flex items-center gap-3">
        <div class="w-3 h-3 rounded-full bg-amber-400 animate-pulse"></div>
        <div>
            <div class="text-sm font-semibold">Applying update…</div>
            <div class="text-xs text-amber-300/80">new binary installed, service is restarting</div>
        </div>
    </div>
</div>`))
}

func writeUpdateError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK) // keep htmx swap; surface error inline
	_, _ = fmt.Fprintf(w, `
<div class="rounded border border-red-800 bg-red-950 text-red-200 px-3 py-2 text-sm">
    <div class="font-semibold">Update failed</div>
    <div class="text-xs text-red-300/80">%s</div>
    <div class="text-xs text-red-300/60 mt-1">the banner will come back on the next page load</div>
</div>`, htmlEscape(msg))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

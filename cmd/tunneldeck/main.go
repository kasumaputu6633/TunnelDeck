// TunnelDeck CLI.
//
// Subcommands:
//   tunneldeck serve     — run the Web UI (default)
//   tunneldeck doctor    — run diagnostic checks
//   tunneldeck inspect   — print detected host state as JSON
//   tunneldeck status    — short one-line status for scripting
//   tunneldeck version   — print build info
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tunneldeck/tunneldeck/internal/auth"
	"github.com/tunneldeck/tunneldeck/internal/config"
	"github.com/tunneldeck/tunneldeck/internal/db"
	"github.com/tunneldeck/tunneldeck/internal/doctor"
	"github.com/tunneldeck/tunneldeck/internal/httpsrv"
	"github.com/tunneldeck/tunneldeck/internal/inspect"
	"github.com/tunneldeck/tunneldeck/internal/nft"
	"github.com/tunneldeck/tunneldeck/internal/sysexec"
)

var version = "0.1.0-dev"

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "serve":
		runServe(args)
	case "doctor":
		runDoctor()
	case "inspect":
		runInspect()
	case "status":
		runStatus()
	case "version", "-v", "--version":
		fmt.Println("tunneldeck", version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Println(`tunneldeck — self-hosted wg+nft gateway control plane

usage:
  tunneldeck [command] [flags]

commands:
  serve    start the Web UI (default)
  doctor   run diagnostic checks
  inspect  print detected host state as JSON
  status   one-line status (for scripts)
  version  print version`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := config.Defaults()
	bind := fs.String("bind", "", "override UI bind address (default from DB/settings)")
	port := fs.Int("port", 0, "override UI port (default from DB/settings)")
	dryNFT := fs.Bool("dry-nft", false, "never apply nftables, only render (monitor mode)")
	stateDir := fs.String("state", cfg.StateDir, "state directory (DB + backups)")
	_ = fs.Parse(args)

	cfg.StateDir = *stateDir
	cfg.DBPath = filepath.Join(cfg.StateDir, "tunneldeck.db")
	cfg.BackupDir = filepath.Join(cfg.StateDir, "backups")
	if err := cfg.EnsureDirs(); err != nil {
		die("ensure dirs: ", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		die("open db: ", err)
	}
	ctx, cancel := signalContext()
	defer cancel()

	if err := database.EnsureGatewayRow(ctx, cfg.DefaultWGIface, cfg.DefaultWGSubnet,
		cfg.DefaultUIBind, cfg.DefaultUIPort, cfg.ManagedNFTTable); err != nil {
		die("seed gateway: ", err)
	}

	authSvc := &auth.Service{DB: database}
	if pw, err := authSvc.EnsureAdmin(ctx, "admin"); err != nil {
		die("ensure admin: ", err)
	} else if pw != "" {
		fmt.Println("=== TunnelDeck first-run ===")
		fmt.Println("username: admin")
		fmt.Println("password:", pw)
		fmt.Println("Save this now; it won't be displayed again.")
		fmt.Println("============================")
	}

	g, err := database.GetGateway(ctx)
	if err != nil {
		die("get gateway: ", err)
	}
	uiBind := g.UIBind
	uiPort := g.UIPort
	if *bind != "" {
		uiBind = *bind
	}
	if *port != 0 {
		uiPort = *port
	}
	if uiBind == "" {
		uiBind = cfg.DefaultUIBind
	}
	if uiPort == 0 {
		uiPort = cfg.DefaultUIPort
	}

	runner := sysexec.ExecRunner{}
	server, err := httpsrv.New(httpsrv.Deps{
		DB:        database,
		Auth:      authSvc,
		NFT:       nft.Client{Runner: runner},
		Runner:    runner,
		TLSOn:     false,
		DryRunNFT: *dryNFT,
	})
	if err != nil {
		die("build server: ", err)
	}

	addr := fmt.Sprintf("%s:%d", uiBind, uiPort)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           server.Router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		fmt.Printf("TunnelDeck listening on http://%s\n", addr)
		if uiBind != "127.0.0.1" && uiBind != "localhost" {
			fmt.Println("WARNING: UI is not bound to localhost. Make sure this address is not publicly reachable.")
		}
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			die("listen: ", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func runDoctor() {
	runner := sysexec.ExecRunner{}
	ctx, cancel := signalContext()
	defer cancel()
	results := doctor.Run(ctx, runner)
	for _, r := range results {
		fmt.Printf("[%-5s] %-18s %s\n", r.Level, r.Name, r.Detail)
	}
}

func runInspect() {
	runner := sysexec.ExecRunner{}
	ctx, cancel := signalContext()
	defer cancel()
	rep := inspect.Host{
		Runner:    runner,
		ReadFile:  os.ReadFile,
		IsUIDZero: func() bool { return os.Geteuid() == 0 },
	}.Run(ctx)
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
}

func runStatus() {
	runner := sysexec.ExecRunner{}
	ctx, cancel := signalContext()
	defer cancel()
	rep := inspect.Host{Runner: runner, ReadFile: os.ReadFile}.Run(ctx)
	fmt.Printf("wg=%s peers=%d nft_tables=%d ip_forward=%v\n",
		rep.WGPrimary, len(rep.WGPeers), len(rep.NFTTables), rep.IPForward)
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func die(prefix string, err error) {
	fmt.Fprintln(os.Stderr, prefix+err.Error())
	os.Exit(1)
}

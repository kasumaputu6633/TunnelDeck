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
	"strings"
	"syscall"
	"time"

	"github.com/kasumaputu6633/tunneldeck/internal/auth"
	"github.com/kasumaputu6633/tunneldeck/internal/config"
	"github.com/kasumaputu6633/tunneldeck/internal/db"
	"github.com/kasumaputu6633/tunneldeck/internal/doctor"
	"github.com/kasumaputu6633/tunneldeck/internal/httpsrv"
	"github.com/kasumaputu6633/tunneldeck/internal/inspect"
	"github.com/kasumaputu6633/tunneldeck/internal/nft"
	"github.com/kasumaputu6633/tunneldeck/internal/sysexec"
	"github.com/kasumaputu6633/tunneldeck/internal/updater"
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
	case "update":
		runUpdate(args)
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
  update   download and install the latest release from GitHub
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
	credPath := filepath.Join(cfg.ConfigDir, "credentials")
	if pw, err := authSvc.EnsureAdmin(ctx, "admin", credPath); err != nil {
		die("ensure admin: ", err)
	} else if pw != "" {
		fmt.Println("=== TunnelDeck first-run ===")
		fmt.Println("username: admin")
		fmt.Println("password:", pw)
		fmt.Println("credentials also saved to:", credPath)
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
		DB:              database,
		Auth:            authSvc,
		NFT:             nft.Client{Runner: runner},
		Runner:          runner,
		TLSOn:           false,
		DryRunNFT:       *dryNFT,
		UpdateRepo:      "kasumaputu6633/tunneldeck",
		Version:         version,
		CredentialsPath: credPath,
	})
	if err != nil {
		die("build server: ", err)
	}
	server.StartBackgroundChecks(ctx)

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

// runUpdate implements `tunneldeck update`.
//
// Flags:
//
//	--check          only print whether an update is available, don't apply
//	--force          apply even if Check() says we're up-to-date
//	--repo owner/n   override the release source (default: kasumaputu6633/tunneldeck)
//	--binary path    override the binary path to replace (default: argv[0])
//	--no-restart     skip `systemctl restart tunneldeck` after swap
//
// Exit codes:
//
//	0 — up to date, or update applied successfully
//	1 — check or apply failed
//	2 — (with --check) update is available
func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "only check, don't apply")
	force := fs.Bool("force", false, "apply even if Check reports up-to-date")
	repo := fs.String("repo", "kasumaputu6633/tunneldeck", "GitHub repo owner/name")
	binaryPath := fs.String("binary", "", "path to binary to replace (default: current)")
	noRestart := fs.Bool("no-restart", false, "don't systemctl restart tunneldeck after swap")
	_ = fs.Parse(args)

	if *binaryPath == "" {
		p, err := os.Executable()
		if err != nil {
			die("resolve current binary: ", err)
		}
		*binaryPath = p
	}

	ctx, cancel := signalContext()
	defer cancel()

	status := updater.Check(ctx, *repo, *binaryPath, version)
	fmt.Printf("current: %s (sha %s)\n", status.CurrentVersion, shortSHA(status.CurrentSHA))
	fmt.Printf("remote:  %s (sha %s, published %s)\n",
		status.RemoteTag, shortSHA(status.RemoteSHA),
		status.RemotePublishedAt.Format("2006-01-02 15:04 MST"))
	fmt.Println("status: ", status.Reason)

	if *checkOnly {
		if status.UpdateAvailable {
			os.Exit(2)
		}
		return
	}

	if !status.UpdateAvailable && !*force {
		fmt.Println("nothing to do. use --force to re-download anyway.")
		return
	}

	fmt.Println("downloading and verifying...")
	res, err := updater.Apply(ctx, *repo, *binaryPath)
	if err != nil {
		die("update failed: ", err)
	}
	fmt.Printf("installed new binary: %s (sha %s)\n", res.NewBinaryPath, shortSHA(res.NewSHA))
	fmt.Printf("previous binary backed up at: %s\n", res.BackupPath)

	if *noRestart {
		fmt.Println("skipping service restart (--no-restart).")
		return
	}
	runner := sysexec.ExecRunner{}
	r := runner.Run(ctx, "systemctl", []string{"restart", "tunneldeck"}, "")
	if r.Err != nil || r.ExitCode != 0 {
		fmt.Fprintf(os.Stderr, "warning: systemctl restart tunneldeck failed (exit=%d): %s\n", r.ExitCode, strings.TrimSpace(r.Stderr))
		fmt.Fprintln(os.Stderr, "the new binary is installed; run 'sudo systemctl restart tunneldeck' manually.")
		return
	}
	fmt.Println("service restarted. all done.")
}

func shortSHA(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12]
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

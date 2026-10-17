package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/discovery"
	"github.com/0xOpCode/sysbridge-mcp/pkg/mcpserver"
	"github.com/0xOpCode/sysbridge-mcp/pkg/runner"
	"github.com/0xOpCode/sysbridge-mcp/pkg/tunnel"
)

var Version = "1.0.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		runServe(ctx, nil)
		return
	}

	first := os.Args[1]
	if strings.HasPrefix(first, "-") {
		runServe(ctx, os.Args[1:])
		return
	}

	switch first {
	case "serve", "mcp":
		runServe(ctx, os.Args[2:])
	case "daemon":
		runDaemon(ctx, os.Args[2:])
	case "status":
		runStatus(ctx, os.Args[2:])
	case "ip":
		runIP(ctx, os.Args[2:])
	case "exec", "run":
		runExec(ctx, os.Args[2:])
	case "send", "push":
		runSend(ctx, os.Args[2:])
	case "tunnel":
		runTunnel(ctx, os.Args[2:])
	case "keygen":
		runKeygen()
	case "version", "--version", "-v":
		fmt.Printf("sysbridge-mcp v%s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", first)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sysbridge-mcp - Zero-install remote OS, mountless SFTP VFS & P2P mesh for AI agents

Usage:
  sysbridge-mcp [serve] [--transport stdio|http|sse|dual|unix] [--listen 127.0.0.1:8787] [--config path]
  sysbridge-mcp daemon  [--port 42424] [--role laptop|phone] [--config path]
  sysbridge-mcp status  [peer]
  sysbridge-mcp ip      [peer]
  sysbridge-mcp exec    [-d] [-peer name] [-sudo] <command...>
  sysbridge-mcp send    [-peer name] <local_file> [remote_path]
  sysbridge-mcp tunnel  <add|list|remove> [args...]
  sysbridge-mcp keygen
  sysbridge-mcp version`)
}

func runServe(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "Path to config.yaml or config.json")
	transportMode := fs.String("transport", "", "MCP transport: stdio | http | sse | dual | unix")
	listenAddr := fs.String("listen", "", "HTTP/SSE listen address (e.g. 127.0.0.1:8787)")
	socketPath := fs.String("socket", "", "Unix domain socket path")
	defaultPeer := fs.String("peer", "", "Override default target peer")
	withMesh := fs.Bool("mesh", false, "Start background UDP :42424 discovery daemon inside MCP process")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load error: %v\n", err)
		os.Exit(1)
	}

	if *transportMode != "" {
		cfg.Server.Transport = *transportMode
	}
	if *listenAddr != "" {
		cfg.Server.Listen = *listenAddr
	}
	if *socketPath != "" {
		cfg.Server.UnixSocket = *socketPath
	}
	if *defaultPeer != "" {
		cfg.DefaultPeer = *defaultPeer
	}

	suite := mcpserver.NewEngineSuite(cfg, *cfgPath)
	defer suite.Close()

	if *withMesh {
		if d, dErr := discovery.NewDaemon(cfg, suite.Store); dErr == nil {
			d.SetOnPeerCallback(func(st *discovery.PeerState) {
				suite.Tunnel.SyncAll(ctx)
			})
			_ = d.StartAsync(ctx)
		}
	}

	token := ""
	if cfg.Server.AuthTokenEnv != "" {
		token = os.Getenv(cfg.Server.AuthTokenEnv)
	}

	srv := mcpserver.NewServer("sysbridge-mcp", Version, token)
	mcpserver.RegisterAll(srv, suite)

	mode := strings.ToLower(strings.TrimSpace(cfg.Server.Transport))
	if mode == "" {
		mode = "stdio"
	}

	switch mode {
	case "stdio":
		if err := srv.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "stdio server error: %v\n", err)
			os.Exit(1)
		}
	case "http", "sse", "dual":
		fmt.Fprintf(os.Stderr, "sysbridge-mcp v%s listening on http://%s (mode: %s, endpoints: /mcp, /sse, /message, /healthz)\n", Version, cfg.Server.Listen, mode)
		if err := srv.ServeHTTP(ctx, cfg.Server.Listen); err != nil {
			fmt.Fprintf(os.Stderr, "http server error: %v\n", err)
			os.Exit(1)
		}
	case "unix":
		sock := config.ExpandPath(cfg.Server.UnixSocket)
		fmt.Fprintf(os.Stderr, "sysbridge-mcp v%s listening on unix://%s\n", Version, sock)
		if err := srv.ServeUnixSocket(ctx, sock); err != nil {
			fmt.Fprintf(os.Stderr, "unix socket error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported transport mode: %s\n", mode)
		os.Exit(1)
	}
}

func runDaemon(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("config", "", "Path to config file")
	role := fs.String("role", "", "Node role (laptop or phone)")
	port := fs.Int("port", 0, "UDP discovery port (default 42424)")
	interval := fs.Int("interval", 0, "Beacon interval in seconds")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if *role != "" {
		cfg.Mesh.Role = *role
	}
	if *port > 0 {
		cfg.Mesh.UDPPort = *port
	}
	if *interval > 0 {
		cfg.Mesh.BeaconIntervalSec = *interval
	}

	suite := mcpserver.NewEngineSuite(cfg, *cfgPath)
	defer suite.Close()

	daemon, err := discovery.NewDaemon(cfg, suite.Store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon init error: %v\n", err)
		os.Exit(1)
	}
	daemon.SetOnPeerCallback(func(st *discovery.PeerState) {
		suite.Tunnel.SyncAll(ctx)
	})

	fmt.Fprintf(os.Stderr, "sysbridge-mcp mesh daemon active [%s] on UDP :%d\n", cfg.Mesh.Role, cfg.Mesh.UDPPort)
	if err := daemon.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "daemon fatal error: %v\n", err)
		os.Exit(1)
	}
}

func runStatus(ctx context.Context, args []string) {
	cfg, _ := config.Load("")
	suite := mcpserver.NewEngineSuite(cfg, "")
	defer suite.Close()

	peerName := cfg.DefaultPeer
	if len(args) > 0 && args[0] != "" {
		peerName = args[0]
	}

	peerCfg, host, port, method, err := suite.Pool.ResolveTarget(peerName)
	status := map[string]any{
		"peer":            peerName,
		"resolved_host":   host,
		"ssh_port":        port,
		"resolution_tier": method,
	}
	if err != nil {
		status["error"] = err.Error()
	} else {
		status["user"] = peerCfg.User
		status["sudo_mode"] = peerCfg.Sudo.Mode
		status["vfs_backend"] = peerCfg.VFS.Backend
		if rtt, pErr := suite.Pool.ProbeTCP(host, port, 1200*time.Millisecond); pErr == nil {
			status["reachable"] = true
			status["rtt_ms"] = float64(rtt.Microseconds()) / 1000.0
		} else {
			status["reachable"] = false
		}
	}
	if st, ok := suite.Store.Get(peerName); ok {
		status["mesh_state"] = st
	}

	out, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(out))
}

func runIP(ctx context.Context, args []string) {
	cfg, _ := config.Load("")
	suite := mcpserver.NewEngineSuite(cfg, "")
	defer suite.Close()

	peerName := cfg.DefaultPeer
	if len(args) > 0 && args[0] != "" {
		peerName = args[0]
	}

	_, host, _, _, err := suite.Pool.ResolveTarget(peerName)
	if err != nil || host == "" {
		os.Exit(1)
	}
	fmt.Print(strings.TrimSpace(host))
}

func runExec(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	detached := fs.Bool("d", false, "Run detached in remote tmux or nohup")
	peerName := fs.String("peer", "", "Target peer name")
	sudo := fs.Bool("sudo", false, "Run with sudo")
	taskName := fs.String("name", "", "Custom task name")
	_ = fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sysbridge-mcp exec [-d] [-peer name] [-sudo] <command...>")
		os.Exit(1)
	}

	cfg, _ := config.Load("")
	suite := mcpserver.NewEngineSuite(cfg, "")
	defer suite.Close()

	target := *peerName
	if target == "" {
		target = cfg.DefaultPeer
	}

	out, err := suite.Runner.Run(ctx, runner.RunOptions{
		Peer:     target,
		Command:  strings.Join(remaining, " "),
		Sudo:     *sudo,
		Detached: *detached,
		TaskName: *taskName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "exec error: %v\n", err)
		os.Exit(1)
	}

	if out.Detached {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	if out.Stdout != "" {
		fmt.Print(out.Stdout)
	}
	if out.Stderr != "" {
		fmt.Fprint(os.Stderr, out.Stderr)
	}
	os.Exit(out.ExitCode)
}

func runSend(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	peerName := fs.String("peer", "", "Target peer name")
	_ = fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sysbridge-mcp send [-peer name] <local_file> [remote_path]")
		os.Exit(1)
	}

	cfg, _ := config.Load("")
	suite := mcpserver.NewEngineSuite(cfg, "")
	defer suite.Close()

	target := *peerName
	if target == "" {
		target = cfg.DefaultPeer
	}
	remotePath := ""
	if len(remaining) >= 2 {
		remotePath = remaining[1]
	}

	res, err := suite.Sync.PushFile(ctx, target, remaining[0], remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "transfer failed: %v\n", err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
}

func runTunnel(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sysbridge-mcp tunnel <add|list|remove>")
		os.Exit(1)
	}

	cfg, _ := config.Load("")
	suite := mcpserver.NewEngineSuite(cfg, "")
	defer suite.Close()

	switch args[0] {
	case "list", "ls":
		b, _ := json.MarshalIndent(suite.Tunnel.ListRules(), "", "  ")
		fmt.Println(string(b))
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sysbridge-mcp tunnel remove <name>")
			os.Exit(1)
		}
		if err := suite.Tunnel.RemoveRule(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "remove tunnel failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed tunnel %s\n", args[1])
	case "add":
		fs := flag.NewFlagSet("tunnel-add", flag.ExitOnError)
		temp := fs.Bool("temp", false, "RAM-only temporary rule")
		peer := fs.String("peer", cfg.DefaultPeer, "Target peer")
		_ = fs.Parse(args[1:])
		rem := fs.Args()
		if len(rem) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: sysbridge-mcp tunnel add [--temp] [--peer name] <name> <local_port> <remote_port> [local|reverse]")
			os.Exit(1)
		}
		lPort, _ := strconv.Atoi(rem[1])
		rPort, _ := strconv.Atoi(rem[2])
		tType := "local"
		if len(rem) >= 4 && rem[3] == "reverse" {
			tType = "reverse"
		}
		rule, err := suite.Tunnel.AddRule(ctx, &tunnel.Rule{
			Name:       rem[0],
			Peer:       *peer,
			LocalPort:  lPort,
			RemotePort: rPort,
			Type:       tType,
			Temporary:  *temp,
			Enabled:    true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "add tunnel failed: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(rule, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Fprintf(os.Stderr, "Unknown tunnel action: %s\n", args[0])
		os.Exit(1)
	}
}

func runKeygen() {
	key, err := discovery.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(key)
}

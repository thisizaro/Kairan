// Command kairan-cp is the Kairan control plane: it stores signed policies,
// runs the rollout engine and keeps the fleet state, and serves proxies and
// admins over one HTTP listener plus an optional metrics listener.
//
// It is a thin main: it reads the config (config.go), finds the admin token
// (token.go), opens the store and wires internal/cp/api and internal/obs.
//
//	kairan-cp -config cp.json [-admin-token-file FILE] [-check]
//
// The listen address and data directory are config keys (listen, data_dir),
// not flags, so one file describes one control plane. The admin token never
// travels on the command line (see adminToken). -check validates the config
// and the token and exits without touching the data directory or the network.
//
// Every message for a person is printed in English and in Japanese. Exit
// status: 0 clean stop (SIGTERM or SIGINT) or a good -check, 2 for a usage,
// config or token error, 1 for a failure at startup or while serving.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/api"
	"kairan/internal/cp/store"
	"kairan/internal/obs"
)

// shutdownGrace is how long a stopping server waits for requests to finish.
const shutdownGrace = 5 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func report(stderr io.Writer, e *cliError) {
	fmt.Fprintf(stderr, "kairan-cp: error: %s\nkairan-cp: エラー: %s\n", e.en, e.ja)
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kairan-cp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path of the control plane config file (JSON)")
	tokFile := fs.String("admin-token-file", "", "file holding the admin token (or set "+envTokenFile+" or "+envToken+")")
	check := fs.Bool("check", false, "check the config and the admin token, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		report(stderr, msg("unexpected argument; usage: kairan-cp -config FILE [-admin-token-file FILE] [-check]",
			"余分な引数があります。使い方: kairan-cp -config FILE [-admin-token-file FILE] [-check]"))
		return 2
	}
	if *cfgPath == "" {
		report(stderr, msg("-config is required", "-config は必須です"))
		return 2
	}
	cfg, cerr := loadConfig(*cfgPath)
	if cerr != nil {
		report(stderr, cerr)
		return 2
	}
	token, cerr := adminToken(*tokFile, getenv)
	if cerr != nil {
		report(stderr, cerr)
		return 2
	}
	d := sha256.Sum256([]byte(token))
	for _, e := range cfg.Proxies {
		if e.TokenDigest == d {
			report(stderr, msg("the admin token is also a proxy token; they must differ", "管理トークンがプロキシのトークンと同じです。別の値にしてください"))
			return 2
		}
	}
	if *check {
		fmt.Fprintf(stdout, "config ok: %d tenant(s), %d proxy enrollment(s)\n設定は正常です: テナント %d 件、プロキシ登録 %d 件\n",
			len(cfg.AdminKeys), len(cfg.Proxies), len(cfg.AdminKeys), len(cfg.Proxies))
		return 0
	}
	if cerr := serve(cfg, token, stderr); cerr != nil {
		report(stderr, cerr)
		return 1
	}
	return 0
}

func serve(cfg *config, token string, stderr io.Writer) *cliError {
	log := obs.NewLogger(stderr, cfg.LogLevel)
	clk := clock.NewReal()

	st, err := store.OpenFiles(cfg.DataDir)
	if err != nil {
		if errors.Is(err, store.ErrCorrupt) {
			file := strings.TrimPrefix(err.Error(), store.ErrCorrupt.Error()+": ")
			return msg("damaged state file: "+file+" (restore it from a backup or move it away; the control plane will not start with it)",
				"状態ファイルが壊れています: "+file+" (バックアップから戻すか、別の場所に移してください。このままでは起動しません)")
		}
		return msg("cannot open data_dir: "+err.Error(), "data_dir を開けません: "+err.Error())
	}

	reg := obs.NewRegistry()
	srv := api.New(api.Config{
		AdminToken:  token,
		Proxies:     cfg.Proxies,
		AdminKeys:   cfg.AdminKeys,
		MaxPolls:    cfg.MaxPolls,
		CanaryDwell: cfg.Dwell,
		Thresholds:  cfg.Thresholds,
	}, st, clk, log, reg)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return listenErr("listen", err)
	}
	defer ln.Close()
	var mln net.Listener
	if cfg.MetricsListen != "" {
		if mln, err = net.Listen("tcp", cfg.MetricsListen); err != nil {
			return listenErr("metrics_listen", err)
		}
		defer mln.Close()
	}

	// base is cancelled when shutdown starts, so held long-polls (which watch
	// their request context) return at once instead of holding the stop.
	base, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	hs := srv.HTTPServer(cfg.Listen)
	hs.BaseContext = func(net.Listener) context.Context { return base }
	if cfg.Certificate != nil {
		hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cfg.Certificate}}
	}
	var ms *http.Server
	if mln != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", reg.Handler())
		ms = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    8 << 10,
		}
		if !loopback(cfg.MetricsListen) {
			log.Warn("metrics listener is not on loopback; metrics have no authentication, keep this port off untrusted networks")
		}
	}
	if cfg.Certificate == nil {
		log.Warn("serving plaintext HTTP (allow_plaintext); tokens and policies cross the network unencrypted, use this for demos only")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var wg sync.WaitGroup
	fail := make(chan error, 2)
	wg.Add(1)
	go func() { defer wg.Done(); srv.Run(ctx) }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		if cfg.Certificate != nil {
			err = hs.ServeTLS(ln, "", "")
		} else {
			err = hs.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			fail <- err
		}
	}()
	metricsAddr := ""
	if ms != nil {
		metricsAddr = mln.Addr().String()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ms.Serve(mln); !errors.Is(err, http.ErrServerClosed) {
				fail <- err
			}
		}()
	}
	log.Info("listening", slog.String("addr", ln.Addr().String()), slog.String("metrics_addr", metricsAddr),
		slog.Int("tenants", len(cfg.AdminKeys)), slog.Int("proxies", len(cfg.Proxies)))

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-fail:
		log.Error("server failed")
	}
	stop() // a second signal now ends the process at once
	log.Info("shutting down")
	cancelBase()
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = hs.Shutdown(sctx)
	if ms != nil {
		_ = ms.Shutdown(sctx)
	}
	_ = hs.Close()
	if ms != nil {
		_ = ms.Close()
	}
	wg.Wait()
	log.Info("stopped")
	if serveErr != nil {
		return msg("the server stopped: "+serveErr.Error(), "サーバーが停止しました: "+serveErr.Error())
	}
	return nil
}

func listenErr(key string, err error) *cliError {
	reason := err.Error()
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		reason = oe.Err.Error()
	}
	return msg("cannot listen for "+key+": "+reason, key+" の待ち受けを開始できません: "+reason)
}

// loopback reports whether addr (host:port) is bound to the loopback
// interface only. An empty or wildcard host is not.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

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
// Every message for a person is printed in English and in Japanese: errors
// and -check as an English line and a Japanese line, usage as one text, and
// log lines (warnings too) with the English text in msg and the Japanese text
// in msg_ja. Exit
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

// usageText is the help text, in both languages.
const usageText = `usage: kairan-cp -config FILE [-admin-token-file FILE] [-check]
使い方: kairan-cp -config FILE [-admin-token-file FILE] [-check]

  -config FILE
        path of the control plane config file (JSON)
        コントロールプレーンの設定ファイル (JSON) のパス
  -admin-token-file FILE
        file holding the admin token (or set ` + envTokenFile + ` or ` + envToken + `)
        管理トークンを入れたファイル (または ` + envTokenFile + ` か ` + envToken + ` を設定)
  -check
        check the config and the admin token, then exit
        設定と管理トークンを確認して終了する
`

// flagError turns an error of the flag package (English only) into a message
// in both languages. It never repeats the value the person typed.
func flagError(err error) *cliError {
	s := err.Error()
	switch {
	case strings.HasPrefix(s, "flag provided but not defined: "):
		f := short(strings.TrimPrefix(s, "flag provided but not defined: "))
		return msg("unknown flag: "+f, "未知のフラグです: "+f)
	case strings.HasPrefix(s, "flag needs an argument: "):
		f := short(strings.TrimPrefix(s, "flag needs an argument: "))
		return msg("flag needs an argument: "+f, "フラグに引数が必要です: "+f)
	}
	return msg("a flag has an invalid value", "フラグの値が正しくありません")
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kairan-cp", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // the flag package speaks English only; see flagError and usageText
	cfgPath := fs.String("config", "", "path of the control plane config file (JSON)")
	tokFile := fs.String("admin-token-file", "", "file holding the admin token (or set "+envTokenFile+" or "+envToken+")")
	check := fs.Bool("check", false, "check the config and the admin token, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, usageText)
			return 0
		}
		report(stderr, flagError(err))
		fmt.Fprint(stderr, usageText)
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
			say(log, slog.LevelWarn, evMetricsOpen)
		}
	}
	if cfg.Certificate == nil {
		say(log, slog.LevelWarn, evPlaintext)
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
	say(log, slog.LevelInfo, evListening, slog.String("addr", ln.Addr().String()), slog.String("metrics_addr", metricsAddr),
		slog.Int("tenants", len(cfg.AdminKeys)), slog.Int("proxies", len(cfg.Proxies)))

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-fail:
		say(log, slog.LevelError, evServerFailed)
	}
	stop() // a second signal now ends the process at once
	say(log, slog.LevelInfo, evShuttingDown)
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
	say(log, slog.LevelInfo, evStopped)
	if serveErr != nil {
		return msg("the server stopped: "+serveErr.Error(), "サーバーが停止しました: "+serveErr.Error())
	}
	return nil
}

// event is a log line meant for a person, in both languages. The English text
// is the msg field (log pipelines and tests match on it); the Japanese text
// is the msg_ja field of the same line.
type event struct{ en, ja string }

var (
	evMetricsOpen = event{
		"metrics listener is not on loopback; metrics have no authentication, keep this port off untrusted networks",
		"メトリクスの待ち受けがループバックではありません。メトリクスに認証はないので、信頼できないネットワークには公開しないでください"}
	evPlaintext = event{
		"serving plaintext HTTP (allow_plaintext); tokens and policies cross the network unencrypted, use this for demos only",
		"平文の HTTP で提供しています (allow_plaintext)。トークンとポリシーが暗号化されずにネットワークを流れます。デモ専用です"}
	evListening    = event{"listening", "待ち受けを開始しました"}
	evServerFailed = event{"server failed", "サーバーが失敗しました"}
	evShuttingDown = event{"shutting down", "停止しています"}
	evStopped      = event{"stopped", "停止しました"}
)

// events lists every log event, so that a test can check each has both
// languages.
var events = []event{evMetricsOpen, evPlaintext, evListening, evServerFailed, evShuttingDown, evStopped}

// say logs ev in both languages. All log lines of this program go through it.
func say(log *slog.Logger, level slog.Level, ev event, attrs ...any) {
	log.Log(context.Background(), level, ev.en, append([]any{slog.String("msg_ja", ev.ja)}, attrs...)...)
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

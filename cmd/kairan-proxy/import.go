package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/store"
	"kairan/internal/wire"
)

// lockFile is the file in data_dir that one process at a time holds.
const lockFile = "kairan.lock"

// lockWait is how long to wait for the data directory (a proxy that was
// stopped a moment ago may still be closing its files).
var lockWait = 5 * time.Second

// lockDataDir takes an exclusive advisory lock on data_dir, so that two
// processes (a running proxy and an import, or two proxies) never write the
// same apply log and policy file. The lock is released when the returned
// function is called or the process exits.
func lockDataDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, osMsg("cannot create data_dir", "data_dir を作成できません", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, osMsg("cannot open the lock file in data_dir", "data_dir のロックファイルを開けません", err)
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, msg("the data directory is in use by another kairan-proxy",
					"データディレクトリは別の kairan-proxy が使用中です")
			}
			return nil, osMsg("cannot lock data_dir", "data_dir をロックできません", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// readBundle reads the bundle file. It refuses anything that is not a regular
// file (a FIFO or device could block or never end) and anything larger than
// an envelope may be, without reading it.
func readBundle(path string) ([]byte, error) {
	// O_NONBLOCK so that opening a FIFO with no writer cannot hang.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, msg("cannot read the bundle file", "バンドルファイルを読めません")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, msg("cannot read the bundle file", "バンドルファイルを読めません")
	}
	if !fi.Mode().IsRegular() {
		return nil, msg("the bundle is not a regular file", "バンドルが通常のファイルではありません")
	}
	tooBig := msg("the bundle file is too large", "バンドルファイルが大きすぎます")
	if fi.Size() > wire.MaxEnvelopeBytes {
		return nil, tooBig
	}
	data, err := io.ReadAll(io.LimitReader(f, wire.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, msg("cannot read the bundle file", "バンドルファイルを読めません")
	}
	if len(data) > wire.MaxEnvelopeBytes {
		return nil, tooBig
	}
	return data, nil
}

// rejection says why a bundle was refused, by wire error code.
func rejection(code wire.ErrorCode) error {
	switch code {
	case wire.ErrThreshold:
		return msg("bundle rejected: not enough valid signatures from distinct trusted keys",
			"バンドルを拒否しました: 信頼された別々の鍵による有効な署名が足りません")
	case wire.ErrWrongTenant:
		return msg("bundle rejected: the policy is for another tenant",
			"バンドルを拒否しました: ポリシーは別のテナント用です")
	case wire.ErrNotNewer:
		return msg("bundle rejected: its version is not newer than the policy already applied",
			"バンドルを拒否しました: 適用済みのポリシーより新しいバージョンではありません")
	case wire.ErrExpired:
		return msg("bundle rejected: the policy has expired",
			"バンドルを拒否しました: ポリシーの有効期限が切れています")
	case wire.ErrPayloadType:
		return msg("bundle rejected: wrong payload type",
			"バンドルを拒否しました: ペイロードの種類が正しくありません")
	case wire.ErrPersist:
		return msg("bundle not applied: could not record it on disk (or the data directory failed verification)",
			"バンドルを適用しませんでした: ディスクに記録できません (またはデータディレクトリの検証に失敗しました)")
	default: // malformed, and anything unexpected
		return msg("bundle rejected: not a well-formed signed policy (malformed)",
			"バンドルを拒否しました: 署名付きポリシーとして正しい形式ではありません (malformed)")
	}
}

// openData opens the stored policy, the clock guard and the apply log in
// cfg.DataDir, as the proxy does at start. An apply log that fails
// verification is not an error: it is returned as logErr with a nil log, and
// the agent boots Tampered and applies nothing.
func openData(cfg *Config, clk clock.Clock, log *slog.Logger) (st *store.Store, guard *agent.ClockGuard, al *applylog.Log, logErr error, err error) {
	if st, err = store.Open(cfg.DataDir); err != nil {
		return nil, nil, nil, nil, osMsg("cannot open data_dir", "data_dir を開けません", err)
	}
	guard, err = agent.OpenClockGuard(clk, cfg.DataDir)
	switch {
	case errors.Is(err, agent.ErrHighWaterCorrupt):
		say(log, slog.LevelWarn, evHighWaterCorrupt)
	case err != nil:
		return nil, nil, nil, nil, osMsg("cannot open the clock high-water file in data_dir", "data_dir のハイウォーターファイルを開けません", err)
	}
	al, err = applylog.Open(filepath.Join(cfg.DataDir, applyLogFile), clk)
	if err != nil {
		// Do not repair or work around it: boot as Tampered, apply nothing.
		say(log, slog.LevelError, evApplyLogBad, "err", errText(err))
		return st, guard, nil, err, nil
	}
	return st, guard, al, nil, nil
}

// importBundle applies one offline signed bundle (PRD J3, P-11) to the data
// directory and exits. The bundle goes through the same path as a policy from
// the control plane: strict decode, trust.Accept, store.Save, then
// applylog.Append (agent.Import). Nothing is served and no network is used. A
// rejection leaves the policy in force and writes an apply-log entry.
func importBundle(cfg *Config, file string, stderr io.Writer) error {
	data, err := readBundle(file)
	if err != nil {
		return err
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return err
	}
	defer unlock()

	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	clk := clock.NewReal()
	st, guard, al, logErr, err := openData(cfg, clk, log)
	if err != nil {
		return err
	}
	if al != nil {
		defer al.Close()
	}
	acfg := agent.Config{
		CP: cfg.CP, Tenant: cfg.Tenant, ProxyID: cfg.ProxyID, Token: cfg.Token, Root: cfg.Root,
		Skew: cfg.Skew, Guard: guard, AllowPlaintext: cfg.AllowPlaintext, LogOpenErr: logErr,
		LogPath: filepath.Join(cfg.DataDir, applyLogFile),
	}
	// The client is never used: an import makes no network call.
	ag, err := agent.New(acfg, st, al, &enforce.Holder{}, clk, &http.Client{}, log, &agent.Stats{})
	if err != nil {
		return osUsageMsg("invalid configuration", "設定が正しくありません", err)
	}
	if err := ag.Boot(); err != nil {
		return osMsg("cannot start", "起動できません", err)
	}
	got, err := ag.Import(data)
	if serr := guard.Save(); serr != nil {
		say(log, slog.LevelWarn, evImportHighWaterLost, "err", errText(serr))
	}
	var ie *agent.ImportError
	switch {
	case errors.As(err, &ie):
		return rejection(ie.Code)
	case err != nil:
		return osMsg("import failed", "取り込みに失敗しました", err)
	}
	fmt.Fprintf(stderr, "kairan-proxy: imported policy version %d (previous %d), hash %s; it is enforced when kairan-proxy starts\n"+
		"kairan-proxy: ポリシー バージョン %d (以前: %d) を取り込みました。ハッシュ %s。kairan-proxy の起動時から適用されます\n",
		got.Version, got.Previous, got.Hash, got.Version, got.Previous, got.Hash)
	return nil
}

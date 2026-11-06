package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Every message for a person is printed in English and in Japanese (PRD J7,
// M-D62). Errors and the import result are an English line and a Japanese line
// (report); usage is one bilingual text; log lines carry the English text in
// msg (log pipelines and tests match on it) and the Japanese text in msg_ja
// (say). A source-scan test (messages_test.go) fails any message that skips
// these helpers. A message never holds a config value, a token, a key or any
// of a bundle's content.

// cliError is a message for the person running the program, in both
// languages. Error() holds both, English first.
type cliError struct {
	en, ja string
	usage  bool // a bad command line or config: exit status 2
	help   bool // print the usage text after the message
}

func (e *cliError) Error() string { return e.en + " / " + e.ja }

// Is makes errors.Is(err, errUsage) true for a usage error.
func (e *cliError) Is(target error) bool { return target == errUsage && e.usage }

// msg is a runtime failure (exit status 1).
func msg(en, ja string) *cliError { return &cliError{en: en, ja: ja} }

// usageMsg is a bad config (exit status 2).
func usageMsg(en, ja string) *cliError { return &cliError{en: en, ja: ja, usage: true} }

// cmdLineMsg is a bad command line (exit status 2, followed by the usage).
func cmdLineMsg(en, ja string) *cliError { return &cliError{en: en, ja: ja, usage: true, help: true} }

// osMsg is a runtime failure with a cause: the English line adds the reason
// (errText) and the Japanese line the class (errClassJa). Neither holds a path
// or a value, and the Japanese line holds no library text (M-D65).
func osMsg(en, ja string, err error) *cliError {
	return msg(en+": "+errText(err), ja+": "+errClassJa(err))
}

// osUsageMsg is osMsg for a bad config (exit status 2).
func osUsageMsg(en, ja string, err error) *cliError {
	return usageMsg(en+": "+errText(err), ja+": "+errClassJa(err))
}

// oneLine makes sure a message cannot start a second line or carry a control
// byte, whatever was put into it.
func oneLine(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			b.WriteString(fmt.Sprintf(`\x%02x`, c))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// report prints err as an English line and a Japanese line.
func report(stderr io.Writer, err error) {
	var e *cliError
	if !errors.As(err, &e) {
		// Not expected: every error is made by msg, usageMsg or cmdLineMsg.
		e = osMsg("unexpected failure", "予期しない失敗です", err)
	}
	fmt.Fprintf(stderr, "kairan-proxy: error: %s\nkairan-proxy: エラー: %s\n", oneLine(e.en), oneLine(e.ja))
	if e.help {
		fmt.Fprint(stderr, usageText)
	}
}

// usageText is the help text, in both languages.
const usageText = `usage: kairan-proxy -config FILE [-import FILE]
使い方: kairan-proxy -config FILE [-import FILE]

  -config FILE
        path to proxy.json
        proxy.json のパス
  -import FILE
        apply this offline signed bundle to the data directory and exit
        オフラインの署名付きバンドルをデータディレクトリに適用して終了する
`

// flagError turns an error of the flag package (English only) into a message
// in both languages. It never repeats the value the person typed.
func flagError(err error) *cliError {
	s := err.Error()
	switch {
	case strings.HasPrefix(s, "flag provided but not defined: "):
		f := esc(strings.TrimPrefix(s, "flag provided but not defined: "))
		return cmdLineMsg("unknown flag: "+f, "未知のフラグです: "+f)
	case strings.HasPrefix(s, "flag needs an argument: "):
		f := esc(strings.TrimPrefix(s, "flag needs an argument: "))
		return cmdLineMsg("flag needs an argument: "+f, "フラグに引数が必要です: "+f)
	}
	return cmdLineMsg("a flag has an invalid value", "フラグの値が正しくありません")
}

// isHelp reports whether the flag package stopped for -h or -help.
func isHelp(err error) bool { return errors.Is(err, flag.ErrHelp) }

// event is a log line meant for a person, in both languages. The English text
// is the msg field; the Japanese text is the msg_ja field of the same line.
type event struct{ en, ja string }

var (
	evBooted        = event{"booted", "起動処理が完了しました"}
	evLocalListener = event{"local listener", "ローカルの待ち受けを開始しました"}
	evListening     = event{"listening", "待ち受けを開始しました"}
	evShuttingDown  = event{"shutting down", "停止しています"}
	evStopped       = event{"stopped", "停止しました"}
	evHighWaterLost = event{"shutdown: high-water not saved",
		"停止時にハイウォーターマークを保存できませんでした"}
	evImportHighWaterLost = event{"high-water not saved",
		"ハイウォーターマークを保存できませんでした"}
	evHighWaterCorrupt = event{"high-water file is corrupt; it will be rewritten",
		"ハイウォーターファイルが壊れています。書き直します"}
	evApplyLogBad = event{"apply log failed verification; starting tampered (deny-all)",
		"適用ログの検証に失敗しました。改ざん状態 (全拒否) で起動します"}
	evTestOnlyKey = event{"TEST-ONLY KEY TRUSTED: a trusted key is a public fixture key; anyone can sign policies. Do not use outside tests.",
		"テスト専用の鍵を信頼しています: 信頼する鍵が公開されたテスト用の鍵なので、誰でもポリシーに署名できます。テスト以外では使わないでください"}
)

// events lists every log event of this program, so that a test can check each
// has both languages.
var events = []event{evBooted, evLocalListener, evListening, evShuttingDown, evStopped, evHighWaterLost,
	evImportHighWaterLost, evHighWaterCorrupt, evApplyLogBad, evTestOnlyKey}

// say logs ev in both languages. All log lines of this program go through it.
func say(log *slog.Logger, level slog.Level, ev event, attrs ...any) {
	log.Log(context.Background(), level, ev.en, append([]any{slog.String("msg_ja", ev.ja)}, attrs...)...)
}

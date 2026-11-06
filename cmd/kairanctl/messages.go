package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

// The flag package speaks English only and repeats what was typed. kairanctl
// sends its output to io.Discard and maps its errors here to an English line
// and a Japanese line (PRD J7, M-D65). A message never repeats a typed flag
// value; a typed flag name is repeated only through esc.

// maxEcho is the most bytes of typed text that a message repeats.
const maxEcho = 128

// esc makes typed text safe to put in a message: printable ASCII stays, every
// other byte (control bytes, ESC, a newline, non-ASCII, a backslash) becomes
// \xNN, and the result is cut to maxEcho bytes with "...". The message stays
// one line of ASCII however hostile the input.
func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		part := string(c)
		if c < 0x20 || c >= 0x7f || c == '\\' {
			part = fmt.Sprintf(`\x%02x`, c)
		}
		if b.Len()+len(part) > maxEcho {
			b.WriteString("...")
			break
		}
		b.WriteString(part)
	}
	return b.String()
}

// flagError turns an error of the flag package into a usage error in both
// languages, followed by the usage of the subcommand.
func flagError(fs *flag.FlagSet, err error) *cliError {
	s := err.Error()
	var e *cliError
	switch {
	case strings.HasPrefix(s, "flag provided but not defined: "):
		f := esc(strings.TrimPrefix(s, "flag provided but not defined: "))
		e = usageErr("unknown flag: "+f, "未知のフラグです: "+f)
	case strings.HasPrefix(s, "flag needs an argument: "):
		f := esc(strings.TrimPrefix(s, "flag needs an argument: "))
		e = usageErr("flag needs an argument: "+f, "フラグに引数が必要です: "+f)
	case strings.HasPrefix(s, "bad flag syntax: "):
		e = usageErr("a flag is malformed", "フラグの書き方が正しくありません")
	default:
		// invalid value "..." for flag -x: ...: it holds the typed value.
		e = usageErr("a flag value is not valid", "フラグの値が正しくありません")
	}
	e.help = usageFor(fs)
	return e
}

// isHelp reports whether the flag package stopped for -h or -help.
func isHelp(err error) bool { return errors.Is(err, flag.ErrHelp) }

// synopsis is the first line of each subcommand's usage.
var synopsis = map[string]string{
	"keygen":           "keygen -name NAME [-dir DIR]",
	"policy new":       "policy new -tenant ID [-version N] [-validity 72h] [-out FILE]",
	"sign":             "sign -key NAME.key -in payload.json -out envelope.json",
	"approve":          "approve -key NAME.key -in envelope.json [-out FILE] [-yes] [-trusted PUB,PUB,...]",
	"publish":          "publish CONN -in envelope.json",
	"rollout start":    "rollout start CONN -tenant ID -version N [-canary-dwell 10m]",
	"rollout status":   "rollout status CONN -tenant ID",
	"rollout rollback": "rollout rollback -from OLD -version N -out payload.json [-validity 72h] [-key A.key -key2 B.key -env-out envelope.json]",
	"fleet":            "fleet CONN -tenant ID",
	"evidence export":  "evidence export CONN -tenant ID [-proxy ID] [-applylog PROXY=FILE]... [-out FILE]",
	"verify-applylog":  "verify-applylog -in FILE",
}

// flagJa is the Japanese text of each flag. A key "command flag" wins over the
// plain "flag" key, where the meaning differs between subcommands.
var flagJa = map[string]string{
	"name":                     "鍵の名前。ファイルは NAME.key と NAME.pub になります",
	"dir":                      "書き込み先のディレクトリ",
	"tenant":                   "テナントID",
	"version":                  "ポリシーのバージョン",
	"policy new version":       "ポリシーのバージョン (1以上。ポリシーごとに増やします)",
	"rollout start version":    "ロールアウトする公開済みのバージョン",
	"rollout rollback version": "新しいバージョン (元のバージョンと公開済みのどれよりも大きくします)",
	"validity":                 "ポリシーが有効な期間",
	"out":                      "作成するファイル",
	"policy new out":           "作成するファイル。省略すると標準出力",
	"evidence export out":      "作成するファイル。省略すると標準出力",
	"sign out":                 "作成する署名付きエンベロープのファイル",
	"approve out":              "-in を更新する代わりに、結果を新しいファイルに書き込む",
	"rollout rollback out":     "作成する新しいペイロードのファイル",
	"key":                      "秘密鍵のファイル",
	"sign key":                 "秘密鍵のファイル (keygen で作成)",
	"approve key":              "承認者の秘密鍵のファイル (keygen で作成)",
	"rollout rollback key":     "任意: 1つ目の署名鍵 (1人が両方の鍵を持つ場合のみ)",
	"key2":                     "任意: 2つ目の署名鍵",
	"env-out":                  "両方の鍵を指定したときに作成するエンベロープのファイル",
	"in":                       "入力ファイル",
	"sign in":                  "ポリシーのペイロードのファイル",
	"approve in":               "承認するエンベロープのファイル",
	"publish in":               "署名付きエンベロープのファイル (sign と approve で作成)",
	"verify-applylog in":       "検証する適用ログのファイル",
	"yes":                      "確認を求めない (スクリプトとテスト用)",
	"trusted":                  "既存の署名を先に検証する: 公開鍵ファイル (NAME.pub) または16進の公開鍵をカンマで区切る",
	"url":                      "コントロールプレーンのアドレス。例: https://cp.example (環境変数 KCTL_CP_URL も可)",
	"ca-file":                  "システムのルートに加えて信頼する CA 証明書 (PEM)",
	"token-file":               "管理者トークンを入れたファイル (環境変数 KCTL_ADMIN_TOKEN または KCTL_ADMIN_TOKEN_FILE も可)",
	"allow-plaintext":          "http:// を許可する (デモ専用。管理者トークンが暗号化されずに送られます)",
	"canary-dwell":             "カナリアグループが先に正常を保つ時間 (0 ならコントロールプレーンの既定値)",
	"from":                     "復元する古いポリシー: ペイロードのファイルまたは署名付きエンベロープ",
	"proxy":                    "このプロキシIDだけ",
	"applylog":                 "PROXY_ID=FILE: 突き合わせるプロキシの適用ログ (複数回指定できます)",
}

// usageFor is the usage of one subcommand in both languages: a line in English
// and a line in Japanese for the command, then for each flag its name and type,
// its English text and its Japanese text.
func usageFor(fs *flag.FlagSet) string {
	var b strings.Builder
	syn := synopsis[fs.Name()]
	fmt.Fprintf(&b, "kairanctl: usage: kairanctl %s\n", syn)
	fmt.Fprintf(&b, "kairanctl: 使い方: kairanctl %s\n\n", syn)
	fs.VisitAll(func(f *flag.Flag) {
		kind, _ := flag.UnquoteUsage(f)
		if kind != "" {
			fmt.Fprintf(&b, "  -%s %s\n", f.Name, kind)
		} else {
			fmt.Fprintf(&b, "  -%s\n", f.Name)
		}
		fmt.Fprintf(&b, "        %s\n", f.Usage)
		ja, ok := flagJa[fs.Name()+" "+f.Name]
		if !ok {
			ja = flagJa[f.Name]
		}
		if ja != "" {
			fmt.Fprintf(&b, "        %s\n", ja)
		}
	})
	return b.String()
}

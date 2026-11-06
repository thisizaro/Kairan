package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"kairan/internal/wire"
)

// httpTimeout is the whole-request limit for every call to the control plane
// (M-D31). A variable only so a test can shorten it.
var httpTimeout = 30 * time.Second

// Response size limits. A fleet or a timeline can be long; anything larger
// than this is not a control plane we should keep reading from.
const (
	maxViewBytes  = 16 << 20
	maxTokenBytes = 512
)

// connFlags are the flags every command that talks to the control plane has.
// There is deliberately no flag for the token itself: flags show in the
// process list.
type connFlags struct {
	url, caFile, tokenFile *string
	plaintext              *bool
}

func addConnFlags(fs *flag.FlagSet) *connFlags {
	return &connFlags{
		url:       fs.String("url", "", "control plane address, for example https://cp.example (or env KCTL_CP_URL)"),
		caFile:    fs.String("ca-file", "", "extra CA certificates (PEM) to trust, besides the system roots"),
		tokenFile: fs.String("token-file", "", "file holding the admin token (or env KCTL_ADMIN_TOKEN, or KCTL_ADMIN_TOKEN_FILE)"),
		plaintext: fs.Bool("allow-plaintext", false, "allow http:// (demo only: the admin token is then sent unencrypted)"),
	}
}

// cpClient is an authenticated client for the admin API.
type cpClient struct {
	base  *url.URL
	token string
	hc    *http.Client
}

// open validates the connection flags and builds the client. No network
// traffic happens here.
func (c *connFlags) open(s streams) (*cpClient, error) {
	raw := *c.url
	if raw == "" {
		raw = s.env("KCTL_CP_URL")
	}
	if raw == "" {
		return nil, usageErr("-url (or KCTL_CP_URL) is required", "-url (または環境変数 KCTL_CP_URL) が必要です")
	}
	base, cerr := parseBaseURL(raw, *c.plaintext)
	if cerr != nil {
		return nil, cerr
	}
	token, cerr := adminToken(s, *c.tokenFile)
	if cerr != nil {
		return nil, cerr
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if *c.caFile != "" {
		pem, err := readBounded(*c.caFile, 1<<20)
		if err != nil {
			return nil, fail("cannot read the -ca-file: "+reason(err), "-ca-file を読めません: "+reasonJa(err))
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fail("the -ca-file holds no PEM certificate", "-ca-file に PEM 形式の証明書がありません")
		}
	}
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  httpTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
	}
	hc := &http.Client{
		Timeout:   httpTimeout,
		Transport: tr,
		// A redirect would send the token somewhere the administrator did not name.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &cpClient{base: base, token: token, hc: hc}, nil
}

func parseBaseURL(raw string, plaintext bool) (*url.URL, *cliError) {
	bad := fail("-url must look like https://host[:port] (no user name, path, query or fragment)",
		"-url は https://host[:port] の形式で指定してください (ユーザー名・パス・クエリ・フラグメントは不可)")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, bad
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !plaintext {
			return nil, fail("http:// is refused: the admin token would travel unencrypted. Use https://, or -allow-plaintext for a local demo",
				"http:// は使えません (管理トークンが暗号化されずに送られます)。https:// を使うか、ローカルのデモでは -allow-plaintext を指定してください")
		}
	default:
		return nil, bad
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// adminToken reads the admin token from a file or the environment. The token
// is never echoed in any message.
func adminToken(s streams, file string) (string, *cliError) {
	if file == "" {
		file = s.env("KCTL_ADMIN_TOKEN_FILE")
	}
	var tok string
	switch {
	case file != "":
		f, st, err := openRegular(file)
		if errors.Is(err, errNotRegular) {
			return "", fail("the token file is not a regular file", "トークンファイルが通常のファイルではありません")
		}
		if err != nil {
			return "", fail("cannot open the token file: "+reason(err), "トークンファイルを開けません: "+reasonJa(err))
		}
		defer f.Close()
		if st.Mode().Perm()&0o077 != 0 {
			return "", fail("token file permissions are too open; run: chmod 600 <token file>",
				"トークンファイルの権限が緩すぎます。chmod 600 <トークンファイル> を実行してください")
		}
		b, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+2))
		if err != nil {
			return "", fail("cannot read the token file: "+reason(err), "トークンファイルを読めません: "+reasonJa(err))
		}
		tok = strings.TrimSpace(string(b))
	default:
		tok = strings.TrimSpace(s.env("KCTL_ADMIN_TOKEN"))
	}
	if tok == "" {
		return "", fail("no admin token: set KCTL_ADMIN_TOKEN, or use -token-file (the token is never a flag)",
			"管理トークンがありません。環境変数 KCTL_ADMIN_TOKEN を設定するか -token-file を使ってください (トークンはフラグでは渡せません)")
	}
	if len(tok) > maxTokenBytes {
		return "", fail("the admin token is too long", "管理トークンが長すぎます")
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] >= 0x7f {
			return "", fail("the admin token holds spaces or non-printable characters", "管理トークンに空白または表示できない文字が含まれています")
		}
	}
	return tok, nil
}

// do sends one request and strictly decodes a 2xx answer into out (nil means
// no body is expected). It returns the HTTP status; for a non-2xx answer the
// error says what the control plane said, in words, never its bytes.
func (c *cpClient) do(method, path string, query url.Values, body []byte, out any) (int, *cliError) {
	return c.doChecked(method, path, query, body, out, nil)
}

// doChecked is do with an extra look at the raw 2xx answer: if check is not
// nil and returns false, the answer is refused like any other malformed one.
func (c *cpClient) doChecked(method, path string, query url.Values, body []byte, out any, check func([]byte) bool) (int, *cliError) {
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, fail("cannot build the request", "リクエストを作成できません")
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+c.token)
	req.Header.Set("Accept", wire.ContentTypeJSON)
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, networkErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, cpError(resp)
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxViewBytes+1))
	if rerr == nil && check != nil && int64(len(data)) <= maxViewBytes && !check(data) {
		rerr = wire.ErrBodyInvalid
	}
	if rerr == nil {
		rerr = wire.Decode(bytes.NewReader(data), maxViewBytes, out)
	}
	if rerr != nil {
		return resp.StatusCode, fail("the control plane sent an answer that does not match the expected format; it was not used",
			"コントロールプレーンの応答が想定した形式ではないため、使用しませんでした")
	}
	return resp.StatusCode, nil
}

// networkErr explains a transport failure without echoing addresses.
func networkErr(err error) *cliError {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var ne net.Error
	switch {
	case errors.As(err, &cv), errors.As(err, &ua):
		return fail("the control plane's certificate is not trusted; if it uses a private CA, pass it with -ca-file",
			"コントロールプレーンの証明書を信頼できません。私的なCAの場合は -ca-file で指定してください")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return fail("the control plane did not answer in time (30 s timeout)", "コントロールプレーンが時間内に応答しませんでした (タイムアウト30秒)")
	case errors.Is(err, http.ErrUseLastResponse):
		return fail("the control plane tried to redirect the request; refused", "リダイレクトは拒否しました")
	}
	return fail("cannot reach the control plane (check -url, the network and any HTTPS_PROXY)",
		"コントロールプレーンに接続できません (-url、ネットワーク、HTTPS_PROXY を確認してください)")
}

// cpError turns a non-2xx answer into a message. Only a known wire error
// code is used; anything else is reported by status number alone.
func cpError(resp *http.Response) *cliError {
	var er wire.ErrorResponse
	data, _ := io.ReadAll(io.LimitReader(resp.Body, wire.MaxSmallRequestBytes+1))
	known := len(data) <= wire.MaxSmallRequestBytes &&
		wire.Decode(bytes.NewReader(data), wire.MaxSmallRequestBytes, &er) == nil && er.Code.Valid()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fail("the control plane tried to redirect the request; refused", "リダイレクトは拒否しました")
	}
	if !known {
		return fail("the control plane answered with an unexpected error (HTTP "+itoa(resp.StatusCode)+")",
			"コントロールプレーンが想定外のエラーを返しました (HTTP "+itoa(resp.StatusCode)+")")
	}
	en, ja := codeText(er.Code)
	en += " (HTTP " + itoa(resp.StatusCode) + ", " + string(er.Code) + ")"
	ja += " (HTTP " + itoa(resp.StatusCode) + ", " + string(er.Code) + ")"
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if n, ok := smallInt(ra); ok {
			en += "; retry after " + itoa(n) + " s"
			ja += "。" + itoa(n) + "秒後に再試行してください"
		}
	}
	return fail(en, ja)
}

// codeText gives fixed bilingual text for every wire error code.
func codeText(c wire.ErrorCode) (string, string) {
	switch c {
	case wire.ErrUnauthorized:
		return "the control plane refused the admin token", "コントロールプレーンが管理トークンを拒否しました"
	case wire.ErrForbidden:
		return "the control plane says this token may not do that", "このトークンではその操作は許可されていません"
	case wire.ErrNotFound:
		return "the control plane has no such item", "該当するものがコントロールプレーンにありません"
	case wire.ErrMethodNotAllowed:
		return "the control plane does not accept that request method", "コントロールプレーンはそのメソッドを受け付けません"
	case wire.ErrConflict:
		return "refused: conflicts with what the control plane already holds (for example that version exists, or a rollout is running)",
			"競合のため拒否されました (例: そのバージョンが既に存在する、ロールアウト実行中)"
	case wire.ErrTooLarge:
		return "the request is too large for the control plane", "リクエストが大きすぎます"
	case wire.ErrUnavailable:
		return "the control plane is busy or unavailable", "コントロールプレーンが混雑中または利用できません"
	case wire.ErrInternal:
		return "the control plane had an internal error", "コントロールプレーンで内部エラーが発生しました"
	case wire.ErrBadRequest:
		return "the control plane could not accept the request", "コントロールプレーンがリクエストを受け付けられませんでした"
	case wire.ErrMalformed, wire.ErrPayloadType:
		return "the control plane says the envelope or policy is malformed", "エンベロープまたはポリシーの形式が不正だとされました"
	case wire.ErrThreshold:
		return "the control plane says there are too few valid signatures from trusted admin keys", "信頼された管理者鍵による有効な署名が不足しているとされました"
	case wire.ErrWrongTenant:
		return "the control plane says the policy is for a different tenant", "ポリシーのテナントが違うとされました"
	case wire.ErrNotNewer:
		return "the control plane says the version is not newer than the current one (rollback needs a higher version)",
			"現在より新しいバージョンではないとされました (ロールバックには、より高いバージョンが必要です)"
	case wire.ErrExpired:
		return "the control plane says the policy has already expired", "ポリシーは既に期限切れだとされました"
	}
	return "the control plane refused the request", "コントロールプレーンがリクエストを拒否しました"
}

func itoa(n int) string { return strconv.Itoa(n) }

// smallInt parses a short decimal number (0..86400).
func smallInt(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, n <= 86400
}

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	"kairan/internal/policy"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// loadEnvelope reads and checks an envelope file the way publish needs it:
// strict decoding, outline, a policy that parses.
func loadEnvelope(path string) (wire.Envelope, []byte, *policy.Policy, *cliError) {
	raw, cerr := readInput(path)
	if cerr != nil {
		return wire.Envelope{}, nil, nil, cerr
	}
	env, err := trust.DecodeEnvelope(raw)
	if err != nil {
		return wire.Envelope{}, nil, nil, fail("the envelope file is not a valid envelope", "エンベロープのファイルが不正です").because(err)
	}
	if err := env.ValidateShape(); err != nil {
		return wire.Envelope{}, nil, nil, fail("the envelope has the wrong shape (payload type, payload or signatures)",
			"エンベロープの形式が不正です (種別・内容・署名)").because(err)
	}
	pol, cerr := parsePayload(env.Payload)
	if cerr != nil {
		return wire.Envelope{}, nil, nil, cerr
	}
	return env, raw, pol, nil
}

// cmdPublish uploads a signed envelope. Publishing only stores it on the
// control plane (M-D2); nothing is enforced until a rollout starts.
func cmdPublish(args []string, s streams) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cf := addConnFlags(fs)
	in := fs.String("in", "", "signed envelope file (from sign and approve)")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *in == "" {
		return usageErr("-in is required", "-in は必須です")
	}
	env, raw, pol, cerr := loadEnvelope(*in)
	if cerr != nil {
		return cerr
	}
	// Count distinct key IDs, not entries: one admin repeated is still one.
	ids := map[wire.Hash]bool{}
	for _, sg := range env.Signatures {
		ids[sg.KeyID] = true
	}
	if len(ids) < 2 {
		return fail("the envelope has fewer than two different signing keys; proxies need two different admins (run: kairanctl approve)",
			"異なる署名鍵が2つ未満です。プロキシは別々の管理者2名の署名を必要とします (kairanctl approve を実行してください)")
	}
	cl, err := cf.open(s)
	if err != nil {
		return err
	}
	var resp wire.PublishResponse
	if _, cerr := cl.do("POST", wire.PathPolicies, nil, raw, &resp); cerr != nil {
		return cerr
	}
	want := policyHash(env.Payload)
	if resp.Tenant != pol.Tenant || resp.Version != pol.Version || resp.PolicyHash != want {
		return fail("the control plane's answer does not match the envelope that was sent (tenant, version or hash differ); do not trust this publish",
			"コントロールプレーンの応答が送ったエンベロープと一致しません (テナント・バージョン・ハッシュが異なります)。この公開を信用しないでください")
	}
	fmt.Fprintf(s.out, "published tenant %s version %d\n", pol.Tenant, pol.Version)
	fmt.Fprintf(s.out, "policy hash: %s\n", want)
	fmt.Fprintf(s.out, "This only stores the policy; it is not enforced anywhere until a rollout starts:\n")
	fmt.Fprintf(s.out, "  kairanctl rollout start -tenant %s -version %d\n", pol.Tenant, pol.Version)
	fmt.Fprintf(s.out, "保存しただけです。ロールアウトを開始するまで、どのプロキシにも適用されません。\n")
	return nil
}

const maxCanaryDwell = 7 * 24 * time.Hour

func cmdRollout(args []string, s streams) error {
	if len(args) == 0 {
		return usageErr("rollout needs a command: start, status or rollback", "rollout にはサブコマンド (start, status, rollback) が必要です")
	}
	switch args[0] {
	case "start":
		return cmdRolloutStart(args[1:], s)
	case "status":
		return cmdRolloutStatus(args[1:], s)
	case "rollback":
		return cmdRolloutRollback(args[1:], s)
	}
	return usageErr("unknown rollout command (try: start, status, rollback)", "rollout のサブコマンドが不明です (start, status, rollback)")
}

func tenantFlagErr(t string) *cliError {
	if !wire.ID(t).Valid() {
		return fail("-tenant must be a valid tenant ID (lowercase letters, digits and '-')",
			"-tenant には有効なテナントID (小文字の英数字と '-') を指定してください")
	}
	return nil
}

// checkRolloutView rejects a view that is not for what we asked about or that
// holds values outside the wire enums (so nothing odd reaches the terminal).
func checkRolloutView(v wire.RolloutView, tenant string) *cliError {
	ok := string(v.Tenant) == tenant && v.Version >= 1 &&
		(v.Phase == wire.PhaseCanary || v.Phase == wire.PhasePromoting || v.Phase == wire.PhaseHalted || v.Phase == wire.PhaseComplete) &&
		(v.Reason == "" || v.Reason.Valid())
	if !ok {
		return badAnswer()
	}
	return nil
}

func badAnswer() *cliError {
	return fail("the control plane sent an answer with unexpected contents; it was not used",
		"コントロールプレーンの応答の内容が想定外のため、使用しませんでした")
}

func printRollout(s streams, v wire.RolloutView) {
	fmt.Fprintf(s.out, "rollout: tenant %s version %d is %s\n", v.Tenant, v.Version, v.Phase)
	if v.Reason != "" {
		fmt.Fprintf(s.out, "reason: %s\n", v.Reason)
	}
}

func cmdRolloutStart(args []string, s streams) error {
	fs := flag.NewFlagSet("rollout start", flag.ContinueOnError)
	cf := addConnFlags(fs)
	tenant := fs.String("tenant", "", "tenant ID")
	version := fs.Uint64("version", 0, "published version to roll out")
	dwell := fs.Duration("canary-dwell", 0, "how long the canary group must stay healthy first (0 = control plane default)")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if cerr := tenantFlagErr(*tenant); cerr != nil {
		return cerr
	}
	if *version < 1 {
		return fail("-version must be at least 1", "-version は1以上にしてください")
	}
	if *dwell < 0 || *dwell > maxCanaryDwell || *dwell%time.Second != 0 {
		return fail("-canary-dwell must be a whole number of seconds from 0 to 168h, for example 10m",
			"-canary-dwell は0〜168hの整数秒で指定してください (例: 10m)")
	}
	req := wire.RolloutRequest{Tenant: wire.ID(*tenant), Version: *version, CanaryDwellSeconds: uint64(*dwell / time.Second)}
	if err := req.Validate(); err != nil {
		return fail("the rollout request is not valid", "ロールアウトのリクエストが不正です").because(err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fail("cannot encode the request", "リクエストを作成できません")
	}
	cl, err := cf.open(s)
	if err != nil {
		return err
	}
	var view wire.RolloutView
	if _, cerr := cl.do("POST", wire.PathRollouts, nil, body, &view); cerr != nil {
		return cerr
	}
	if view.Version != *version || checkRolloutView(view, *tenant) != nil {
		return badAnswer()
	}
	printRollout(s, view)
	return nil
}

func cmdRolloutStatus(args []string, s streams) error {
	fs := flag.NewFlagSet("rollout status", flag.ContinueOnError)
	cf := addConnFlags(fs)
	tenant := fs.String("tenant", "", "tenant ID")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if cerr := tenantFlagErr(*tenant); cerr != nil {
		return cerr
	}
	cl, err := cf.open(s)
	if err != nil {
		return err
	}
	var view wire.RolloutView
	st, cerr := cl.do("GET", wire.PathRollouts, url.Values{wire.QueryTenant: {*tenant}}, nil, &view)
	if st == 404 && cerr != nil {
		fmt.Fprintf(s.out, "no rollout yet for tenant %s\n", *tenant)
		return nil
	}
	if cerr != nil {
		return cerr
	}
	if cerr := checkRolloutView(view, *tenant); cerr != nil {
		return cerr
	}
	printRollout(s, view)
	return nil
}

// payloadDoc is the policy document as kairanctl writes it. The roles are
// copied from a payload that already passed policy.Parse.
type payloadDoc struct {
	Tenant    string                       `json:"tenant"`
	Version   uint64                       `json:"version"`
	IssuedAt  string                       `json:"issued_at"`
	ExpiresAt string                       `json:"expires_at"`
	Default   string                       `json:"default"`
	Roles     map[string]map[string]string `json:"roles"`
}

// loadOldPolicy reads -from: a policy payload or a signed envelope holding one.
func loadOldPolicy(path string) ([]byte, *policy.Policy, *cliError) {
	raw, cerr := readInput(path)
	if cerr != nil {
		return nil, nil, cerr
	}
	if p, err := policy.Parse(raw); err == nil {
		return raw, p, nil
	}
	env, err := trust.DecodeEnvelope(raw)
	if err != nil || env.ValidateShape() != nil {
		return nil, nil, fail("-from is neither a valid policy payload nor a valid envelope", "-from は有効なポリシーでもエンベロープでもありません")
	}
	p, cerr := parsePayloadFor("the old policy is not valid", env.Payload)
	if cerr != nil {
		return nil, nil, cerr
	}
	return env.Payload, p, nil
}

func parsePayloadFor(en string, payload []byte) (*policy.Policy, *cliError) {
	p, err := policy.Parse(payload)
	if err != nil {
		return nil, fail(en, "古いポリシーが不正です").because(err)
	}
	return p, nil
}

func rulesBody(p *policy.Policy) string {
	parts := strings.SplitN(p.Render(), "\n", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

// cmdRolloutRollback prepares a rollback: the old content as a new, higher
// version with fresh validity (J6). Proxies never accept an older version
// (I2), so a rollback is a new policy that needs new signatures. Without
// -key and -key2 this writes only the unsigned payload; the two admins then
// run sign and approve as usual.
func cmdRolloutRollback(args []string, s streams) error {
	fs := flag.NewFlagSet("rollout rollback", flag.ContinueOnError)
	from := fs.String("from", "", "the old policy to restore: a payload file or a signed envelope")
	version := fs.Uint64("version", 0, "the new version (must be higher than the old one and than any published)")
	validity := fs.Duration("validity", 72*time.Hour, "how long the new policy stays valid")
	out := fs.String("out", "", "new payload file to create")
	keyA := fs.String("key", "", "optional: first signing key (only if one person holds both keys)")
	keyB := fs.String("key2", "", "optional: second signing key")
	envOut := fs.String("env-out", "", "envelope file to create when both keys are given")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *from == "" || *out == "" || *version < 1 {
		return usageErr("-from, -version and -out are required", "-from, -version, -out は必須です")
	}
	nKeys := 0
	for _, v := range []string{*keyA, *keyB, *envOut} {
		if v != "" {
			nKeys++
		}
	}
	if nKeys != 0 && nKeys != 3 {
		return usageErr("-key, -key2 and -env-out go together: give all three or none", "-key, -key2, -env-out は3つ一緒に指定するか、すべて省略してください")
	}
	if *validity < time.Second || *validity%time.Second != 0 {
		return fail("-validity must be a positive whole number of seconds, for example 72h",
			"-validity は1秒以上の整数秒で指定してください (例: 72h)")
	}
	oldRaw, old, cerr := loadOldPolicy(*from)
	if cerr != nil {
		return cerr
	}
	if *version <= old.Version {
		return fail(fmt.Sprintf("-version must be higher than the old policy's version (%d): proxies never accept an older or equal version", old.Version),
			fmt.Sprintf("-version は古いポリシーのバージョン (%d) より大きくしてください。プロキシは同じか古いバージョンを受け付けません", old.Version))
	}
	var privA, privB ed25519.PrivateKey
	if nKeys == 3 {
		if privA, cerr = loadKey(*keyA); cerr != nil {
			return cerr
		}
		if privB, cerr = loadKey(*keyB); cerr != nil {
			return cerr
		}
		if trust.KeyID(privA.Public().(ed25519.PublicKey)) == trust.KeyID(privB.Public().(ed25519.PublicKey)) {
			return fail("-key and -key2 are the same key; a policy needs two different keys",
				"-key と -key2 が同じ鍵です。ポリシーには異なる2つの鍵が必要です")
		}
	}

	var doc payloadDoc
	if err := json.Unmarshal(oldRaw, &doc); err != nil {
		return fail("cannot read the old policy", "古いポリシーを読めません").because(err)
	}
	issued := s.now().UTC().Truncate(time.Second)
	doc.Version = *version
	doc.IssuedAt = issued.Format(time.RFC3339)
	doc.ExpiresAt = issued.Add(*validity).Format(time.RFC3339)
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fail("cannot encode the new policy", "新しいポリシーを作成できません")
	}
	payload = append(payload, '\n')
	pol, err := policy.Parse(payload)
	if err != nil || pol.Tenant != old.Tenant || pol.Version != *version || rulesBody(pol) != rulesBody(old) || rulesBody(old) == "" {
		return fail("could not rebuild the old rules unchanged; nothing was written", "古いルールを変更せずに再構築できませんでした。何も書き込んでいません").because(err)
	}

	var envData []byte
	if nKeys == 3 {
		env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
		trust.Sign(&env, privA)
		trust.Sign(&env, privB)
		if envData, cerr = encodeEnvelope(env); cerr != nil {
			return cerr
		}
	}
	if err := createExclusive(*out, payload, 0o644); err != nil {
		return writeErr(err)
	}
	if envData != nil {
		if err := createExclusive(*envOut, envData, 0o644); err != nil {
			removeQuiet(*out)
			return writeErr(err)
		}
	}

	fmt.Fprintf(s.out, "wrote %s: the rules of version %d as new version %d for tenant %s\n", *out, old.Version, pol.Version, pol.Tenant)
	fmt.Fprintf(s.out, "valid from %s to %s\n", pol.IssuedAt.Format(time.RFC3339), pol.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(s.out, "policy hash: %s\n", policyHash(payload))
	if envData != nil {
		fmt.Fprintf(s.out, "wrote %s (2 signatures)\n", *envOut)
		fmt.Fprintf(s.out, "next: kairanctl publish -in %s, then: kairanctl rollout start -tenant %s -version %d\n", *envOut, pol.Tenant, pol.Version)
		return nil
	}
	fmt.Fprintf(s.out, "next: kairanctl sign -key A.key -in %s -out envelope.json\n", *out)
	fmt.Fprintf(s.out, "      kairanctl approve -key B.key -in envelope.json\n")
	fmt.Fprintf(s.out, "      kairanctl publish -in envelope.json\n")
	fmt.Fprintf(s.out, "      kairanctl rollout start -tenant %s -version %d\n", pol.Tenant, pol.Version)
	return nil
}

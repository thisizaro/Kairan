package web

import (
	"sort"
	"strconv"
	"strings"
)

// Languages the page speaks. Japanese is the default when nothing else asks.
const (
	langJA = "ja"
	langEN = "en"
)

// strs holds every word the page prints, per language. Both tables must have
// the same keys (a test checks it). Values that come from the store (IDs,
// hashes, codes) are never looked up here; only fixed enumerations are.
var strs = map[string]map[string]string{
	langJA: {
		"title":           "Kairan フリート状況",
		"tenant":          "テナント",
		"generated":       "表示時刻",
		"refresh":         "10秒ごとに自動更新します。",
		"lang.switch":     "English",
		"summary":         "概要",
		"stat.total":      "プロキシ合計",
		"stat.healthy":    "正常",
		"stat.stale":      "遅延",
		"stat.lost":       "途絶",
		"stat.tampered":   "改ざん検知",
		"stat.safe_mode":  "セーフモード",
		"stat.clock":      "時計が信頼できません",
		"rollout":         "ロールアウト",
		"rollout.none":    "ロールアウトはありません。",
		"rollout.version": "バージョン",
		"rollout.phase":   "フェーズ",
		"rollout.reason":  "停止理由",
		"fleet":           "プロキシ一覧",
		"empty":           "まだ報告したプロキシはありません。",
		"col.proxy":       "プロキシ",
		"col.group":       "グループ",
		"col.health":      "稼働状況",
		"col.state":       "状態",
		"col.desired":     "目標バージョン",
		"col.applied":     "適用済みバージョン",
		"col.drift":       "差分",
		"col.hash":        "ポリシーハッシュ",
		"col.seen":        "最終受信",
		"col.error":       "最後のエラー",
		"never":           "未受信",
		"none":            "なし",
		"drift.sync":      "同期済み",
		"drift.behind":    "バージョン遅れ",
		"drift.ahead":     "目標より先行",
		"drift.notarget":  "目標なし",
		"back":            "一覧に戻る",
		"error.title":     "エラー",

		"health.healthy": "正常",
		"health.stale":   "遅延",
		"health.lost":    "途絶",

		"state.booting":   "起動中",
		"state.deny_all":  "全拒否(ポリシーなし)",
		"state.tampered":  "改ざん検知(全拒否)",
		"state.enforcing": "適用中",
		"state.safe_mode": "セーフモード",

		"phase.canary":    "カナリア",
		"phase.promoting": "展開中",
		"phase.halted":    "停止",
		"phase.complete":  "完了",

		"err.bad_request":        "リクエストが正しくありません",
		"err.unauthorized":       "認証が必要です",
		"err.forbidden":          "権限がありません",
		"err.not_found":          "見つかりません",
		"err.method_not_allowed": "このメソッドは使えません",
		"err.conflict":           "すでに存在します",
		"err.too_large":          "サイズが大きすぎます",
		"err.internal":           "内部エラーが発生しました",
		"err.unavailable":        "一時的に利用できません",
		"err.malformed":          "ポリシーの形式が正しくありません",
		"err.payload_type":       "ペイロードの種別が正しくありません",
		"err.threshold_not_met":  "有効な署名の数が足りません",
		"err.wrong_tenant":       "テナントが一致しません",
		"err.version_not_newer":  "バージョンが新しくありません",
		"err.expired":            "ポリシーの期限が切れています",
		"err.persist_failed":     "ポリシーを保存できませんでした",
		"err.tampered":           "保存されたポリシーが改ざんされています",
		"err.canary_lost":        "カナリアが応答しません",
		"err.clock_untrusted":    "時計が信頼できません",
	},
	langEN: {
		"title":           "Kairan fleet status",
		"tenant":          "Tenant",
		"generated":       "Generated at",
		"refresh":         "Refreshes every 10 seconds.",
		"lang.switch":     "日本語",
		"summary":         "Summary",
		"stat.total":      "Proxies",
		"stat.healthy":    "Healthy",
		"stat.stale":      "Stale",
		"stat.lost":       "Lost",
		"stat.tampered":   "Tampered",
		"stat.safe_mode":  "Safe mode",
		"stat.clock":      "Clock untrusted",
		"rollout":         "Rollout",
		"rollout.none":    "No rollout.",
		"rollout.version": "Version",
		"rollout.phase":   "Phase",
		"rollout.reason":  "Halt reason",
		"fleet":           "Proxies",
		"empty":           "No proxy has reported yet.",
		"col.proxy":       "Proxy",
		"col.group":       "Group",
		"col.health":      "Health",
		"col.state":       "State",
		"col.desired":     "Desired version",
		"col.applied":     "Applied version",
		"col.drift":       "Drift",
		"col.hash":        "Policy hash",
		"col.seen":        "Last seen",
		"col.error":       "Last error",
		"never":           "never",
		"none":            "none",
		"drift.sync":      "in sync",
		"drift.behind":    "behind",
		"drift.ahead":     "ahead of target",
		"drift.notarget":  "no target",
		"back":            "Back to the fleet",
		"error.title":     "Error",

		"health.healthy": "Healthy",
		"health.stale":   "Stale",
		"health.lost":    "Lost",

		"state.booting":   "Booting",
		"state.deny_all":  "Deny all (no policy)",
		"state.tampered":  "Tampered (deny all)",
		"state.enforcing": "Enforcing",
		"state.safe_mode": "Safe mode",

		"phase.canary":    "Canary",
		"phase.promoting": "Promoting",
		"phase.halted":    "Halted",
		"phase.complete":  "Complete",

		"err.bad_request":        "The request is not valid",
		"err.unauthorized":       "Authentication is required",
		"err.forbidden":          "Not allowed",
		"err.not_found":          "Not found",
		"err.method_not_allowed": "This method is not allowed",
		"err.conflict":           "Already exists",
		"err.too_large":          "Too large",
		"err.internal":           "Internal error",
		"err.unavailable":        "Temporarily unavailable",
		"err.malformed":          "The policy is malformed",
		"err.payload_type":       "Wrong payload type",
		"err.threshold_not_met":  "Not enough valid signatures",
		"err.wrong_tenant":       "Wrong tenant",
		"err.version_not_newer":  "The version is not newer",
		"err.expired":            "The policy has expired",
		"err.persist_failed":     "The policy could not be saved",
		"err.tampered":           "The stored policy was tampered with",
		"err.canary_lost":        "Canary stopped reporting",
		"err.clock_untrusted":    "The clock cannot be trusted",
	},
}

// tr returns the text for key, or the key itself if there is none.
func tr(lang, key string) string {
	if s, ok := strs[lang][key]; ok {
		return s
	}
	return key
}

// has reports whether key exists in the table of lang.
func has(lang, key string) bool {
	_, ok := strs[lang][key]
	return ok
}

// other is the language the switch link points to.
func other(lang string) string {
	if lang == langJA {
		return langEN
	}
	return langJA
}

// maxAcceptLanguage bounds the header we are willing to parse.
const maxAcceptLanguage = 256

// pickLang chooses the page language. An explicit ?lang= of exactly "ja" or
// "en" wins; anything else falls back to Accept-Language (highest q first),
// then to Japanese.
func pickLang(query, accept string) string {
	if query == langJA || query == langEN {
		return query
	}
	if len(accept) > maxAcceptLanguage {
		return langJA
	}
	type cand struct {
		lang string
		q    float64
	}
	var cands []cand
	for _, part := range strings.Split(accept, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		q := 1.0
		if k, v, ok := strings.Cut(strings.TrimSpace(params), "="); ok && strings.TrimSpace(k) == "q" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f >= 0 && f <= 1 {
				q = f
			}
		}
		if q == 0 {
			continue
		}
		for _, l := range []string{langJA, langEN} {
			if tag == l || strings.HasPrefix(tag, l+"-") {
				cands = append(cands, cand{l, q})
			}
		}
	}
	if len(cands) == 0 {
		return langJA
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	return cands[0].lang
}

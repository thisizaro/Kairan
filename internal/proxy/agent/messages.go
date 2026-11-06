package agent

import (
	"context"
	"log/slog"
)

// Log lines of the agent are messages for a person, so they are in English and
// Japanese (PRD J7, M-D62). The English text is the msg field (log pipelines
// and tests match on it) and the Japanese text is the msg_ja field of the same
// line. Every log call of this package goes through say; a test scans the
// source for any that does not.

// event is one log line, in both languages.
type event struct{ en, ja string }

var (
	evBoot             = event{"boot", "起動時の判定"}
	evRepairNotWritten = event{"boot: repair entry not written; staying tampered",
		"起動時: 補修の記録を書けないため、改ざん状態のままにします"}
	evSaveFailed = event{"apply: save failed", "適用: ポリシーの保存に失敗しました"}
	evLogAppend  = event{"apply: log append failed", "適用: 適用ログへの追記に失敗しました"}
	evApplied    = event{"policy applied", "ポリシーを適用しました"}
	evRejected   = event{"envelope rejected", "署名付きポリシーを拒否しました"}
	evRejectLost = event{"apply log: rejection not recorded", "適用ログ: 拒否を記録できませんでした"}
	evExpired    = event{"policy expired; safe mode", "ポリシーの有効期限が切れました。セーフモードにします"}
	evPollFailed = event{"poll failed", "コントロールプレーンの確認に失敗しました"}
	evCPDown     = event{"control plane unavailable", "コントロールプレーンが利用できません"}
	evPollRefuse = event{"poll refused", "コントロールプレーンが確認を拒否しました"}
	evStatusBad  = event{"status report invalid; not sent", "状態報告が正しくないため送りません"}
	evStatusFail = event{"status report failed", "状態報告の送信に失敗しました"}
	evStatusNo   = event{"status report refused", "状態報告が拒否されました"}
	evLogReset   = event{"apply log reset: the broken log was kept and a new chain started",
		"適用ログをリセットしました: 壊れたログは証拠として保存し、新しいチェーンを開始しました"}
	evResetFailed = event{"apply log reset failed; nothing applied",
		"適用ログのリセットに失敗しました。何も適用していません"}
	evClockSave = event{"clock high-water save failed", "時計のハイウォーターマークの保存に失敗しました"}

	evClockUntrusted = event{"wall clock is more than 5 minutes behind effective time; clock untrusted; expiry follows effective time, not the wall clock",
		"システム時計が有効時刻より 5 分以上遅れています。時計を信頼できません。有効期限は有効時刻に従い、システム時計には従いません"}
	evClockTrusted = event{"wall clock is trusted again", "システム時計を再び信頼できます"}
)

// events lists every log event of the package, so that a test can check each
// has both languages.
var events = []event{evBoot, evRepairNotWritten, evSaveFailed, evLogAppend, evApplied, evRejected, evRejectLost,
	evExpired, evPollFailed, evCPDown, evPollRefuse, evStatusBad, evStatusFail, evStatusNo, evClockSave, evLogReset, evResetFailed,
	evClockUntrusted, evClockTrusted}

// say logs ev in both languages.
func say(log *slog.Logger, level slog.Level, ev event, attrs ...any) {
	log.Log(context.Background(), level, ev.en, append([]any{slog.String("msg_ja", ev.ja)}, attrs...)...)
}

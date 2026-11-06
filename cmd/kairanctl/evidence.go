package main

// Evidence cross-check (T-07; M-D7, M-D29, M-D35, M-D48, M-D55): the control
// plane's timeline is compared with each proxy's own apply log. The control
// plane could lie (THREATS #2); the proxy's hash-chained log is read inside
// the customer network and is the stronger witness. Anything that does not
// agree is printed as a FLAG line and makes the command exit 1.
//
// What is checked, per proxy:
//   - timeline alone: the apply-log anchor (log_seq, log_head) never goes
//     backwards between periods (M-D48: the store starts a new period when it
//     does, so 7 then 5 is visible), the same seq always has the same head,
//     and the version never goes down.
//   - with the proxy's apply log: the chain verifies (applylog.Verify rules);
//     every anchor the control plane recorded is an entry of that log (a
//     recorded seq beyond the log's end means the tail was cut off); every
//     version and hash the control plane says was enforced has an applied
//     entry in the log; and the log's newest applied version is the one the
//     control plane last saw.
//
// A period with version 0 and an empty hash is a proxy's deny-all boot (Q-D40,
// M-D71): "no policy". It is printed as such, never compared with the log's
// applied versions, and its anchor is checked like any other.
//
// Dropped timeline entries (the control plane keeps at most 256 per proxy;
// M-D55) are reported as a WARNING, because the export is then incomplete,
// but they are not a mismatch and do not change the exit code.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

// maxApplyLogBytes is the largest apply log file read into memory (about
// 190,000 entries).
const maxApplyLogBytes = 64 << 20

// dropped is how many earlier timeline entries the control plane discarded.
type dropped struct {
	total   uint64
	byProxy map[wire.ID]uint64 // only non-zero counts
}

// checkDropped validates the dropped counts of the timeline answer (M-D55,
// M-D56): proxy IDs must be valid (they are printed) and the sum must not
// overflow. Zero counts are left out. wire.Decode has already refused
// anything that is not an object of non-negative integers.
func checkDropped(m map[wire.ID]uint64) (dropped, error) {
	var d dropped
	for id, n := range m {
		if !id.Valid() {
			return dropped{}, errors.New("bad dropped proxy ID")
		}
		if n == 0 {
			continue
		}
		if d.total > math.MaxUint64-n {
			return dropped{}, errors.New("bad dropped count")
		}
		d.total += n
		if d.byProxy == nil {
			d.byProxy = map[wire.ID]uint64{}
		}
		d.byProxy[id] = n
	}
	return d, nil
}

// parseLogArg splits "PROXY_ID=FILE".
func parseLogArg(s string) (wire.ID, string, bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", false
	}
	id, path := wire.ID(s[:i]), s[i+1:]
	if !id.Valid() || path == "" || !utf8.ValidString(path) || strings.IndexByte(path, 0) >= 0 {
		return "", "", false
	}
	return id, path, true
}

// logInput is one proxy's apply log as read from disk. entries are the
// entries that verified; err is non-nil if the chain did not.
type logInput struct {
	entries []applylog.Entry
	err     error
}

// finding is one thing the evidence check wants the reader to see.
type finding struct {
	proxy  wire.ID
	kind   string // version, seq, head, regression, anchor, log
	en, ja string
}

// crossCheck compares the (already sorted) timeline with the supplied logs.
// It returns the findings in proxy order.
func crossCheck(timeline []wire.TimelineEntry, logs map[wire.ID]*logInput) []finding {
	byProxy := map[wire.ID][]wire.TimelineEntry{}
	ids := map[wire.ID]bool{}
	for _, e := range timeline {
		byProxy[e.ProxyID] = append(byProxy[e.ProxyID], e)
		ids[e.ProxyID] = true
	}
	for id := range logs {
		ids[id] = true
	}
	order := make([]wire.ID, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	var out []finding
	for _, id := range order {
		periods := byProxy[id]
		out = append(out, checkTimelineAlone(id, periods)...)
		lg := logs[id]
		if lg == nil {
			continue
		}
		if len(periods) == 0 {
			out = append(out, finding{id, "log",
				fmt.Sprintf("an apply log was supplied for proxy %s, but the control plane timeline has no entry for it", id),
				fmt.Sprintf("プロキシ %s の適用ログが指定されましたが、コントロールプレーンのタイムラインに該当する記録がありません", id)})
			continue
		}
		if lg.err != nil {
			out = append(out, finding{id, "log",
				fmt.Sprintf("the apply log of proxy %s failed verification after %d good entries (%s); it was not compared", id, len(lg.entries), logProblem(lg.err)),
				fmt.Sprintf("プロキシ %s の適用ログは %d 件目まで正常で、その後の検証に失敗しました (%s)。比較は行っていません", id, len(lg.entries), logProblemJa(lg.err))})
			continue
		}
		out = append(out, checkAgainstLog(id, periods, lg.entries)...)
	}
	return out
}

func logProblem(err error) string {
	switch {
	case errors.Is(err, applylog.ErrTruncated):
		return "the file ends in an incomplete line"
	case errors.Is(err, applylog.ErrChain):
		return "the hash chain is broken: an entry was edited, deleted, reordered or added"
	case errors.Is(err, applylog.ErrMalformed):
		return "a line is not a valid log entry"
	}
	return "the file could not be read"
}

func logProblemJa(err error) string {
	switch {
	case errors.Is(err, applylog.ErrTruncated):
		return "ファイルが不完全な行で終わっています"
	case errors.Is(err, applylog.ErrChain):
		return "ハッシュ連鎖が壊れています。エントリの改変・削除・並べ替え・追加の可能性があります"
	case errors.Is(err, applylog.ErrMalformed):
		return "不正な形式の行があります"
	}
	return "ファイルを読めませんでした"
}

// checkTimelineAlone needs no proxy log: the anchor and the version must only
// move forward across the periods of one proxy (oldest first).
func checkTimelineAlone(id wire.ID, periods []wire.TimelineEntry) []finding {
	var out []finding
	var maxSeq, maxVersion uint64
	var headAtMax wire.Hash
	for _, e := range periods {
		at := fmtTime(e.FirstSeenUnixMs)
		if e.Version < maxVersion {
			out = append(out, finding{id, "version",
				fmt.Sprintf("proxy %s: the control plane timeline shows version %d at %s, after it had shown version %d", id, e.Version, at, maxVersion),
				fmt.Sprintf("プロキシ %s: コントロールプレーンのタイムラインで、バージョン %d の後の %s にバージョン %d が記録されています", id, maxVersion, at, e.Version)})
		} else {
			maxVersion = e.Version
		}
		if (e.LogSeq > 0) != (e.LogHead != "") {
			// A real proxy reports both or neither (M-D63). One alone is not
			// an anchor, and may hide a truncated or rewritten log.
			out = append(out, finding{id, "anchor",
				fmt.Sprintf("proxy %s: the control plane timeline has an incomplete apply-log anchor at %s (%s); a proxy reports the seq and the head together, so this may hide a cut or rewritten log", id, at, halfAnchor(e, false)),
				fmt.Sprintf("プロキシ %s: %s のタイムラインの適用ログのアンカーが不完全です (%s)。プロキシは seq とヘッドを必ず一緒に報告するため、ログの切り詰めや書き換えが隠れている可能性があります", id, at, halfAnchor(e, true))})
			continue
		}
		switch {
		case e.LogSeq < maxSeq:
			out = append(out, finding{id, "regression",
				fmt.Sprintf("proxy %s: the apply-log anchor went backwards: seq %d reported from %s, after seq %d had been reported (the log was cut short or rewritten, or the control plane is wrong)", id, e.LogSeq, at, maxSeq),
				fmt.Sprintf("プロキシ %s: 適用ログのアンカーが後退しました。seq %d の後の %s に seq %d が報告されています (ログの切り詰め・書き換え、またはコントロールプレーンの誤りの可能性)", id, maxSeq, at, e.LogSeq)})
		case e.LogSeq == maxSeq && maxSeq > 0 && e.LogHead != headAtMax:
			out = append(out, finding{id, "head",
				fmt.Sprintf("proxy %s: two different heads were reported for apply-log seq %d (%s at %s)", id, maxSeq, shortHash(e.LogHead), at),
				fmt.Sprintf("プロキシ %s: 適用ログ seq %d に対して異なるヘッドが報告されました (%s, %s)", id, maxSeq, shortHash(e.LogHead), at)})
		default:
			maxSeq, headAtMax = e.LogSeq, e.LogHead
		}
	}
	return out
}

func halfAnchor(e wire.TimelineEntry, ja bool) string {
	if e.LogSeq > 0 {
		if ja {
			return fmt.Sprintf("seq %d のみでヘッドなし", e.LogSeq)
		}
		return fmt.Sprintf("seq %d without a head", e.LogSeq)
	}
	if ja {
		return fmt.Sprintf("ヘッド %s のみで seq なし", shortHash(e.LogHead))
	}
	return fmt.Sprintf("head %s without a seq", shortHash(e.LogHead))
}

// checkAgainstLog compares one proxy's verified log with its timeline.
func checkAgainstLog(id wire.ID, periods []wire.TimelineEntry, log []applylog.Entry) []finding {
	var out []finding
	n := uint64(len(log))
	applied := map[uint64]map[wire.Hash]bool{}
	var newest *applylog.Entry
	for i := range log {
		if log[i].Result == "" {
			if applied[log[i].To] == nil {
				applied[log[i].To] = map[wire.Hash]bool{}
			}
			applied[log[i].To][log[i].Hash] = true
			newest = &log[i]
		}
	}
	for _, e := range periods {
		at := fmtTime(e.FirstSeenUnixMs)
		if e.LogSeq > 0 && e.LogHead != "" { // a half-set anchor is flagged by checkTimelineAlone
			switch {
			case e.LogSeq > n:
				out = append(out, finding{id, "seq",
					fmt.Sprintf("proxy %s: the control plane recorded apply-log seq %d at %s, but the proxy's log ends at seq %d (the tail of the log was cut off, or this is a different log)", id, e.LogSeq, at, n),
					fmt.Sprintf("プロキシ %s: コントロールプレーンは %s に適用ログ seq %d を記録しましたが、プロキシのログは seq %d で終わっています (末尾が切り取られたか、別のログです)", id, at, e.LogSeq, n)})
			case log[e.LogSeq-1].Self != e.LogHead:
				out = append(out, finding{id, "head",
					fmt.Sprintf("proxy %s: at seq %d the control plane recorded head %s (%s), but the proxy's log has head %s (the log was rewritten, or this is a different log)", id, e.LogSeq, shortHash(e.LogHead), at, shortHash(log[e.LogSeq-1].Self)),
					fmt.Sprintf("プロキシ %s: seq %d でコントロールプレーンが記録したヘッド %s (%s) と、プロキシのログのヘッド %s が一致しません (ログの書き換え、または別のログです)", id, e.LogSeq, shortHash(e.LogHead), at, shortHash(log[e.LogSeq-1].Self))})
			}
		}
		if isNoPolicy(e) {
			continue // no policy was enforced; there is nothing in the log to match (M-D71)
		}
		hashes, ok := applied[e.Version]
		switch {
		case !ok:
			out = append(out, finding{id, "version",
				fmt.Sprintf("proxy %s: the control plane says version %d (hash %s) was enforced from %s, but the proxy's apply log has no applied entry for version %d", id, e.Version, shortHash(e.PolicyHash), at, e.Version),
				fmt.Sprintf("プロキシ %s: コントロールプレーンは %s からバージョン %d (ハッシュ %s) が適用されていたと記録していますが、プロキシの適用ログにバージョン %d の適用記録がありません", id, at, e.Version, shortHash(e.PolicyHash), e.Version)})
		case !hashes[e.PolicyHash]:
			out = append(out, finding{id, "version",
				fmt.Sprintf("proxy %s: version %d is in the apply log, but with a different hash than the control plane recorded (%s from %s)", id, e.Version, shortHash(e.PolicyHash), at),
				fmt.Sprintf("プロキシ %s: バージョン %d は適用ログにありますが、コントロールプレーンの記録 (%s, %s) とハッシュが異なります", id, e.Version, shortHash(e.PolicyHash), at)})
		}
	}
	// The newest period that enforced a policy; "no policy" periods are not
	// compared with the log.
	var last *wire.TimelineEntry
	for i := len(periods) - 1; i >= 0; i-- {
		if !isNoPolicy(periods[i]) {
			last = &periods[i]
			break
		}
	}
	switch {
	case last == nil:
		if newest != nil {
			out = append(out, finding{id, "version",
				fmt.Sprintf("proxy %s: the apply log's newest applied version is %d, but the control plane has only seen the proxy without a policy (a newer apply may not have been reported yet)", id, newest.To),
				fmt.Sprintf("プロキシ %s: 適用ログの最新の適用バージョンは %d ですが、コントロールプレーンはポリシーなしの状態しか確認していません (新しい適用がまだ報告されていない可能性があります)", id, newest.To)})
		}
	case newest == nil:
		out = append(out, finding{id, "version",
			fmt.Sprintf("proxy %s: the apply log has no applied version, but the control plane last saw version %d", id, last.Version),
			fmt.Sprintf("プロキシ %s: 適用ログに適用済みバージョンがありませんが、コントロールプレーンが最後に確認したのはバージョン %d です", id, last.Version)})
	case newest.To != last.Version:
		out = append(out, finding{id, "version",
			fmt.Sprintf("proxy %s: the apply log's newest applied version %d differs from version %d, the last the control plane saw (a newer apply may not have been reported yet)", id, newest.To, last.Version),
			fmt.Sprintf("プロキシ %s: 適用ログの最新の適用バージョン %d が、コントロールプレーンが最後に確認したバージョン %d と異なります (新しい適用がまだ報告されていない可能性があります)", id, newest.To, last.Version)})
	}
	return out
}

// readApplyLog reads and verifies one apply log file. A file that cannot be
// opened or is too large is an error of the command; a chain that fails to
// verify is data (logInput.err) and becomes a finding.
func readApplyLog(path string) (*logInput, *cliError) {
	f, st, err := openRegular(path)
	switch {
	case errors.Is(err, errNotRegular):
		return nil, fail("an apply log file is not a regular file", "適用ログのファイルが通常のファイルではありません")
	case err != nil:
		return nil, fail("cannot read an apply log file: "+reason(err), "適用ログのファイルを読めません: "+reasonJa(err))
	}
	defer f.Close()
	if st.Size() > maxApplyLogBytes {
		return nil, fail("an apply log file is larger than the 64 MiB limit", "適用ログのファイルが上限 (64 MiB) を超えています")
	}
	entries, rerr := applylog.Read(io.LimitReader(f, maxApplyLogBytes+1))
	if rerr != nil && !errors.Is(rerr, applylog.ErrChain) && !errors.Is(rerr, applylog.ErrMalformed) && !errors.Is(rerr, applylog.ErrTruncated) {
		return nil, fail("cannot read an apply log file: "+reason(rerr), "適用ログのファイルを読めません: "+reasonJa(rerr))
	}
	return &logInput{entries: entries, err: rerr}, nil
}

// cmdVerifyApplylog checks one apply log's hash chain (I6). It cannot see a
// cut-off tail; evidence export compares the log with the control plane's
// anchor for that.
func cmdVerifyApplylog(args []string, s streams) error {
	fs := flag.NewFlagSet("verify-applylog", flag.ContinueOnError)
	in := fs.String("in", "", "apply log file to verify")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *in == "" {
		return usageErr("-in FILE is required", "-in FILE を指定してください")
	}
	f, _, err := openRegular(*in)
	switch {
	case errors.Is(err, errNotRegular):
		return fail("the apply log is not a regular file", "適用ログが通常のファイルではありません")
	case err != nil:
		return fail("cannot read the apply log: "+reason(err), "適用ログを読めません: "+reasonJa(err))
	}
	defer f.Close()
	last, n, verr := applylog.Verify(f)
	if verr != nil {
		return fail(fmt.Sprintf("the apply log FAILED verification after %d good entries: %s", n, logProblem(verr)),
			fmt.Sprintf("適用ログの検証に失敗しました (%d 件目まで正常): %s", n, logProblemJa(verr))).because(verr)
	}
	if n == 0 {
		fmt.Fprintln(s.out, "apply log verified: empty (0 entries)")
		return nil
	}
	fmt.Fprintf(s.out, "apply log verified: %d entries, newest seq %d, head %s, written %s\n",
		n, last.Seq, last.Self, fmtTime(last.Time.UnixMilli()))
	return nil
}

package main

import (
	"flag"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"kairan/internal/wire"
)

// cmdEvidenceExport writes the control plane's record of which policy each
// proxy reported, as plain sentences with JST and UTC times (J5). With
// -applylog PROXY=FILE (repeatable) it also cross-checks that record against
// the proxy's own apply log (T-07); any mismatch is a FLAG line and exit 1.
func cmdEvidenceExport(args []string, s streams) error {
	fs := flag.NewFlagSet("evidence export", flag.ContinueOnError)
	cf := addConnFlags(fs)
	tenant := fs.String("tenant", "", "tenant ID")
	proxy := fs.String("proxy", "", "only this proxy ID")
	out := fs.String("out", "", "file to create; default is standard output")
	var logArgs []string
	fs.Func("applylog", "PROXY_ID=FILE: a proxy's apply log to cross-check (repeatable)", func(v string) error {
		logArgs = append(logArgs, v)
		return nil
	})
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if cerr := tenantFlagErr(*tenant); cerr != nil {
		return cerr
	}
	if *proxy != "" && !wire.ID(*proxy).Valid() {
		return fail("-proxy must be a valid proxy ID", "-proxy には有効なプロキシIDを指定してください")
	}
	logPaths := map[wire.ID]string{}
	for _, a := range logArgs {
		id, path, ok := parseLogArg(a)
		switch {
		case !ok:
			return usageErr("-applylog must be PROXY_ID=FILE with a valid proxy ID", "-applylog には PROXY_ID=FILE の形式で有効なプロキシIDを指定してください")
		case logPaths[id] != "":
			return usageErr("-applylog was given twice for the same proxy", "同じプロキシに -applylog が重複しています")
		case *proxy != "" && string(id) != *proxy:
			return usageErr("-applylog names a proxy that -proxy filters out", "-applylog が -proxy で除外されるプロキシを指しています")
		}
		logPaths[id] = path
	}
	logs := map[wire.ID]*logInput{}
	for id, path := range logPaths {
		li, cerr := readApplyLog(path)
		if cerr != nil {
			return cerr
		}
		logs[id] = li
	}
	cl, err := cf.open(s)
	if err != nil {
		return err
	}
	var view wire.TimelineView
	if _, cerr := cl.doChecked("GET", wire.PathTimeline, url.Values{wire.QueryTenant: {*tenant}}, nil, &view, strictTimelineKeys); cerr != nil {
		return cerr
	}
	if cerr := checkTimeline(view, *tenant); cerr != nil {
		return cerr
	}
	drop, derr := checkDropped(view.Dropped)
	if derr != nil {
		return badAnswer()
	}
	var entries []wire.TimelineEntry
	for _, e := range view.Entries {
		if *proxy == "" || string(e.ProxyID) == *proxy {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.ProxyID != b.ProxyID {
			return a.ProxyID < b.ProxyID
		}
		if a.FirstSeenUnixMs != b.FirstSeenUnixMs {
			return a.FirstSeenUnixMs < b.FirstSeenUnixMs
		}
		return a.Version < b.Version
	})
	findings := crossCheck(entries, logs)

	var b strings.Builder
	fmt.Fprintf(&b, "Evidence export for tenant %s\n", view.Tenant)
	b.WriteString("Source: the control plane's record of what each proxy reported. Times are when the control plane saw the reports (JST and UTC);\n")
	b.WriteString("they are not proof from the proxy itself. Compare with the proxy apply logs (-applylog) before relying on this.\n\n")
	if len(entries) == 0 {
		b.WriteString("no entries\n")
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "proxy %s enforced version %d (hash %s) from %s to %s\n",
			e.ProxyID, e.Version, e.PolicyHash, fmtTime(e.FirstSeenUnixMs), fmtTime(e.LastSeenUnixMs))
	}
	writeCrossCheck(&b, entries, logs, findings, drop)
	if *out == "" {
		if _, err := fmt.Fprint(s.out, b.String()); err != nil {
			return err
		}
	} else {
		if err := createExclusive(*out, []byte(b.String()), 0o644); err != nil {
			return writeErr(err)
		}
		fmt.Fprintf(s.out, "wrote %s (%d entries)\n", *out, len(entries))
	}
	if len(findings) > 0 {
		return fail(fmt.Sprintf("evidence check found %d problem(s); see the FLAG lines", len(findings)),
			fmt.Sprintf("証拠の照合で %d 件の問題が見つかりました。FLAG の行を確認してください", len(findings)))
	}
	return nil
}

// writeCrossCheck prints the cross-check section, if there is anything to say.
func writeCrossCheck(b *strings.Builder, entries []wire.TimelineEntry, logs map[wire.ID]*logInput, findings []finding, drop dropped) {
	if len(logs) == 0 && len(findings) == 0 && drop.total == 0 {
		return
	}
	b.WriteString("\nCross-check against proxy apply logs / プロキシ適用ログとの照合:\n")
	seen := map[wire.ID]bool{}
	var ids []wire.ID
	for _, e := range entries {
		if !seen[e.ProxyID] {
			seen[e.ProxyID] = true
			ids = append(ids, e.ProxyID)
		}
	}
	for id := range logs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		li := logs[id]
		switch {
		case li == nil:
			if len(logs) > 0 {
				fmt.Fprintf(b, "proxy %s: no apply log supplied; not cross-checked\n", id)
			}
		case li.err != nil:
			fmt.Fprintf(b, "proxy %s: apply log FAILED verification after %d good entries\n", id, len(li.entries))
		case len(li.entries) == 0:
			fmt.Fprintf(b, "proxy %s: apply log verified: empty (0 entries)\n", id)
		default:
			last := li.entries[len(li.entries)-1]
			fmt.Fprintf(b, "proxy %s: apply log verified: %d entries, newest seq %d (head %s) written %s\n",
				id, len(li.entries), last.Seq, shortHash(last.Self), fmtTime(last.Time.UnixMilli()))
		}
	}
	if drop.total > 0 {
		fmt.Fprintf(b, "WARNING [dropped] %d earlier timeline entries were dropped by the control plane (it keeps at most 256 per proxy); this export does not cover the whole history\n", drop.total)
		fmt.Fprintf(b, "     警告: コントロールプレーンが古いタイムライン %d 件を破棄しました (プロキシごとに最大256件)。この出力は全履歴を含みません\n", drop.total)
		for _, id := range sortedIDs(drop.byProxy) {
			fmt.Fprintf(b, "     proxy %s: %d dropped\n", id, drop.byProxy[id])
		}
	}
	for _, f := range findings {
		fmt.Fprintf(b, "FLAG [%s] %s\n     %s\n", f.kind, f.en, f.ja)
	}
	switch {
	case len(findings) > 0:
		fmt.Fprintf(b, "Result: %d problem(s) found / 結果: %d 件の問題\n", len(findings), len(findings))
	case len(logs) > 0:
		fmt.Fprintf(b, "Result: no mismatch found between the control plane timeline and the %d apply log(s) supplied / 結果: 指定された適用ログ %d 件との不一致なし\n", len(logs), len(logs))
	}
}

func sortedIDs(m map[wire.ID]uint64) []wire.ID {
	ids := make([]wire.ID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"kairan/internal/wire"
)

func removeQuiet(path string) { _ = os.Remove(path) }

// jst is Japan Standard Time. A fixed zone, so no time zone database is needed.
var jst = time.FixedZone("JST", 9*3600)

// Times from the control plane must lie in years 2000..9999 to be shown.
const (
	minUnixMs = 946684800000
	maxUnixMs = 253402300799999
)

// fmtTime shows an instant in JST and UTC (J5, J7).
func fmtTime(ms int64) string {
	t := time.UnixMilli(ms)
	return t.In(jst).Format("2006-01-02 15:04:05 MST") + " (" + t.UTC().Format("2006-01-02 15:04:05") + " UTC)"
}

func validMs(ms int64) bool { return ms >= minUnixMs && ms <= maxUnixMs }

func shortHash(h wire.Hash) string {
	if h == "" {
		return "-"
	}
	return string(h[:12])
}

func checkFleet(v wire.FleetView, tenant string) *cliError {
	if string(v.Tenant) != tenant {
		return badAnswer()
	}
	for _, p := range v.Proxies {
		okHealth := p.Health == wire.HealthHealthy || p.Health == wire.HealthStale || p.Health == wire.HealthLost
		if !p.ProxyID.Valid() || !p.Group.Valid() || !okHealth || !p.State.Valid() ||
			(p.PolicyHash != "" && !p.PolicyHash.Valid()) || !validMs(p.LastSeenUnixMs) ||
			(p.LastError != nil && !p.LastError.Code.Valid()) {
			return badAnswer()
		}
	}
	return nil
}

// cmdFleet prints the fleet: which proxy is on which policy version.
func cmdFleet(args []string, s streams) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
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
	var view wire.FleetView
	if _, cerr := cl.do("GET", wire.PathFleet, url.Values{wire.QueryTenant: {*tenant}}, nil, &view); cerr != nil {
		return cerr
	}
	if cerr := checkFleet(view, *tenant); cerr != nil {
		return cerr
	}
	if len(view.Proxies) == 0 {
		fmt.Fprintf(s.out, "tenant %s: no proxies have reported yet\n", view.Tenant)
		return nil
	}
	proxies := append([]wire.ProxyView(nil), view.Proxies...)
	sort.SliceStable(proxies, func(i, j int) bool { return proxies[i].ProxyID < proxies[j].ProxyID })
	fmt.Fprintf(s.out, "tenant %s: %d proxies\n", view.Tenant, len(proxies))
	tw := tabwriter.NewWriter(s.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROXY\tGROUP\tHEALTH\tSTATE\tDESIRED\tAPPLIED\tDRIFT\tHASH\tLAST SEEN\tLAST ERROR")
	for _, p := range proxies {
		last := "-"
		if p.LastError != nil {
			last = string(p.LastError.Code)
			if p.LastError.Version != 0 {
				last += fmt.Sprintf(" (v%d)", p.LastError.Version)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", p.ProxyID, p.Group, p.Health, p.State,
			p.DesiredVersion, p.AppliedVersion, p.Drift, shortHash(p.PolicyHash), fmtTime(p.LastSeenUnixMs), last)
	}
	return tw.Flush()
}

func cmdEvidence(args []string, s streams) error {
	if len(args) == 0 || args[0] != "export" {
		return usageErr("unknown evidence command (try: evidence export)", "evidence のサブコマンドが不明です (evidence export を使います)")
	}
	return cmdEvidenceExport(args[1:], s)
}

func checkTimeline(v wire.TimelineView, tenant string) *cliError {
	if string(v.Tenant) != tenant {
		return badAnswer()
	}
	for _, e := range v.Entries {
		if !e.ProxyID.Valid() || e.Version < 1 || !e.PolicyHash.Valid() ||
			!validMs(e.FirstSeenUnixMs) || !validMs(e.LastSeenUnixMs) || e.LastSeenUnixMs < e.FirstSeenUnixMs {
			return badAnswer()
		}
	}
	return nil
}

// cmdEvidenceExport writes the control plane's record of which policy each
// proxy reported, as plain sentences with JST and UTC times (J5). It is the
// control plane's word only; the cross-check with proxy apply logs is T-07.
func cmdEvidenceExport(args []string, s streams) error {
	fs := flag.NewFlagSet("evidence export", flag.ContinueOnError)
	cf := addConnFlags(fs)
	tenant := fs.String("tenant", "", "tenant ID")
	proxy := fs.String("proxy", "", "only this proxy ID")
	out := fs.String("out", "", "file to create; default is standard output")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if cerr := tenantFlagErr(*tenant); cerr != nil {
		return cerr
	}
	if *proxy != "" && !wire.ID(*proxy).Valid() {
		return fail("-proxy must be a valid proxy ID", "-proxy には有効なプロキシIDを指定してください")
	}
	cl, err := cf.open(s)
	if err != nil {
		return err
	}
	var view wire.TimelineView
	if _, cerr := cl.do("GET", wire.PathTimeline, url.Values{wire.QueryTenant: {*tenant}}, nil, &view); cerr != nil {
		return cerr
	}
	if cerr := checkTimeline(view, *tenant); cerr != nil {
		return cerr
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

	var b strings.Builder
	fmt.Fprintf(&b, "Evidence export for tenant %s\n", view.Tenant)
	b.WriteString("Source: the control plane's record of what each proxy reported. Times are when the control plane saw the reports (JST and UTC);\n")
	b.WriteString("they are not proof from the proxy itself. Compare with the proxy apply logs before relying on this.\n\n")
	if len(entries) == 0 {
		b.WriteString("no entries\n")
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "proxy %s enforced version %d (hash %s) from %s to %s\n",
			e.ProxyID, e.Version, e.PolicyHash, fmtTime(e.FirstSeenUnixMs), fmtTime(e.LastSeenUnixMs))
	}
	if *out == "" {
		_, err := fmt.Fprint(s.out, b.String())
		return err
	}
	if err := createExclusive(*out, []byte(b.String()), 0o644); err != nil {
		return writeErr(err)
	}
	fmt.Fprintf(s.out, "wrote %s (%d entries)\n", *out, len(entries))
	return nil
}

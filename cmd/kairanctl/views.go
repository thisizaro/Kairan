package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
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

// isNoPolicy reports a "no policy" period: the proxy booted deny-all and had
// no signed policy yet, so it reports version 0 and an empty hash.
func isNoPolicy(e wire.TimelineEntry) bool { return e.Version == 0 && e.PolicyHash == "" }

func checkTimeline(v wire.TimelineView, tenant string) *cliError {
	if string(v.Tenant) != tenant {
		return badAnswer()
	}
	for _, e := range v.Entries {
		// Version 0 with an empty hash is a proxy's deny-all boot (Q-D40,
		// M-D71); any other mix of version and hash is a bad answer.
		if !e.ProxyID.Valid() || !(isNoPolicy(e) || e.Version >= 1 && e.PolicyHash.Valid()) ||
			!validMs(e.FirstSeenUnixMs) || !validMs(e.LastSeenUnixMs) || e.LastSeenUnixMs < e.FirstSeenUnixMs ||
			(e.LogHead != "" && !e.LogHead.Valid()) {
			return badAnswer()
		}
	}
	return nil
}

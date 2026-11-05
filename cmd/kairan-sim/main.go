// Command kairan-sim runs N simulated proxies against a control plane: real HTTP
// long-polls and status reports with the timing constants from the wire package.
//
// The proxies are SIMULATED. Their IDs start with "sim-", the User-Agent says so,
// and the JSON result carries "simulated": true. They hold no trusted keys, verify
// no signatures and enforce nothing; they exist to load the control plane (M1, M7, S9).
// Only the wire package is imported.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"kairan/internal/wire"
)

func main() { os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr)) }

func marshalStatus(r wire.StatusReport) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	if len(b) > wire.MaxStatusBytes {
		return "", errors.New("status report too large")
	}
	return string(b), nil
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kairan-sim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cp := fs.String("cp", "", "control plane base URL, e.g. http://localhost:8080 (required)")
	n := fs.Int("n", 1000, "number of simulated proxies")
	tenant := fs.String("tenant", "sim", "tenant ID the simulated proxies belong to")
	pattern := fs.String("token-pattern", defaultPattern, "enrollment token; {n} becomes the zero-padded proxy number")
	duration := fs.Duration("duration", 0, "stop after this long (0 = until SIGINT/SIGTERM or -until-version)")
	ramp := fs.Duration("ramp", 0, "spread proxy start-up uniformly over this window")
	until := fs.Uint64("until-version", 0, "stop once every proxy has acked a version >= this (0 = off)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "kairan-sim: unexpected arguments")
		return 2
	}
	u, err := url.Parse(*cp)
	if err != nil {
		fmt.Fprintln(stderr, "kairan-sim: bad -cp URL")
		return 2
	}
	if *duration < 0 {
		fmt.Fprintln(stderr, "kairan-sim: -duration must not be negative")
		return 2
	}
	sim, err := New(Config{CP: u, Tenant: wire.ID(*tenant), N: *n, TokenPattern: *pattern, Ramp: *ramp, UntilVersion: *until})
	if err != nil {
		fmt.Fprintf(stderr, "kairan-sim: %v\n", err)
		return 2
	}

	fmt.Fprintf(stderr, "kairan-sim: SIMULATED proxies, not real kairan-proxy: n=%d ids=%s0000.. tenant=%s cp=%s\n",
		*n, IDPrefix, *tenant, u.Redacted())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	res := sim.Run(ctx)

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(stderr, "kairan-sim: write result: %v\n", err)
		return 1
	}
	return 0
}

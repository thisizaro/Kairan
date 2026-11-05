// Command kairanctl is the administrator's tool: it creates keys and policy
// payloads, signs them, and adds the second signature on the approver's own
// machine. Private keys never leave the machine that ran keygen. Only the
// commands from publish onward talk to the control plane, and they send
// signed envelopes and rollout requests, never a private key.
//
// Usage:
//
//	kairanctl keygen   -name NAME [-dir DIR]
//	kairanctl policy new -tenant ID [-version N] [-validity 72h] [-out FILE]
//	kairanctl sign     -key NAME.key -in payload.json -out envelope.json
//	kairanctl approve  -key NAME.key -in envelope.json [-out FILE] [-yes] [-trusted PUB,PUB,...]
//	kairanctl publish  CONN -in envelope.json
//	kairanctl rollout start    CONN -tenant ID -version N [-canary-dwell 10m]
//	kairanctl rollout status   CONN -tenant ID
//	kairanctl rollout rollback -from OLD -version N -out payload.json [-validity 72h]
//	                           [-key A.key -key2 B.key -env-out envelope.json]
//	kairanctl fleet    CONN -tenant ID
//	kairanctl evidence export CONN -tenant ID [-proxy ID] [-out FILE]
//
// CONN is: -url https://cp.example [-ca-file ca.pem] [-allow-plaintext]
// [-token-file FILE]. The admin token is read from the environment variable
// KCTL_ADMIN_TOKEN or from a file (-token-file, or KCTL_ADMIN_TOKEN_FILE),
// never from a flag, because flags show in the process list. The URL may
// also come from KCTL_CP_URL.
//
// Exit codes: 0 success, 1 the command was refused or failed, 2 bad usage.
// Errors are printed in English and Japanese (PRD J7).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// streams is everything a command touches besides the file system, so tests
// can drive run in-process. now is the only clock (policy new reads it).
type streams struct {
	in       io.Reader
	out, err io.Writer
	now      func() time.Time
	getenv   func(string) string // nil reads as an empty environment
}

func (s streams) env(key string) string {
	if s.getenv == nil {
		return ""
	}
	return s.getenv(key)
}

// Exit codes.
const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 2
	helpSummary = `kairanctl: Kairan administrator tool

  kairanctl keygen   -name NAME [-dir DIR]
  kairanctl policy new -tenant ID [-version N] [-validity 72h] [-out FILE]
  kairanctl sign     -key NAME.key -in payload.json -out envelope.json
  kairanctl approve  -key NAME.key -in envelope.json [-out FILE] [-yes] [-trusted PUB,PUB,...]
  kairanctl publish  CONN -in envelope.json
  kairanctl rollout start    CONN -tenant ID -version N [-canary-dwell 10m]
  kairanctl rollout status   CONN -tenant ID
  kairanctl rollout rollback -from OLD -version N -out payload.json [-validity 72h]
                             [-key A.key -key2 B.key -env-out envelope.json]
  kairanctl fleet    CONN -tenant ID
  kairanctl evidence export CONN -tenant ID [-proxy ID] [-out FILE]

  CONN: -url https://cp.example [-ca-file ca.pem] [-allow-plaintext] [-token-file FILE]
  The admin token comes from KCTL_ADMIN_TOKEN or a token file
  (-token-file or KCTL_ADMIN_TOKEN_FILE), never from a flag.
  The URL may come from KCTL_CP_URL.
`
)

func main() {
	os.Exit(run(os.Args[1:], streams{in: os.Stdin, out: os.Stdout, err: os.Stderr, now: time.Now, getenv: os.Getenv}))
}

// cliError is a failure with a message in both languages (J7). It never
// carries key material or payload text.
type cliError struct {
	en, ja string
	usage  bool  // exit 2 instead of 1
	cause  error // for errors.Is in tests; not printed
}

func (e *cliError) Error() string { return e.en }
func (e *cliError) Unwrap() error { return e.cause }

func fail(en, ja string) *cliError { return &cliError{en: en, ja: ja} }

func usageErr(en, ja string) *cliError { return &cliError{en: en, ja: ja, usage: true} }

func (e *cliError) because(err error) *cliError {
	c := *e
	c.cause = err
	return &c
}

// run dispatches one command line and returns the exit code.
func run(args []string, s streams) int {
	err := dispatch(args, s)
	if err == nil {
		return exitOK
	}
	var fe *flagExit
	if errors.As(err, &fe) {
		return fe.code
	}
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = fail("internal error", "内部エラー")
	}
	fmt.Fprintf(s.err, "error: %s\nエラー: %s\n", ce.en, ce.ja)
	if ce.usage {
		fmt.Fprint(s.err, "\n"+helpSummary)
		return exitUsage
	}
	return exitFailed
}

func dispatch(args []string, s streams) error {
	if len(args) == 0 {
		return usageErr("no command given", "コマンドが指定されていません")
	}
	rest := args[1:]
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(s.out, helpSummary)
		return nil
	case "keygen":
		return cmdKeygen(rest, s)
	case "policy":
		if len(rest) == 0 || rest[0] != "new" {
			return usageErr("unknown policy command (try: policy new)", "policy のサブコマンドが不明です (policy new を使います)")
		}
		return cmdPolicyNew(rest[1:], s)
	case "sign":
		return cmdSign(rest, s)
	case "approve":
		return cmdApprove(rest, s)
	case "publish":
		return cmdPublish(rest, s)
	case "rollout":
		return cmdRollout(rest, s)
	case "fleet":
		return cmdFleet(rest, s)
	case "evidence":
		return cmdEvidence(rest, s)
	}
	return usageErr("unknown command", "不明なコマンドです")
}

// flagExit carries an exit code chosen while parsing flags (-h is 0, a bad
// flag is 2); the flag package has already printed its message.
type flagExit struct{ code int }

func (e *flagExit) Error() string { return "flag exit" }

// parseFlags parses args into fs. Stray positional arguments are a usage error.
func parseFlags(fs *flag.FlagSet, args []string, s streams) error {
	fs.SetOutput(s.err)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &flagExit{exitOK}
		}
		return &flagExit{exitUsage}
	}
	if fs.NArg() != 0 {
		return usageErr("unexpected argument", "余分な引数があります")
	}
	return nil
}

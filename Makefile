SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := ci

# Go steps are skipped while the scaffold has no .go files.
HAVE_GO := $(shell find . -name '*.go' -not -path './.git/*' -print -quit 2>/dev/null)

.PHONY: ci test break hooks-test fuzz-smoke lint vet check-jsonl vulncheck e2e chaos bench demo k3d-demo plan log

ci: vet lint test fuzz-smoke check-jsonl hooks-test vulncheck
	@echo "make ci: ok"

vet:
ifneq ($(HAVE_GO),)
	go vet ./...
else
	@echo "vet: no Go files yet, skipped"
endif

lint:
ifneq ($(HAVE_GO),)
	@if command -v staticcheck >/dev/null; then staticcheck ./...; else echo "lint: staticcheck not installed, skipped"; fi
	@bad=$$(gofmt -l .); if [ -n "$$bad" ]; then echo "gofmt needed:"; echo "$$bad"; exit 1; fi
else
	@echo "lint: no Go files yet, skipped"
endif
	@if command -v shellcheck >/dev/null; then shellcheck -x scripts/*.sh .githooks/pre-commit .claude/hooks/*.sh; else echo "lint: shellcheck not installed, skipped"; fi

test:
ifneq ($(HAVE_GO),)
	go test -race ./...
else
	@echo "test: no Go files yet, skipped"
endif

# Break-pass attack tests (M-D17), written by lane Q against exported APIs. Also run by `test`.
# Break tests run binaries black-box; build them here when the source exists in this checkout (M-D48).
# Lane Q's sparse checkout has no cmd/ sources, so the Overseer runs `make break` on main or passes
# KAIRANCTL_SRC_DIR / FAKEMCP_BIN explicitly. Any skipped test fails `make break` (M-D52).
BREAK_BIN := $(CURDIR)/.break-bin
break:
	@mkdir -p $(BREAK_BIN); \
	if [ -d cmd/kairanctl ]; then go build -o $(BREAK_BIN)/kairanctl ./cmd/kairanctl && export KAIRANCTL_BIN=$(BREAK_BIN)/kairanctl; fi; \
	if [ -d cmd/fakemcp ]; then go build -o $(BREAK_BIN)/fakemcp ./cmd/fakemcp && export FAKEMCP_BIN=$(BREAK_BIN)/fakemcp; fi; \
	if ! find test/break -name '*_test.go' -print -quit 2>/dev/null | grep -q .; then echo "break: no break tests yet"; exit 0; fi; \
	rc=0; go test -race -count=1 -v ./test/break/... >$(BREAK_BIN)/break.log 2>&1 || rc=$$?; \
	grep -E '^(ok|FAIL)[[:space:]]' $(BREAK_BIN)/break.log || true; \
	if ((rc)); then grep -E -A6 -- '--- FAIL|^panic:' $(BREAK_BIN)/break.log | head -150; echo "break: FAIL (full log $(BREAK_BIN)/break.log)"; exit $$rc; fi; \
	if grep -E -- '--- SKIP' $(BREAK_BIN)/break.log; then echo "break: skipped tests are not allowed in make break (M-D52); set KAIRANCTL_BIN/FAKEMCP_BIN if a binary could not be built"; exit 1; fi; \
	echo "break: ok, 0 skips"

# Guard hooks and pre-commit, driven with synthetic tool calls.
hooks-test:
	@scripts/test-hooks.sh

# 5s per Fuzz target; every package with fuzz tests.
fuzz-smoke:
ifneq ($(HAVE_GO),)
	@for pkg in $$(go list ./... ); do \
	  for f in $$(go test -list '^Fuzz' "$$pkg" 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "fuzz $$pkg $$f"; go test -run '^$$' -fuzz "^$$f$$" -fuzztime 5s "$$pkg"; \
	  done; \
	done
else
	@echo "fuzz-smoke: no Go files yet, skipped"
endif

check-jsonl:
	@scripts/check-jsonl.sh

vulncheck:
ifneq ($(HAVE_GO),)
	@if command -v govulncheck >/dev/null; then govulncheck ./...; else echo "vulncheck: govulncheck not installed, skipped"; fi
else
	@echo "vulncheck: no Go files yet, skipped"
endif

e2e:
	@echo "not implemented yet (see PLAN Q-02)"
chaos:
	@echo "not implemented yet (see PLAN Q-02)"
bench:
	@echo "not implemented yet (see PLAN Q-06)"
demo:
	@echo "not implemented yet (see PLAN Q-01)"
k3d-demo:
	@echo "not implemented yet (see PLAN Q-08)"

plan:
	@scripts/plan.sh list

log:
	@scripts/log-decision.sh --help || true
	@echo
	@scripts/commit.sh --help || true

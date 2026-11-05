SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := ci

# Go steps are skipped while the scaffold has no .go files.
HAVE_GO := $(shell find . -name '*.go' -not -path './.git/*' -print -quit 2>/dev/null)

.PHONY: ci test fuzz-smoke lint vet check-jsonl vulncheck e2e chaos bench demo k3d-demo plan log

ci: vet lint test fuzz-smoke check-jsonl vulncheck
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

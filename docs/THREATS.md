# Kairan: Threats (STRIDE)

**Draft. Reviewed at Gate G0 by security-reviewer.** Source: design §4, §6.6, §10. Invariants I1-I6 are defined in `docs/PRD.md`. Scenario IDs S1-S11 are the chaos scenarios (design §10.3). `TODO` = no proof yet; each becomes a PLAN task or a decision before G2.

Assets: the policy in force on each proxy; the data inside the customer network (payloads, prompts, PII); signing keys; the apply log.
Trust: admins' machines and the proxy's local config are trusted; the control plane and the network are **not**.

| # | Threat | STRIDE | Mitigation | Proof |
|---|---|---|---|---|
| 1 | **Forged policy:** fake control plane or man-in-the-middle sends a policy | S, T | Proxy accepts only an envelope with 2 valid ed25519 signatures from 2 distinct trusted keys over the exact bytes; tenant, version and expiry checked; trust root only in local config | I1; S5 (unsigned, 1-sig, wrong tenant, corrupted); unit + fuzz in `trust` (T-03, T-04) |
| 2 | **Compromised control plane:** attacker owns kairan-cp | S, T, D | CP can distribute but not create valid policy; proxies verify independently; CP cannot change keys or threshold; on CP loss proxies stay fail-static | I1, I3; S2, S5; M5, M6. TODO: a lying CP can hide drift in the fleet view. Proposal: M-D7 (proxy self view + kairanctl cross-check) |
| 3 | **Rollback replay:** old valid policy re-sent to widen permissions | T, E | Version must be greater than the applied one; rollback is a new higher version | I2; S5 (old version); unit table in `trust` Accept |
| 4 | **Freeze / expiry:** attacker blocks updates so a stale policy lingers | D, E | Expiry (default 72h) triggers read-only safe mode; fleet page and metrics show it | I3; S7 |
| 5 | **Tampered disk file:** policy or apply log edited by hand | T, R | Policy re-verified at load: failure means deny-all and a tamper report; apply log is hash-chained; writes are temp+fsync+rename | I3, I6; S6; unit in `proxy/store`, `proxy/applylog`. TODO: attacker with disk write plus config write can replace trusted keys (document in LIMITATIONS) |
| 6 | **Spoofed proxy status:** someone posts false "applied vN" for a proxy | S, R | Demo: per-proxy enrollment token on status/poll. Production: mTLS client cert. Strict schema | TODO: test that an unauthenticated or wrong-token status is rejected (C-04). Proposal: M-D9 |
| 7 | **Payload / PII leak to the control plane** | I | `wire` types carry metadata only; strict decoding rejects unknown fields; logs and metrics carry no call data; user IDs only HMAC'd | I4; S10; M8 (0 canary hits). Status path covered: `TestStatusReportCannotCarryPayload` in internal/wire (M-D3, mutation-checked) |
| 8 | **Slow-client and huge-body DoS** on the CP or proxy | D | `http.Server` Read/ReadHeader/Write/Idle timeouts; `http.MaxBytesReader` on every body; bounded concurrent long-polls | TODO: tests for slow headers, oversize body (413), connection cap (C-04, P-02). Proposal: M-D9; M7 for load |
| 9 | **Stolen API keys** (agent role keys, admin token) | S, E | Demo keys map to one role each so blast radius is that role; constant-time compare; rotate by config; production: OIDC + mTLS | TODO: key-compare uses `crypto/subtle` (G2 checklist); LIMITATIONS: demo auth is weak by design |
| 10 | **Leaked signing keys** | S, T | Private keys live only on admins' machines; 2-of-N means one leaked key cannot publish; `.gitignore` covers `*.key`, `keys/`, `.env`; test keys only as `TEST-ONLY-*` in `test/fixtures/` | I1; G2 repo secret scan. TODO: key revocation/rotation distribution is described for production, not built |
| 11 | **Agent exceeds its role** (calls a tool its role may not use) | E | Default deny; `tools/list` hides tools; `tools/call` re-checks; safe mode blocks W/X | I3, I5; unit table in `policy` matcher and `proxy/enforce` |
| 12 | **Proxy clock manipulation** to defeat expiry | T | Expiry uses the proxy's clock with small skew tolerance | TODO: proposal M-D8 (monotonic bound + highest-seen wall time); document the root-attacker limit in LIMITATIONS |

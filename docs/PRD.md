# Kairan (回覧): Product Requirements

Source: `docs/superpowers/specs/2026-11-05-kairan-design.md` (approved 2026-11-05). If this file and the source disagree, stop and file an `incident`.
Independent project; not affiliated with RAYVEN. Anything about Tumiki comes from public pages and is marked *(assumption)* where guessed.

## 1. Problem
A customer-side **proxy** checks every AI-agent tool call against the customer's **policy**; a **control plane** sends policies to many proxies in many networks. An operator must answer at any time:

| # | Operator question |
|---|---|
| Q1 | **Alive?** Which proxies run, which went silent? |
| Q2 | **Which rules?** Which policy version is each proxy enforcing right now? |
| Q3 | **Did it arrive?** Has every proxy applied the change I just made? |
| Q4 | **Cloud down?** Do proxies keep protecting correctly, or fail open? |
| Q5 | **Tampering?** Is a hand-edited file or a fake control plane accepted? |
| Q6 | **Proof later?** Which rules were in force on proxy P at time T? |

## 2. Users
| User | Needs |
|---|---|
| RAYVEN operator | Fleet view, safe rollouts, rollback, alerts on lost/drift/safe mode |
| Customer security admin | Sign and approve policy (2 people); evidence of what was enforced |
| Auditor | Time-stamped, tamper-evident proof of policy versions (JST + UTC) |

## 3. Goals
| ID | Goal |
|---|---|
| G1 | Signed policy distribution; 2 signatures from 2 different people (four-eyes) |
| G2 | Live fleet view: healthy/stale/lost, desired vs applied version, last error |
| G3 | Safe when disconnected: fail-static, never widen permissions |
| G4 | Rollback and freeze protection: version never decreases; notice when nothing new arrives for too long |
| G5 | Careful rollouts: canary, then all; auto-halt on errors; one-step rollback |
| G6 | Evidence trail: every decision records policy version; tamper-evident apply history |
| G7 | Data stays inside: only metadata reaches the control plane, proven by a test |
| G8 | Real numbers: reproducible with one command |

## 4. Non-goals
No Tumiki clone (no PII masking, virtual-MCP builder, connectors). Not a full MCP implementation: only `tools/list` and `tools/call` are understood, the rest passes through. No OIDC in the demo. No multi-region control plane, billing, or large UI (one fleet page). No use of RAYVEN private code.

## 5. Anti-goals (failure even if it "works")
1. Any payload, prompt or personal data reaching the control plane.
2. Fail-open behavior: a failure that widens permissions.
3. Fake or cherry-picked numbers; simulated proxies not labeled as simulated.
4. A heavy dependency tree (stdlib first).
5. A critical tone: respectful proposal, not a bug report.

## 6. Japan-first requirements
| ID | Requirement |
|---|---|
| J1 | Heartbeats/acks carry only versions, hashes, health, counters. User IDs, if any, are HMAC'd. A canary-secret test proves no leak. |
| J2 | Proxies make **outbound HTTPS only**; HTTP/1.1 long-poll; honor `HTTPS_PROXY`. No inbound ports. |
| J3 | **Offline mode:** a signed bundle can be imported from a file and passes the same signature, version and expiry checks. |
| J4 | **2-of-N signatures**; approver signs on their own machine; the control plane distributes but cannot create a valid policy. |
| J5 | Local **hash-chained apply log**; each decision stamped with policy version + hash; export shows "proxy P enforced version V (hash H) from T1 to T2" in JST + UTC. |
| J6 | Canary rollout, optional rollout windows (e.g. after 19:00 JST), auto-halt, rollback by re-publishing old content as a new higher version. |
| J7 | README and fleet page in Japanese and English; errors readable in both. |

## 7. Functional requirements
| Area | Requirement |
|---|---|
| Policy | JSON: `tenant`, `version` (integer, only grows), `issued_at`, `expires_at` (default 72h), `default: deny`, `roles` -> tools with R/W/X; wildcards like `slack.*` |
| Envelope | Exact policy bytes + signatures (DSSE idea); sign bytes, never re-encoded JSON |
| Accept | >= 2 valid signatures from 2 distinct trusted keys; tenant matches; version > current; not expired (small skew allowed); strict format. Otherwise keep current policy and report the reason. |
| Trust root | Tenant, trusted public keys and threshold come from the proxy's **local config**, never from the control plane |
| Enforcement | `tools/list` hides tools the role cannot use; `tools/call` forwards if allowed, else MCP tool error "blocked by policy vN"; local log per decision; role from static API key (demo) |
| Sync | Long-poll "newer than vN?"; ~30s timeout; verify, persist (temp, fsync, rename), atomic swap, ack |
| Health | Status ~every 10s; control plane marks healthy / stale (30s) / lost (2m), configurable |
| Rollout | Canary group first, then all; halt on canary apply error or loss; rollback = re-publish |
| Failure modes | See ARCHITECTURE.md "Failure behavior" table |
| Metrics | Hand-written Prometheus text on control plane and proxies |

## 8. Invariants (must-pass: each needs tests)
| ID | Invariant |
|---|---|
| I1 | A proxy never enforces a policy without 2 valid signatures from 2 distinct trusted keys |
| I2 | A proxy's applied version never goes down |
| I3 | No failure (control plane down, network cut, bad policy, disk error) ever makes permissions wider |
| I4 | No payload, prompt or canary secret ever reaches the control plane |
| I5 | Every allow/deny decision is recorded with the exact policy version and hash that made it |
| I6 | The apply log's hash chain detects any edit, deletion or reordering |

## 9. Metrics (all produced by `make bench` into RESULTS.md: commit, machine, >= 5 runs, median and spread; real and simulated labeled separately)
| # | Metric | Measured by | Target |
|---|---|---|---|
| M1 | Propagation time p50/p95/p99 | publish timestamp vs each ack; 10 real (Docker), 100 / 1,000 simulated | TODO(Phase 0): numeric target (design says hypotheses, report honestly). Proposal: M-D6 |
| M2 | Dead-proxy detection time | kill a container, time to stale/lost | TODO(Phase 0): numeric target. Proposal: M-D6 |
| M3 | Catch-up after network cut | disconnect, publish, reconnect, time to ack | TODO(Phase 0): numeric target. Proposal: M-D6 |
| M4 | Enforcement overhead | Go benchmarks (ns, allocs) and e2e latency with/without proxy | TODO(Phase 0): numeric target. Proposal: M-D6 |
| M5 | Outage correctness | thousands of mixed calls during control-plane outage | **0 wrongly allowed** |
| M6 | Bad-policy rejection | unsigned, 1 sig, old version, wrong tenant, expired, corrupted | **0 applied** |
| M7 | Control-plane cost | memory, CPU, connections per 1,000 watching proxies (kairan-sim) | TODO(Phase 0): numeric target. Proposal: M-D6 |
| M8 | Data leakage | canary secrets seen in captured control-plane traffic | **0 hits** |

## 10. Acceptance criteria (definition of done)
1. Invariants I1-I6 each have passing tests (unit, fuzz where applicable, `-race`).
2. Chaos S1-S10 pass automatically (see ARCHITECTURE.md / design §10.3); S11 (k3d) is a stretch.
3. `make ci` green on main: vet, staticcheck, `test -race`, fuzz smoke, JSONL checks, govulncheck.
4. RESULTS.md generated from a clean checkout by `make bench`; M5, M6, M8 meet their targets; other results reported honestly.
5. Go stdlib only, unless a decision entry justifies an addition.
6. README in Japanese and English; LIMITATIONS.md; a 3-minute video from the real demo.
7. Security review at G0 (THREATS.md) and G2 (code) done, findings triaged.

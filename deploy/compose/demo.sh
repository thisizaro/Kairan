#!/usr/bin/env bash
# Kairan compose demo (Q-01). Local only; the only images pulled are the pinned ones in Dockerfile and
# compose.yaml. Keys, tokens and configs are generated here at run time into deploy/compose/.run (gitignored).
#
#   demo.sh [demo]   build, start the stack, sign + approve (2 signatures) + publish + canary rollout,
#                    wait until all 10 proxies ack, print the fleet view. Leaves the stack running.
#   demo.sh up       fresh stack with no policy published (used by test/e2e)
#   demo.sh fleet    print the fleet view of both tenants
#   demo.sh down     stop the stack, delete its volumes and the generated secrets
#
# Environment: DEMO_SRC = build context (default: the repository root), ACK_TIMEOUT (seconds, default 120).
# Exit status is non-zero on any failure, and the failing step is named in English and Japanese.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/.run"
SRC="${DEMO_SRC:-$(git -C "$HERE" rev-parse --show-toplevel)}"
ACK_TIMEOUT="${ACK_TIMEOUT:-120}"
CP_HOST_URL="http://127.0.0.1:18080"
export COMPOSE_PROJECT_NAME=kairan-demo

# id tenant group
PROXIES=(
  "bank-a-canary bank-a canary"
  "bank-a-main-1 bank-a main" "bank-a-main-2 bank-a main" "bank-a-main-3 bank-a main"
  "bank-a-main-4 bank-a main" "bank-a-main-5 bank-a main"
  "city-b-canary city-b canary"
  "city-b-main-1 city-b main" "city-b-main-2 city-b main" "city-b-main-3 city-b main"
)
TENANTS=(bank-a city-b)

dc() { docker compose -f "$HERE/compose.yaml" "$@"; }
say() { printf '== %s\n' "$*"; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
now_s() { date +%s; }

fail() {
  printf 'FAILED: %s\n失敗: %s\n' "$1" "${2:-$1}" >&2
  exit 1
}

# kairanctl in a container, as the host user, with ./.run mounted at /work and the CP on the "cloud" network.
ctl() {
  COMPOSE_PROGRESS=quiet dc run --rm --no-deps -T --user "$(id -u):$(id -g)" ctl "$@"
}

build() {
  say "build image kairan:demo from $SRC"
  docker build -q -f "$HERE/Dockerfile" -t kairan:demo "$SRC" >/dev/null || fail "image build" "イメージのビルド"
}

prepare() {
  say "generate TEST-ONLY keys, tokens and configs in $RUN (gitignored)"
  rm -rf "$RUN"
  mkdir -p "$RUN/keys" "$RUN/proxies" "$RUN/work"
  chmod 755 "$RUN" "$RUN/proxies" "$RUN/work" "$RUN/keys"
  for k in admin-a admin-b admin-c; do
    docker run --rm --user "$(id -u):$(id -g)" -v "$RUN/keys:/keys" kairan:demo \
      kairanctl keygen -name "$k" -dir /keys >/dev/null || fail "keygen $k" "鍵の生成 $k"
  done
  rnd 24 >"$RUN/admin.token"
  printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$(rnd 12)" >"$RUN/grafana.env"
  printf '%s\n' "demo-key-sales-$(rnd 8)" >"$RUN/agent-key-sales"
  printf '%s\n' "demo-key-intern-$(rnd 8)" >"$RUN/agent-key-intern"
  # kairan-cp refuses a token file that others can read, and a 0600 file owned by the host user is not
  # readable by the container user, so the CP gets the token as KCP_ADMIN_TOKEN (documented) via cp.env.
  chmod 600 "$RUN/admin.token"
  printf 'KCP_ADMIN_TOKEN=%s\n' "$(cat "$RUN/admin.token")" >"$RUN/cp.env"
  chmod 644 "$RUN"/grafana.env "$RUN"/cp.env "$RUN"/agent-key-*

  local pubs
  pubs="$(jq -cn --arg a "$(tr -d '\n' <"$RUN/keys/admin-a.pub")" --arg b "$(tr -d '\n' <"$RUN/keys/admin-b.pub")" \
    --arg c "$(tr -d '\n' <"$RUN/keys/admin-c.pub")" '[$a,$b,$c]')"
  echo "$pubs" >"$RUN/trusted-keys.json"

  local enroll='[]' entry id tenant group tok
  for entry in "${PROXIES[@]}"; do
    read -r id tenant group <<<"$entry"
    tok="tok-$id-$(rnd 16)"
    printf '%s\n' "$tok" >"$RUN/proxies/$id.token"
    enroll="$(jq -c --arg id "$id" --arg t "$tenant" --arg g "$group" \
      --arg h "$(printf '%s' "$tok" | sha256sum | cut -d' ' -f1)" \
      '. + [{proxy_id:$id, tenant:$t, group:$g, token_sha256:$h}]' <<<"$enroll")"
    jq -n --arg tenant "$tenant" --arg id "$id" --arg tok "$tok" --argjson pubs "$pubs" \
      --arg up "http://fakemcp-$tenant:9000" \
      --arg sales "$(cat "$RUN/agent-key-sales")" --arg intern "$(cat "$RUN/agent-key-intern")" \
      '{tenant:$tenant, proxy_id:$id, cp_url:"http://cp:8080", token:$tok, trusted_keys:$pubs, threshold:2,
        listen:"0.0.0.0:8080", metrics_listen:"0.0.0.0:9090", upstream:$up,
        api_keys:{($sales):"sales", ($intern):"intern"}, data_dir:"/data", allow_plaintext:true}' \
      >"$RUN/proxies/$id.json"
    chmod 644 "$RUN/proxies/$id.json"
    chmod 600 "$RUN/proxies/$id.token"
  done
  jq -n --argjson pubs "$pubs" --argjson enroll "$enroll" \
    '{listen:"0.0.0.0:8080", metrics_listen:"0.0.0.0:9100", data_dir:"/data", allow_plaintext:true,
      log_level:"info", canary_dwell_seconds:5,
      tenants:{"bank-a":{threshold:2, admin_keys:$pubs}, "city-b":{threshold:2, admin_keys:$pubs}},
      enrollments:$enroll}' >"$RUN/cp.json"
  chmod 644 "$RUN/cp.json"
}

up() {
  say "start the stack (10 proxies, 2 tenants, fakemcp, kairan-cp, Prometheus, Grafana)"
  dc up -d --wait --wait-timeout 120 || fail "stack start" "スタックの起動"
}

# compose parses env_file even for "down", so make sure the files exist first.
teardown() {
  mkdir -p "$RUN"
  [ -e "$RUN/grafana.env" ] || : >"$RUN/grafana.env"
  [ -e "$RUN/cp.env" ] || : >"$RUN/cp.env"
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}

fresh() {
  teardown
  build
  prepare
  up
}

admin_get() { curl -fsS -H "Authorization: Bearer $(cat "$RUN/admin.token")" "$CP_HOST_URL$1"; }

# policy_payload TENANT VERSION: the exact policy bytes (ARCHITECTURE 10.0). v1 = read-only for sales; v2+ adds notes.write.
policy_payload() {
  local tenant="$1" version="$2" issued expires extra=""
  issued="$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)"
  expires="$(date -u -d '+72 hours' +%Y-%m-%dT%H:%M:%SZ)"
  if ((version >= 2)); then extra=',"notes.write":"W"'; fi
  printf '{"tenant":"%s","version":%d,"issued_at":"%s","expires_at":"%s","default":"deny","roles":{"sales":{"notes.read":"R","crm.read_*":"R"%s},"intern":{"notes.read":"R"}}}' \
    "$tenant" "$version" "$issued" "$expires" "$extra"
}

# publish_policy TENANT VERSION: sign with admin-a, approve with admin-b (2 signatures), publish.
publish_policy() {
  local tenant="$1" version="$2" base="work/$1-v$2" trusted
  trusted="$(jq -r 'join(",")' "$RUN/trusted-keys.json")"
  policy_payload "$tenant" "$version" >"$RUN/$base.json"
  say "$tenant v$version: sign (admin-a), approve (admin-b), publish"
  ctl sign -key /work/keys/admin-a.key -in "/work/$base.json" -out "/work/$base.signed1.json" >/dev/null ||
    fail "sign $tenant v$version" "署名 $tenant v$version"
  ctl approve -key /work/keys/admin-b.key -in "/work/$base.signed1.json" -out "/work/$base.signed2.json" -yes \
    -trusted "$trusted" >/dev/null || fail "approve $tenant v$version" "承認 $tenant v$version"
  ctl publish -allow-plaintext -in "/work/$base.signed2.json" || fail "publish $tenant v$version" "公開 $tenant v$version"
}

start_rollout() {
  local tenant="$1" version="$2"
  say "$tenant v$version: start canary rollout"
  ctl rollout start -allow-plaintext -tenant "$tenant" -version "$version" || fail "rollout start $tenant" "ロールアウト開始 $tenant"
}

# wait_acks VERSION: every proxy of both tenants reports applied_version == VERSION, drift 0.
wait_acks() {
  local version="$1" t0 deadline total ok tenant
  t0="$(now_s)"
  deadline=$((t0 + ACK_TIMEOUT))
  say "wait until all ${#PROXIES[@]} proxies ack v$version (timeout ${ACK_TIMEOUT}s)"
  while :; do
    total=0
    for tenant in "${TENANTS[@]}"; do
      ok="$(admin_get "/v1/fleet?tenant=$tenant" |
        jq --argjson v "$version" '[.proxies[] | select(.applied_version == $v and .drift == 0 and .health == "healthy")] | length' 2>/dev/null || echo 0)"
      total=$((total + ok))
    done
    if ((total == ${#PROXIES[@]})); then
      echo "all ${#PROXIES[@]} proxies acked v$version after $(($(now_s) - t0))s"
      return 0
    fi
    if (($(now_s) > deadline)); then
      echo "only $total of ${#PROXIES[@]} proxies acked v$version" >&2
      fleet || true
      fail "not all proxies acked v$version within ${ACK_TIMEOUT}s" "${ACK_TIMEOUT}秒以内に全プロキシが v$version を確認しませんでした"
    fi
    sleep 1
  done
}

fleet() {
  local tenant
  for tenant in "${TENANTS[@]}"; do
    say "fleet view: $tenant"
    ctl fleet -allow-plaintext -tenant "$tenant"
    ctl rollout status -allow-plaintext -tenant "$tenant" || true
  done
}

diagnose() {
  echo "--- docker compose ps ---" >&2
  dc ps -a >&2 || true
  echo "--- kairan-cp log (tail) ---" >&2
  dc logs --tail 30 cp >&2 || true
}

demo() {
  local t0 t
  t0="$(now_s)"
  trap 'rc=$?; if ((rc)); then diagnose; fi' EXIT
  fresh
  for t in "${TENANTS[@]}"; do
    publish_policy "$t" 1
    start_rollout "$t" 1
  done
  wait_acks 1
  fleet
  echo
  echo "demo ok in $(($(now_s) - t0))s: 10 of 10 proxies on v1. These are 10 real kairan-proxy containers, none simulated."
  echo "デモ成功: 実プロキシ 10 台すべてが v1 を適用 (シミュレーションではありません)"
  echo "fleet page:  $CP_HOST_URL/?tenant=bank-a   Prometheus: http://127.0.0.1:19090   Grafana: http://127.0.0.1:13000"
  echo "stop with: deploy/compose/demo.sh down"
}

down() {
  say "stop the stack and delete volumes and generated secrets"
  teardown
  rm -rf "$RUN"
}

case "${1:-demo}" in
  demo) demo ;;
  up) fresh ;;
  fleet) fleet ;;
  down) down ;;
  *) echo "usage: demo.sh [demo|up|fleet|down]" >&2; exit 2 ;;
esac

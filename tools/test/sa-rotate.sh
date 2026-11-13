#!/bin/bash
# Service-account key rotation with an overlap (#177): tokens issued before `kr pki rotate
# --service-account-key` keep verifying while pki/sa-old.pem exists, new tokens use the new key.
#   tools/test/sa-rotate.sh [path/to/kr]     (rootless; needs kubectl and curl; uses port 17450)
set -euo pipefail
KR=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/kr}
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
A=$W/a
k() { KUBECONFIG=$A/server/admin.kubeconfig kubectl "$@"; }
wait_api() { for _ in $(seq 60); do k get --raw /healthz >/dev/null 2>&1 && return 0; sleep 1; done; echo "API not up"; exit 1; }
start() { KR_ROOT=$A $KR server --port 17450 >"$W/s.log" 2>&1 & P=$!; wait_api; }
stop() { kill "$P"; wait "$P" 2>/dev/null || true; sleep 1; }
# Who a bearer token is (a user entry without a client certificate, so the token decides).
who() {
  cp "$A/server/admin.kubeconfig" "$W/tok.kubeconfig"
  KUBECONFIG=$W/tok.kubeconfig kubectl config set-credentials tokuser --token="$1" >/dev/null
  KUBECONFIG=$W/tok.kubeconfig kubectl --user=tokuser auth whoami 2>/dev/null | awk '$1=="Username"{print $2}' | grep . || echo rejected
}
start
k create rolebinding -n default x --clusterrole=view --serviceaccount=default:default >/dev/null
OLD=$(k create token default --duration=1h)
[ "$(who "$OLD")" = "system:serviceaccount:default:default" ] || { echo "FAIL the token before rotation"; exit 1; }
stop
KR_ROOT=$A $KR pki rotate --service-account-key >/dev/null
[ -f "$A/server/pki/sa-old.pem" ] && [ "$(stat -c %a "$A/server/pki/sa-old.pem")" = 600 ] || { echo "FAIL sa-old.pem"; exit 1; }
start
[ "$(who "$OLD")" = "system:serviceaccount:default:default" ] && echo "ok   an old token still verifies after the rotation"
NEW=$(k create token default --duration=1h)
[ "$(who "$NEW")" = "system:serviceaccount:default:default" ] && echo "ok   a new token works"
[ "$OLD" != "$NEW" ] && [ "$(echo "$OLD" | cut -d. -f1)" != "$(echo "$NEW" | cut -d. -f1)" ] && echo "ok   the new token names another key (kid)"
stop
rm "$A/server/pki/sa-old.pem"
start
[ "$(who "$OLD")" = rejected ] && echo "ok   without sa-old.pem the old token is refused"
[ "$(who "$NEW")" = "system:serviceaccount:default:default" ] && echo "ok   the new token still works"

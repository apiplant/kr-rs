#!/bin/bash
# Cluster CA rotation (#156): prepare, activate, finish on a rootless single server.
#   tools/test/ca-rotate.sh [path/to/kr]     (needs kubectl, openssl; uses port 17451)
set -uo pipefail
KR=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/kr}
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
A=$W/a; P=$A/server/pki; fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2], want [$3]"; fail=1; fi; }
works() { KUBECONFIG=$1 kubectl get ns >/dev/null 2>&1 && echo yes || echo no; }
wait_api() { for _ in $(seq 60); do KUBECONFIG=$A/server/admin.kubeconfig kubectl get --raw /healthz >/dev/null 2>&1 && return 0; sleep 1; done; echo "API not up"; cat "$W/s.log"; exit 1; }
start() { KR_ROOT=$A $KR server --port 17451 >"$W/s.log" 2>&1 & P1=$!; wait_api; }
stop() { kill "$P1"; wait "$P1" 2>/dev/null || true; sleep 1; }
ncerts() { grep -c "BEGIN CERTIFICATE" "$1"; }
start
cp "$A/server/admin.kubeconfig" "$W/old.kubeconfig"
OLDHASH=$(openssl x509 -in "$P/ca.pem" -outform DER | sha256sum | cut -d' ' -f1)
check "node-token pins the old CA" "$(cut -c4-67 "$A/server/node-token")" "$OLDHASH"
stop
KR_ROOT=$A $KR pki rotate --ca prepare >/dev/null || fail=1
check "prepare: ca.pem holds two CAs" "$(ncerts "$P/ca.pem")" 2
start
check "prepare: the old kubeconfig still works" "$(works "$W/old.kubeconfig")" yes
# What a client gets by copying the bundle: the old client certificate, trust in both CAs.
cp "$W/old.kubeconfig" "$W/mid.kubeconfig"
KUBECONFIG=$W/mid.kubeconfig kubectl config set-cluster kr --embed-certs --certificate-authority="$P/ca.pem" >/dev/null
check "prepare: a kubeconfig with the bundle works" "$(works "$W/mid.kubeconfig")" yes
stop
KR_ROOT=$A $KR pki rotate --ca activate >/dev/null || fail=1
NEWHASH=$(openssl x509 -in "$P/ca.pem" -outform DER | sha256sum | cut -d' ' -f1)
check "activate: the first CA is new" "$([ "$NEWHASH" != "$OLDHASH" ] && echo yes)" yes
check "activate: node-token pins the new CA" "$(cut -c4-67 "$A/server/node-token")" "$NEWHASH"
start
check "activate: the new admin kubeconfig works" "$(works "$A/server/admin.kubeconfig")" yes
check "activate: the old client certificate is still accepted with the bundle" "$(works "$W/mid.kubeconfig")" yes
check "activate: a client that only trusts the old CA no longer verifies the server" "$(works "$W/old.kubeconfig")" no
stop
KR_ROOT=$A $KR pki rotate --ca finish >/dev/null 2>&1 && { echo "FAIL finish without --yes"; fail=1; }
KR_ROOT=$A $KR pki rotate --ca finish --yes >/dev/null || fail=1
check "finish: only the new CA remains" "$(ncerts "$P/ca.pem")" 1
start
check "finish: the new admin kubeconfig works" "$(works "$A/server/admin.kubeconfig")" yes
check "finish: the old client certificate is refused" "$(works "$W/mid.kubeconfig")" no
exit $fail

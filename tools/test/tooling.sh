#!/bin/bash
# Rootless end-to-end test of ADR-043: manifest auto-deploy, scheduled and manual snapshots,
# restore (single server and into a new one-member HA cluster), certificate rotation.
#   tools/test/tooling.sh [path/to/kr]     (needs kubectl and tar; uses ports 17443-17445)
set -euo pipefail
KR=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/kr}
W=${KEEP_DIR:-$(mktemp -d)}; trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP_DIR:-}" ] || rm -rf "$W"' EXIT
k() { KUBECONFIG=$1/server/admin.kubeconfig kubectl "${@:2}"; }
wait_api() { for _ in $(seq 60); do k "$1" get --raw /healthz >/dev/null 2>&1 && return 0; sleep 1; done; echo "API not up"; exit 1; }
stop() { kill "$1"; wait "$1" 2>/dev/null || true; sleep 1; }

A=$W/a; mkdir -p "$A/server/manifests"
printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: auto\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hello\n  namespace: auto\ndata:\n  a: b\n' > "$A/server/manifests/00.yaml"
KR_ROOT=$A $KR server --port 17443 --snapshot-interval 3s --snapshot-keep 2 >"$W/a.log" 2>&1 & P=$!
wait_api "$A"
for _ in $(seq 30); do k "$A" -n auto get cm hello >/dev/null 2>&1 && break; sleep 1; done
[ "$(k "$A" -n auto get cm hello -o jsonpath='{.metadata.annotations.kr\.io/manifest-file}')" = 00.yaml ] || { echo "FAIL manifest annotation"; exit 1; }
sleep 8; [ "$(ls "$A/server/snapshots" | wc -l)" = 2 ] || { echo "FAIL scheduled snapshots keep=2"; exit 1; }
KR_ROOT=$A $KR snapshot save "$W/s.tar"
[ "$(stat -c %a "$W/s.tar")" = 600 ] || { echo "FAIL mode"; exit 1; }
tar tf "$W/s.tar" | grep -q pki/ca.key
if KR_ROOT=$A $KR snapshot restore "$W/s.tar" 2>/dev/null; then echo "FAIL restore over a running server"; exit 1; fi
stop $P
if KR_ROOT=$A $KR snapshot restore "$W/s.tar" 2>/dev/null; then echo "FAIL restore without --force"; exit 1; fi
B=$W/b; KR_ROOT=$B $KR snapshot restore "$W/s.tar"
KR_ROOT=$B $KR server --port 17444 >"$W/b.log" 2>&1 & P=$!
wait_api "$B"; k "$B" -n auto get cm hello >/dev/null
stop $P
KR_ROOT=$B $KR pki rotate
KR_ROOT=$B $KR server --port 17444 >"$W/b.log" 2>&1 & P=$!
wait_api "$B"
k "$B" -n auto create cm later --from-literal=x=y
stop $P
KR_ROOT=$B $KR server --port 17444 --cluster-init >"$W/b2.log" 2>&1 & P=$!
wait_api "$B"; k "$B" -n auto create cm ha --from-literal=x=y
KR_ROOT=$B $KR snapshot save "$W/ha.tar"; stop $P
C=$W/c; KR_ROOT=$C $KR snapshot restore "$W/ha.tar"
KR_ROOT=$C $KR server --port 17445 --cluster-init >"$W/c.log" 2>&1 & P=$!
wait_api "$C"
for c in hello later ha; do k "$C" -n auto get cm $c >/dev/null || { echo "FAIL missing $c after HA restore"; exit 1; }; done
echo "tooling: ok"

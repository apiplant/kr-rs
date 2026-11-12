#!/usr/bin/env bash
# `kubectl exec` and exec probes run as the container's own user and with its capabilities, not
# as root with the default set. Rootless `kr server`; needs kubectl, systemd --user and network for
# the alpine image:  KR=target/release/kr tools/test/exec-identity.sh
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16446}
trap 'systemctl --user stop kr-execid-test.scope >/dev/null 2>&1; systemctl --user reset-failed kr-execid-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-execid-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
kubectl apply -f - >/dev/null <<'Y'
apiVersion: v1
kind: Pod
metadata: {name: locked}
spec:
  securityContext: {runAsUser: 1234, runAsGroup: 4321, supplementalGroups: [77]}
  containers:
  - name: c
    image: docker.io/library/alpine:3.20
    command: [sleep, "3600"]
    securityContext: {capabilities: {drop: [ALL]}, allowPrivilegeEscalation: false}
Y
kubectl wait --for=condition=Ready pod/locked --timeout=120s >/dev/null
check "exec uid:gid" "$(kubectl exec locked -- id -u):$(kubectl exec locked -- id -g)" "1234:4321"
check "exec supplementary group" "$(kubectl exec locked -- id -G | tr ' ' '\n' | grep -c '^77$')" "1"
check "exec has no capabilities" "$(kubectl exec locked -- grep CapEff /proc/self/status | awk '{print $2}')" "0000000000000000"
check "main process has no capabilities" "$(kubectl exec locked -- grep CapEff /proc/1/status | awk '{print $2}')" "0000000000000000"
exit $fail

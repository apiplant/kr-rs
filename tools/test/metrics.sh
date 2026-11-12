#!/usr/bin/env bash
# Metrics API (ADR-048): `kubectl top node|pod` and metrics.k8s.io from the kubelet's
# /metrics/resource, on a rootless `kr server` in a delegated cgroup (systemd-run --user).
# Needs kubectl, systemd --user, network for the alpine image, and a built kr:
#   KR=target/debug/kr tools/test/metrics.sh
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16443}
trap 'systemctl --user stop kr-metrics-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-metrics-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
kubectl run burn --image=docker.io/library/alpine:3.20 --command -- sh -c 'while true; do :; done' >/dev/null
for _ in $(seq 60); do kubectl get pod burn --no-headers 2>/dev/null | grep -q Running && break; sleep 2; done
# CPU usage is a rate: it needs two 15 s scrapes.
for _ in $(seq 60); do kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/default/pods/burn >/dev/null 2>&1 && break; sleep 2; done
cpu=$(kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/default/pods/burn | sed -n 's/.*"cpu":"\([0-9]*\)n".*/\1/p')
check "pod cpu above 0.5 core (busy loop)" "$([ "${cpu:-0}" -gt 500000000 ] && echo yes)" yes
check "kubectl top node" "$(kubectl top node --no-headers | wc -l)" 1
check "kubectl top pod" "$(kubectl top pod --no-headers | awk '{print $1}')" burn
check "label selector miss" "$(kubectl top pod -l run=nope --no-headers 2>&1 | grep -c 'No resources')" 1
kubectl top node; kubectl top pod
exit $fail

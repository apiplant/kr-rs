#!/usr/bin/env bash
# HorizontalPodAutoscaler end to end on a rootless `kr server` (needs kubectl, systemd --user,
# network for the alpine image, a built kr):  KR=target/release/kr tools/test/hpa.sh
# A busy-loop Deployment (request 100m, ~1 core used) with an HPA of 50% scales up by itself;
# `kubectl get hpa` shows the metrics; deleting the load is not tested (the scale-down window is 5 min).
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16444}
trap 'systemctl --user stop kr-hpa-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-hpa-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
kubectl apply -f - >/dev/null <<'Y'
apiVersion: apps/v1
kind: Deployment
metadata: {name: burn}
spec:
  replicas: 1
  selector: {matchLabels: {app: burn}}
  template:
    metadata: {labels: {app: burn}}
    spec:
      containers:
      - name: c
        image: docker.io/library/alpine:3.20
        command: [sh, -c, "while true; do :; done"]
        resources: {requests: {cpu: 100m}}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: burn}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: burn}
  minReplicas: 1
  maxReplicas: 3
  metrics:
  - type: Resource
    resource: {name: cpu, target: {type: Utilization, averageUtilization: 50}}
Y
# metrics need two 15 s scrapes, the HPA acts every 15 s: allow a few minutes.
up=""
for _ in $(seq 90); do
  n=$(kubectl get deploy burn -o jsonpath='{.spec.replicas}' 2>/dev/null)
  if [ "${n:-1}" -ge 2 ]; then up=yes; break; fi
  sleep 4
done
check "HPA scaled the busy deployment up" "$up" yes
kubectl get hpa burn
check "TARGETS shows a utilization" "$(kubectl get hpa burn --no-headers | awk '{print $3}' | grep -c '%/50%')" 1
check "ScalingActive is True" "$(kubectl get hpa burn -o jsonpath='{.status.conditions[?(@.type=="ScalingActive")].status}')" True
check "replicas reach max 3" "$(for _ in $(seq 60); do n=$(kubectl get deploy burn -o jsonpath='{.spec.replicas}'); [ "$n" = 3 ] && { echo 3; break; }; sleep 4; done)" 3
kubectl get hpa burn
exit $fail

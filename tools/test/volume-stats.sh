#!/usr/bin/env bash
# Volume statistics: a pod writes into a PVC (local-path), and `nodes/<n>/proxy/metrics` reports
# kubelet_volume_stats_* for the claim, `nodes/<n>/proxy/stats/summary` lists the volume.
# Rootless `kr server`; needs kubectl, systemd --user and network for the alpine image:
#   KR=target/release/kr tools/test/volume-stats.sh
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16448}
trap 'systemctl --user stop kr-volstats-test.scope >/dev/null 2>&1; systemctl --user reset-failed kr-volstats-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-volstats-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
kubectl apply -f - >/dev/null <<'Y'
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Pod
metadata: {name: writer}
spec:
  containers:
  - name: c
    image: docker.io/library/alpine:3.20
    command: [sh, -c, "head -c 3000000 /dev/zero > /data/blob; sleep 3600"]
    volumeMounts: [{name: d, mountPath: /data}]
  volumes: [{name: d, persistentVolumeClaim: {claimName: data}}]
Y
kubectl wait --for=condition=Ready pod/writer --timeout=180s >/dev/null
NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
# The claim is looked up every 20 s at most.
for _ in $(seq 40); do
  M=$(kubectl get --raw "/api/v1/nodes/$NODE/proxy/metrics" 2>/dev/null)
  echo "$M" | grep -q 'kubelet_volume_stats_used_bytes{namespace="default",persistentvolumeclaim="data"}' && break; sleep 2
done
used=$(echo "$M" | sed -n 's/^kubelet_volume_stats_used_bytes{namespace="default",persistentvolumeclaim="data"} //p')
cap=$(echo "$M" | sed -n 's/^kubelet_volume_stats_capacity_bytes{namespace="default",persistentvolumeclaim="data"} //p')
[ -n "$used" ] && [ -n "$cap" ] && [ "$cap" -gt 0 ] && echo "ok   kubelet_volume_stats_* for the claim (used $used of $cap)" || { echo "FAIL no volume metrics: $(echo "$M" | head -3)"; fail=1; }
check "summary lists the volume" "$(kubectl get --raw "/api/v1/nodes/$NODE/proxy/stats/summary" | grep -c '"pvcRef":{"name":"data","namespace":"default"}')" "1"
check "resource metrics still served" "$(kubectl get --raw "/api/v1/nodes/$NODE/proxy/metrics/resource" | grep -c '^node_cpu_usage_seconds_total')" "1"
check "unknown node path is 404" "$(kubectl get --raw "/api/v1/nodes/$NODE/proxy/pods" 2>&1 | grep -c NotFound)" "1"
exit $fail

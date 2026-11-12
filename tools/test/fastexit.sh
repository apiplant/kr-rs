#!/usr/bin/env bash
# Containers that exit at once (`echo`) are reported Succeeded with no restart, not RunContainerError
# (the shim reaps them before the kubelet opens their pidfd). Rootless `kr server`; needs kubectl,
# systemd --user and network for the alpine image:  KR=target/release/kr tools/test/fastexit.sh
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16445}
trap 'systemctl --user stop kr-fastexit-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-fastexit-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
N=12
for i in $(seq $N); do
kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: fast-$i}
spec:
  restartPolicy: Never
  initContainers:
  - {name: i, image: docker.io/library/alpine:3.20, command: [echo, init]}
  containers:
  - {name: a, image: docker.io/library/alpine:3.20, command: [echo, app]}
Y
done
for _ in $(seq 90); do
  done_n=$(kubectl get pods --no-headers 2>/dev/null | grep -c Succeeded)
  [ "$done_n" = "$N" ] && break; sleep 1
done
echo "succeeded: $done_n/$N"
[ "$done_n" = "$N" ] || { fail=1; kubectl get pods; }
bad=$(kubectl get pods -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}' | grep -vc '^0$')
echo "containers with restarts: $bad"
[ "$bad" = 0 ] || fail=1
exit $fail

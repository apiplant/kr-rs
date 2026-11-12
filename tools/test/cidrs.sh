#!/usr/bin/env bash
# Pod and Service networks other than the defaults (KR_POD_CIDR, KR_SERVICE_CIDR) on a rootless
# `kr server`; needs kubectl, systemd --user and network for the alpine image:
#   KR=target/release/kr tools/test/cidrs.sh
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16447}
trap 'systemctl --user stop kr-cidrs-test.scope >/dev/null 2>&1; systemctl --user reset-failed kr-cidrs-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
KR_POD_CIDR=10.200.0.0/16 KR_SERVICE_CIDR=10.201.0.0/16 KR_ROOT=$T/root systemd-run --user --scope --unit=kr-cidrs-test -p Delegate=yes -E KR_POD_CIDR -E KR_SERVICE_CIDR "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
check "kubernetes Service" "$(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}')" "10.201.0.1"
check "kube-dns Service" "$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')" "10.201.0.10"
check "ServiceCIDR" "$(kubectl get servicecidr kubernetes -o jsonpath='{.spec.cidrs[0]}')" "10.201.0.0/16"
check "node podCIDR" "$(kubectl get node -o jsonpath='{.items[0].spec.podCIDR}' | sed 's/\.[0-9]*\.0\/24$/.N.0\/24/')" "10.200.N.0/24"
kubectl create service clusterip web --tcp=80:80 >/dev/null
check "new Service address" "$(kubectl get svc web -o jsonpath='{.spec.clusterIP}')" "10.201.0.11"
check "outside address refused" "$(kubectl create service clusterip bad --tcp=80:80 --clusterip=10.96.0.50 2>&1 | grep -c 'not in the service CIDR 10.201.0.0/16')" "1"
kubectl apply -f - >/dev/null <<'Y'
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
  - {name: c, image: docker.io/library/alpine:3.20, command: [sleep, "3600"]}
Y
kubectl wait --for=condition=Ready pod/p --timeout=120s >/dev/null
case "$(kubectl get pod p -o jsonpath='{.status.podIP}')" in 10.200.*) echo "ok   pod address";; *) echo "FAIL pod address"; fail=1;; esac
check "pod resolv.conf nameserver" "$(kubectl exec p -- cat /etc/resolv.conf | awk '/^nameserver/ {print $2; exit}')" "10.201.0.10"
check "service name resolves" "$(kubectl exec p -- nslookup web.default.svc.cluster.local 2>/dev/null | awk '/^Address/ && !/#/ {print $2}' | tail -1)" "10.201.0.11"
check "invalid value is refused" "$(KR_POD_CIDR=10.5.0.0/24 "$KR" server 2>&1 | grep -c 'KR_POD_CIDR')" "1"
exit $fail

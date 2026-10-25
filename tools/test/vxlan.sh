#!/bin/bash
# Live check of the VXLAN overlay (ADR-025): 3 nodes (server kr1 + agents kr2, kr3) in throwaway
# privileged containers. Reads back FDB / ARP / routes on every node, runs a cross-node pod-to-pod
# wget, deletes a Node and checks its entries go away on the others. Needs target/release/kr (dev only).
#   tools/test/vxlan.sh [down]
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
NODES="kr1 kr2 kr3"
docker rm -f $NODES >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && { docker network rm krnet >/dev/null 2>&1 || true; exit 0; }
docker network create krnet >/dev/null 2>&1 || true
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
for n in $NODES; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    archlinux:base-devel sleep infinity >/dev/null
  docker exec $n sh -c 'command -v bridge >/dev/null || pacman -Sy --noconfirm iproute2 >/dev/null 2>&1'
done
docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) ${KR_SERVER_ENV:-} KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
for _ in $(seq 60); do $K get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec kr1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
for n in kr2 kr3; do
  docker exec $n sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
  docker exec -d $n sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) ${KR_AGENT_ENV:-} KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
done
for _ in $(seq 60); do [ "$($K get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 3 ] && break; sleep 1; done
$K get nodes
ip_of() { docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' "$1"; }
fdb_of() { docker exec "$1" bridge fdb show dev kr.vxlan 2>/dev/null | grep ' dst ' || true; }
# Waits (up to 40 s; the reconcile loop runs every 5 s) until $1 has $2 FDB entries with a remote dst.
wait_fdb() { for _ in $(seq 40); do [ "$(fdb_of "$1" | wc -l)" = "$2" ] && return 0; sleep 1; done; return 0; }
dump() { for n in "$@"; do echo "--- $n"; docker exec $n sh -c 'bridge fdb show dev kr.vxlan; ip neigh show dev kr.vxlan; ip route | grep kr.vxlan'; done; }
nroutes() { docker exec "$1" ip route | grep -c 'dev kr.vxlan.*onlink' || true; }
narp() { docker exec "$1" ip neigh show dev kr.vxlan | grep -c PERMANENT || true; }

for n in $NODES; do wait_fdb $n 2; done
dump $NODES
for n in $NODES; do
  fdb=$(fdb_of $n)
  check "$n: exactly 2 FDB entries" "[ \$(echo \"\$fdb\" | wc -l) = 2 ]"
  check "$n: 2 permanent ARP entries" "[ \$(narp $n) = 2 ]"
  check "$n: 2 pod-subnet routes via kr.vxlan" "[ \$(nroutes $n) = 2 ]"
  for p in $NODES; do
    [ $p = $n ] && continue
    pip=$(ip_of $p); mac=$(printf '02:4b:%02x:%02x:%02x:%02x' ${pip//./ })
    check "$n: FDB $mac -> $pip" "echo \"\$fdb\" | grep -q \"^$mac dst $pip \""
    check "$n: single FDB entry for $p" "[ \$(echo \"\$fdb\" | grep -c \"^$mac \") = 1 ]"
    check "$n: FDB entry for $p is permanent" "echo \"\$fdb\" | grep \"^$mac \" | grep -q permanent"
  done
done

# Cross-node pod to pod.
cat <<Y | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: web}
spec:
  nodeName: kr2
  containers: [{name: web, image: busybox, command: [sh, -c, "mkdir -p /www && echo hi-from-kr2 > /www/index.html && httpd -f -p 8080 -h /www"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: cli}
spec:
  nodeName: kr3
  containers: [{name: cli, image: busybox, command: [sleep, "3600"]}]
Y
for _ in $(seq 120); do [ "$($K get pods --no-headers 2>/dev/null | grep -c Running)" = 2 ] && break; sleep 1; done
$K get pods -o wide
WEBIP=$($K get pod web -o jsonpath='{.status.podIP}')
check "pod-to-pod wget kr3 -> kr2 ($WEBIP)" "[ \"\$($K exec cli -- wget -q -T 5 -O- http://$WEBIP:8080)\" = hi-from-kr2 ]"

# Node deletion: its entries must go away on the others.
$K delete node kr3 --wait=false >/dev/null
for n in kr1 kr2; do
  wait_fdb $n 1
  dump $n
  check "$n: 1 FDB entry after kr3 deleted" "[ \$(fdb_of $n | wc -l) = 1 ]"
  check "$n: 1 ARP entry after kr3 deleted" "[ \$(narp $n) = 1 ]"
  check "$n: 1 route after kr3 deleted" "[ \$(nroutes $n) = 1 ]"
done
if [ $FAIL = 0 ]; then echo "ALL OK"; else echo "FAILURES"; exit 1; fi

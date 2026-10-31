#!/usr/bin/env bash
# Changing KR_POD_FAMILIES on an existing cluster (ADR-034): a dual-stack two-node cluster is
# restarted as IPv6-only (nodes keep their pod network numbers, the built-in Services follow, new
# pods are IPv6-only), then as IPv4-only. Needs target/release/kr, docker, kubectl.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f kr1 kr2 >/dev/null 2>&1
"$REPO/tools/test/two-node.sh" up >/dev/null 2>&1 || { echo "cluster did not start"; exit 1; }
K="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
IMG=${IMG:-registry.k8s.io/e2e-test-images/agnhost:2.66.1}
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
MIRR=$("$REPO/tools/test/registry-cache.sh" env krnet)
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
restart_as() { # families
  docker exec kr1 pkill -x kr; docker exec kr2 pkill -x kr; sleep 2
  docker exec -d kr1 sh -c "KR_POD_FAMILIES=$1 KR_REGISTRY_MIRRORS=$MIRR KR_ROOT=/store /krbin/kr server --data /var/tmp/srv >> /tmp/srv.log 2>&1"
  for _ in $(seq 60); do $K get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
  docker exec -d kr2 sh -c "KR_REGISTRY_MIRRORS=$MIRR KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 >> /tmp/agent.log 2>&1"
  for _ in $(seq 60); do [ "$($K get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 2 ] && break; sleep 1; done
  sleep 8
}
probe() { # name node
  $K run "$1" --image=$IMG --overrides="{\"spec\":{\"nodeName\":\"$2\"}}" --command -- sleep 3600 >/dev/null
  $K wait --for=condition=Ready pod/$1 --timeout=90s >/dev/null
}
for mode in 6 4; do
  echo "== restart as families $mode"
  $K delete pod --all --now >/dev/null 2>&1
  restart_as $mode
  want_cidr() { case $1 in 6) echo "fd00:88:0::/64 fd00:88:0:1::/64";; *) echo "10.88.0.0/24 10.88.1.0/24";; esac; }
  check node-cidrs "$(for n in kr1 kr2; do $K get node $n -o jsonpath='{.spec.podCIDRs[*]}'; echo; done | tr '\n' ' ' | sed 's/ $//')" "$(want_cidr $mode)"
  check kube-dns-ip "$($K -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIPs[*]}')" "$([ $mode = 6 ] && echo fd00:96::a || echo 10.96.0.10)"
  check kubernetes-ip "$($K get svc kubernetes -o jsonpath='{.spec.clusterIPs[0]}')" "$([ $mode = 6 ] && echo fd00:96::1 || echo 10.96.0.1)"
  probe a kr1; probe b kr2
  A=$($K get pod a -o jsonpath='{.status.podIPs[*].ip}'); B=$($K get pod b -o jsonpath='{.status.podIP}')
  check pod-ips "$A" "$([ $mode = 6 ] && echo fd00:88::2 || echo 10.88.0.2)"
  f() { case $1 in *:*) echo "[$1]";; *) echo "$1";; esac; }
  check cross-node "$($K exec a -- /agnhost connect "$(f $B):8080" --timeout=3s 2>&1 | grep -c REFUSED)" 1
  check kubernetes-svc "$($K exec a -- /agnhost connect kubernetes.default.svc.cluster.local:443 --timeout=3s >/dev/null 2>&1; echo $?)" 0
  check cluster-dns "$($K exec a -- nslookup kubernetes.default.svc.cluster.local 2>&1 | grep -c '^Address.*[0-9a-f]')" 2
done
[ $fail = 0 ] && echo "families change: all checks passed" || { echo "families change: FAILED"; exit 1; }

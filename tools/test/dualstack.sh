#!/usr/bin/env bash
# Dual-stack check on a two-node cluster (tools/test/two-node.sh up): pod IPv6 addresses,
# pod-to-pod across nodes, dual-stack and IPv6-only Services (ClusterIPs, EndpointSlices, proxy,
# DNS AAAA) and IPv6 egress through the masquerade table. Run after `two-node.sh up`.
set -u
K="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
KI="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
IMG=${IMG:-registry.k8s.io/e2e-test-images/agnhost:2.66.1}
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }

$K create deployment web --image="$IMG" --replicas=2 -- /agnhost netexec >/dev/null
$KI apply -f - >/dev/null <<Y
apiVersion: v1
kind: Service
metadata: {name: dual}
spec: {selector: {app: web}, ipFamilyPolicy: PreferDualStack, ports: [{port: 80, targetPort: 8080}]}
---
apiVersion: v1
kind: Service
metadata: {name: v6only}
spec: {selector: {app: web}, ipFamilies: [IPv6], ports: [{port: 80, targetPort: 8080}]}
Y
for _ in $(seq 60); do [ "$($K get deploy web -o jsonpath='{.status.readyReplicas}')" = 2 ] && break; sleep 1; done
sleep 6

echo "== nodes and pods"
check node-podcidrs "$($K get node kr2 -o jsonpath='{.spec.podCIDRs[1]}')" "fd00:88:0:1::/64"
P=$($K get pod -l app=web -o name | head -1)
check pod-has-two-ips "$($K get $P -o jsonpath='{.status.podIPs[*].ip}' | wc -w)" 2
IP6=$($K get pod -l app=web -o jsonpath='{.items[*].status.podIPs[1].ip}' | tr ' ' '\n' | head -2)
for ip in $IP6; do
  check "host-to-pod-v6 $ip" "$(docker exec kr1 curl -s -m3 "http://[$ip]:8080/hostname" | cut -c1-4)" "web-"
done

echo "== services"
check dual-clusterips "$($K get svc dual -o jsonpath='{.spec.clusterIPs}')" '["10.96.0.11","fd00:96::b"]'
check dual-families "$($K get svc dual -o jsonpath='{.spec.ipFamilies}')" '["IPv4","IPv6"]'
check v6only-clusterips "$($K get svc v6only -o jsonpath='{.spec.clusterIPs}')" '["fd00:96::c"]'
check slice-types "$($K get endpointslices -l kubernetes.io/service-name=dual -o jsonpath='{.items[*].addressType}' | tr ' ' '\n' | sort | tr '\n' ' ')" "IPv4 IPv6 "
seen() { for _ in 1 2 3 4 5 6; do docker exec kr1 curl -s -m3 "$1" ; echo; done | sort -u | grep -c web; }
check proxy-v4 "$(seen http://10.96.0.11:80/hostname)" 2
check proxy-v6 "$(seen 'http://[fd00:96::b]:80/hostname')" 2
check proxy-v6only "$(seen 'http://[fd00:96::c]:80/hostname')" 2

echo "== DNS"
DNS=$($K exec $P -- sh -c 'nslookup dual.default.svc.cluster.local 2>&1')
check dns-a "$(echo "$DNS" | grep -c '^Address: 10.96.0.11')" 1
check dns-aaaa "$(echo "$DNS" | grep -c '^Address: fd00:96::b')" 1
check dns-v6only "$($K exec $P -- sh -c 'wget -qO- -T3 http://v6only.default.svc.cluster.local:80/hostname' | cut -c1-4)" "web-"

echo "== IPv6 egress (masquerade)"
docker exec kr1 sh -c 'ip netns add t6 2>/dev/null; ip link add vt0 type veth peer name vt1 netns t6 2>/dev/null; ip addr add fd01::1/64 dev vt0 nodad; ip link set vt0 up; ip -n t6 addr add fd01::2/64 dev vt1 nodad; ip -n t6 link set vt1 up; ip -n t6 link set lo up; mkdir -p /srv6 && echo hi > /srv6/index.html; cd /srv6 && (ip netns exec t6 python3 -m http.server 8000 --bind fd01::2 >/dev/null 2>&1 &)'
sleep 1
PK1=$($K get pod -l app=web -o jsonpath='{.items[?(@.spec.nodeName=="kr1")].metadata.name}' | cut -d' ' -f1)
check pod-egress-v6 "$($K exec "$PK1" -- curl -s -m5 -o /dev/null -w '%{http_code}' 'http://[fd01::2]:8000/')" 200
[ $fail = 0 ] && echo "dual stack: all checks passed" || { echo "dual stack: FAILED"; exit 1; }

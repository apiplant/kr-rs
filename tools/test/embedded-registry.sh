#!/bin/bash
# Embedded registry mirror (#322, ADR-067): server krm1 (--embedded-registry) + agents krm2, krm3 in
# throwaway privileged containers (dev only). krm2 pulls busybox from the registry; krm3 has no
# route to any registry and must get the image from a peer. Also: status.images, the mirror
# annotation, `latest` is never taken from peers, and the mirror refuses clients without a
# cluster certificate.
#   tools/test/embedded-registry.sh [down]     (needs target/release/kr)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
N="krm1 krm2 krm3"
docker rm -f $N >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krm1 kubectl"
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
IMG=busybox:1.36
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 2; done; return 1; }
for n in $N; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    archlinux:base-devel sleep infinity >/dev/null
done
docker exec -d krm1 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --embedded-registry --data /var/tmp/srv > /tmp/srv.log 2>&1"
waitfor "$K get --raw /healthz >/dev/null 2>&1" 30
TOKEN=$(docker exec krm1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krm1)
# krm3: a dead mirror for docker.io (so docker.io counts as mirrored) and no default route.
docker exec krm3 ip route del default
for n in krm2 krm3; do
  m=$MIRRORS; [ $n = krm3 ] && m=docker.io=http://127.0.0.1:1
  docker exec $n sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
  docker exec -d $n sh -c "KR_REGISTRY_MIRRORS=$m KR_ROOT=/store exec /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
done
waitfor '[ "$($K get nodes --no-headers 2>/dev/null | grep -c " Ready")" = 3 ]' 45
$K get nodes
check "cluster marked by the server" "waitfor '$K get node krm1 -o jsonpath={.metadata.annotations} | grep -q registry.kr.io/embedded' 15"
for n in $N; do check "$n serves the mirror" "waitfor '$K get node $n -o jsonpath={.metadata.annotations} | grep -q registry.kr.io/mirror-port' 15"; done

pod() { echo "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"$1\"},\"spec\":{\"nodeName\":\"$2\",\"containers\":[{\"name\":\"c\",\"image\":\"$3\",\"command\":[\"sleep\",\"3600\"]}]}}" | $K apply -f - >/dev/null; }
pod seed krm2 $IMG
check "seed pod running on krm2 (from the registry)" "waitfor '[ \"\$($K get pod seed -o jsonpath={.status.phase})\" = Running ]' 60"
check "krm2 reports the image in status.images" "waitfor '$K get node krm2 -o jsonpath={.status.images[*].names} | grep -q docker.io/library/$IMG' 30"
check "status.images also names the manifest digest" "$K get node krm2 -o jsonpath={.status.images[*].names} | grep -q 'docker.io/library/busybox@sha256:'"
pod peer krm3 $IMG
check "krm3 (no registry) runs the pod with the image from a peer" "waitfor '[ \"\$($K get pod peer -o jsonpath={.status.phase})\" = Running ]' 60"
check "krm3 has every blob verified (image present)" "docker exec krm3 sh -c 'ls /store/refs | grep -q busybox'"
pod latest krm3 busybox:latest
sleep 20
check "latest is never taken from a peer" "[ \"\$($K get pod latest -o jsonpath={.status.containerStatuses[0].state.waiting.reason})\" != '' ]"
IP2=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krm2)
check "mirror refuses a client without a cluster certificate" "! docker exec krm1 curl -sk -m 5 -o /dev/null -w '%{http_code}' https://$IP2:5001/kr/ns/docker.io/v2/ | grep -q 200"
check "mirror answers a node certificate" "docker exec krm1 curl -s -m 5 --cacert /var/tmp/srv/pki/ca.pem --cert /var/tmp/srv/pki/kubelet-client.pem --key /var/tmp/srv/pki/kubelet-client.key https://$IP2:5001/kr/ns/docker.io/v2/library/busybox/manifests/1.36 | grep -q layers"
[ $FAIL = 0 ] && { echo PASS; docker rm -f $N >/dev/null; } || { echo "FAILED (left running; $0 down)"; exit 1; }

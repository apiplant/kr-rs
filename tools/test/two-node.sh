#!/bin/bash
# Two-node kr cluster (server kr1 + agent kr2) in throwaway privileged containers (dev only).
#   tools/test/two-node.sh [up|down]
# Extra env for the server: KR_SERVER_ENV, e.g. KR_SERVER_ENV=KR_NODE_CERT_SECONDS=90.
# KR_STORE_SIZE (default 2g) sizes the image store tmpfs; KR_SONOBUOY=1 also mounts sonobuoy.
# Same for the agent: KR_AGENT_ENV, e.g. KR_AGENT_ENV=KR_NET_BACKEND=host-gw.
# Then: docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f kr1 kr2 >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && { docker network rm krnet >/dev/null 2>&1 || true; exit 0; }
docker network create krnet >/dev/null 2>&1 || true
for n in kr1 kr2; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=${KR_STORE_SIZE:-2g} \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    ${KR_SONOBUOY:+-v "$(command -v sonobuoy):/usr/local/bin/sonobuoy:ro"} \
    archlinux:base-devel sleep infinity >/dev/null
done
# KR_HOST_V6=1: give the nodes a global IPv6 address on the shared network, so they report an
# IPv6 InternalIP and the kubernetes Service becomes dual stack (host-gw v6 routes etc.).
# KR_V6_UNDERLAY=1: nodes use their IPv6 addresses for everything (join, Raft, kubelet, VXLAN).
if [ -n "${KR_V6_UNDERLAY:-}" ]; then
  KR_HOST_V6=1; KR_SERVER_ENV="KR_PREFER_IPV6=1 ${KR_SERVER_ENV:-}"; KR_AGENT_ENV="KR_PREFER_IPV6=1 ${KR_AGENT_ENV:-}"
fi
if [ -n "${KR_HOST_V6:-}" ]; then
  i=1; for n in kr1 kr2; do docker exec $n sh -c "sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0; ip -6 addr add fd05::$i/64 dev eth0 nodad; ip -6 route add default dev eth0 metric 1024"; i=$((i+1)); done
fi
docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) ${KR_SERVER_ENV:-} KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
# node-token is written before the API listens: wait for the API itself.
for _ in $(seq 60); do docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec kr1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
[ -n "${KR_V6_UNDERLAY:-}" ] && IP1="[fd05::1]"
docker exec kr2 sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
docker exec -d kr2 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) ${KR_AGENT_ENV:-} KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
for _ in $(seq 60); do
  [ "$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 2 ] && break; sleep 1
done
docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes

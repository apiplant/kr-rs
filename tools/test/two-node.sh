#!/bin/bash
# Two-node kr cluster (server kr1 + agent kr2) in throwaway privileged containers (dev only).
#   tools/test/two-node.sh [up|down]
# Extra env for the server: KR_SERVER_ENV, e.g. KR_SERVER_ENV=KR_NODE_CERT_SECONDS=90.
# Then: docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f kr1 kr2 >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && { docker network rm krnet >/dev/null 2>&1 || true; exit 0; }
docker network create krnet >/dev/null 2>&1 || true
for n in kr1 kr2; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    archlinux:base-devel sleep infinity >/dev/null
done
docker exec -d kr1 sh -c "${KR_SERVER_ENV:-} KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
# node-token is written before the API listens: wait for the API itself.
for _ in $(seq 60); do docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec kr1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
docker exec kr2 sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
docker exec -d kr2 sh -c "KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
for _ in $(seq 60); do
  [ "$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 2 ] && break; sleep 1
done
docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes

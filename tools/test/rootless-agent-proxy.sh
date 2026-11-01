#!/usr/bin/env bash
# Pod proxy to a pod on a rootless agent (the API server on another node cannot route to the pod
# network; it tunnels through the agent's kubelet). Server kr1 (root) + rootless agent kr2.
# Needs docker, kubectl, target/release/kr, archlinux:base-devel.
set -u
cd "$(dirname "$0")/../.."
REPO=$PWD
docker rm -f kr1 kr2 >/dev/null 2>&1; docker network create krnet >/dev/null 2>&1 || true
for n in kr1 kr2; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" archlinux:base-devel sleep infinity >/dev/null
done
KC="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$(tools/test/registry-cache.sh env krnet) KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
for _ in $(seq 60); do $KC get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec kr1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
docker exec kr2 bash -c "
useradd -m u && echo u:100000:65536 > /etc/subuid && echo u:100000:65536 > /etc/subgid
chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap
mkdir -p /home/u/kr && mount -t tmpfs -o size=2g,exec tmpfs /home/u/kr && chown u /home/u/kr
echo '$TOKEN' > /home/u/token && chown u /home/u/token && chmod 600 /home/u/token"
docker exec -d kr2 su u -c "KR_REGISTRY_MIRRORS=$(tools/test/registry-cache.sh env krnet) KR_ROOT=/home/u/kr /krbin/kr agent --server https://$IP1:6443 --token-file /home/u/token > /home/u/agent.log 2>&1"
for _ in $(seq 90); do [ "$($KC get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 2 ] && break; sleep 1; done
$KC get nodes
docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: w}
spec:
  nodeSelector: {kubernetes.io/hostname: kr2}
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sh, -c, "while true; do printf \"HTTP/1.0 200 OK\\\\r\\\\nContent-Length: 8\\\\r\\\\n\\\\r\\\\nproxied\\\\n\" | nc -l -p 8080; done"]}]
Y
$KC wait --for=condition=Ready pod/w --timeout=120s >/dev/null 2>&1; sleep 2
echo "rootless annotation: $($KC get node kr2 -o jsonpath='{.metadata.annotations.kr\.io/rootless}')"
OUT=$($KC get --raw /api/v1/namespaces/default/pods/w:8080/proxy/ 2>&1)
if [ "$OUT" = proxied ]; then echo "ok   pod-proxy through the rootless agent"; RC=0; else echo "FAIL pod-proxy: $OUT"; docker exec kr2 tail -5 /home/u/agent.log; RC=1; fi
docker rm -f kr1 kr2 >/dev/null 2>&1
exit $RC

#!/bin/bash
# Install-time configuration on a live cluster (#318, ADR-060), in throwaway privileged containers
# (dev only): a server kri1 and an agent kri2 configured through config files.
#  1. tls-san, node-label, node-taint from the server's config file; a client reaches the API by
#     the extra name; then a changed config (new SAN, new label, taint removed) after a restart.
#  2. The agent joins with node-label, node-taint and node-ip on its second (multi-homed) network;
#     logs through its kubelet use that address.
#  3. Every `disable:` component, observed by its effect, against a cluster with nothing disabled.
#   tools/test/install-config.sh [down]     (needs target/release/kr)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
N="kri1 kri2"
docker rm -f $N >/dev/null 2>&1 || true
docker network rm kri2net >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
docker network create --subnet 172.31.9.0/24 kri2net >/dev/null
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kri1 kubectl"
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 2; done; return 1; }
for n in $N; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
  docker network connect kri2net $n
done
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kri1)
IP2B=$(docker inspect -f '{{.NetworkSettings.Networks.kri2net.IPAddress}}' kri2)
cfg() { docker exec -i $1 sh -c "mkdir -p /etc/kr && cat > /etc/kr/config.yaml"; }
start_server() { docker exec -d kri1 sh -c "echo \$\$ > /tmp/srv.pid; KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --config /etc/kr/config.yaml --data /var/tmp/srv >> /tmp/srv.log 2>&1"; waitfor "$K get --raw /healthz >/dev/null 2>&1" 30; }
stop_server() { docker exec kri1 sh -c 'kill $(cat /tmp/srv.pid)'; waitfor "! docker exec kri1 sh -c 'kill -0 \$(cat /tmp/srv.pid) 2>/dev/null'" 15; }
san_ok() { docker exec kri1 curl -s -m 5 --cacert /var/tmp/srv/pki/ca.pem --resolve "$1:6443:127.0.0.1" "https://$1:6443/healthz" | grep -q ok; }

# --- 1. server config
cfg kri1 <<'Y'
tls-san:
  - kr.example.test
node-label:
  - zone=a
node-taint:
  - dedicated=infra:NoSchedule
Y
start_server
check "server node has the configured label" "waitfor '$K get node kri1 -o jsonpath={.metadata.labels.zone} | grep -qx a' 15"
check "server node has the configured taint" "$K get node kri1 -o jsonpath={.spec.taints} | grep -q dedicated"
check "API certificate covers tls-san kr.example.test" "san_ok kr.example.test"
check "API certificate does not cover an unknown name" "! san_ok other.example.test"
stop_server
cfg kri1 <<'Y'
tls-san:
  - kr.example.test
  - kr2.example.test
node-label:
  - zone=b
Y
start_server
check "after a SAN change: the new name works without a client change" "san_ok kr2.example.test"
check "after a SAN change: the old name still works" "san_ok kr.example.test"
check "after a config change: label updated" "waitfor '$K get node kri1 -o jsonpath={.metadata.labels.zone} | grep -qx b' 15"
check "after a config change: removed taint is gone" "waitfor '! $K get node kri1 -o jsonpath={.spec.taints} | grep -q dedicated' 15"

# --- 2. agent on a multi-homed host
TOKEN=$(docker exec kri1 cat /var/tmp/srv/node-token)
cfg kri2 <<Y
node-label:
  - role=edge
node-taint:
  - edge=true:NoExecute
node-ip: $IP2B
Y
docker exec kri2 sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
docker exec -d kri2 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr agent --config /etc/kr/config.yaml --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
check "agent Ready" "waitfor '$K get node kri2 --no-headers 2>/dev/null | grep -q \" Ready\"' 45"
check "agent label from its config" "$K get node kri2 -o jsonpath={.metadata.labels.role} | grep -qx edge"
check "agent taint from its config (present at registration)" "$K get node kri2 -o jsonpath={.spec.taints} | grep -q '\"edge\"'"
check "agent InternalIP is the --node-ip on the second network" "[ \"\$($K get node kri2 -o jsonpath='{.status.addresses[?(@.type==\"InternalIP\")].address}' | cut -d' ' -f1)\" = $IP2B ]"
cat <<Y | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: edge}
spec:
  nodeName: kri2
  tolerations: [{key: edge, operator: Exists}]
  containers: [{name: c, image: busybox:1.36, command: [sh, -c, 'while true; do echo edge-up; sleep 3; done']}]
Y
check "logs through the agent's kubelet at its node-ip" "waitfor '$K logs edge 2>/dev/null | grep -q edge-up' 60"

# --- 3. disable: each component on and off
probe_components() { # prints one word per component that works
  cat <<'Y' | $K apply -f - >/dev/null 2>&1
apiVersion: v1
kind: Service
metadata: {name: lb}
spec: {type: LoadBalancer, selector: {app: none}, ports: [{port: 8099}]}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: pvc}
spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Mi}}}
---
apiVersion: v1
kind: Pod
metadata: {name: dns}
spec:
  tolerations: [{operator: Exists}]
  nodeName: kri1
  volumes: [{name: v, persistentVolumeClaim: {claimName: pvc}}]
  containers: [{name: c, image: busybox:1.36, command: [sleep, '3600'], volumeMounts: [{name: v, mountPath: /v}]}]
---
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: hc, namespace: kube-system}
spec: {chart: nonexistent, repo: 'https://example.invalid'}
Y
  sleep 30
  $K get svc lb -o jsonpath='{.status.loadBalancer.ingress}' | grep -q ip && echo servicelb
  $K get --raw /apis/metrics.k8s.io/v1beta1/nodes 2>/dev/null | grep -q kri1 && echo metrics-server
  $K get pvc pvc -o jsonpath='{.status.phase}' | grep -q Bound && echo local-storage
  $K exec dns -- nslookup kubernetes.default.svc.cluster.local 2>/dev/null | grep -q 10.96 && echo coredns
  $K get jobs -n kube-system -o name 2>/dev/null | grep -q helm-install-hc && echo helm-controller
  $K delete pod dns --force >/dev/null 2>&1; $K delete svc lb pvc >/dev/null 2>&1; $K delete pvc pvc >/dev/null 2>&1; $K delete helmchart -n kube-system hc >/dev/null 2>&1
}
ALL="servicelb metrics-server local-storage coredns helm-controller"
ON=$(probe_components | tr '\n' ' ')
for c in $ALL; do check "enabled by default: $c works" "echo ' $ON ' | grep -q ' $c '"; done
stop_server
cfg kri1 <<'Y'
tls-san: [kr.example.test, kr2.example.test]
disable: [servicelb, metrics-server, local-storage, coredns, network-policy]
disable-helm-controller: true
Y
start_server
OFF=$(probe_components | tr '\n' ' ')
for c in $ALL; do check "disabled: $c does nothing" "! echo ' $OFF ' | grep -q ' $c '"; done
check "disabled: network-policy leaves no kr-netpol tables" "! docker exec kri1 nft list tables | grep -q kr-netpol"
[ $FAIL = 0 ] && { echo PASS; docker rm -f $N >/dev/null; docker network rm kri2net >/dev/null; } || { echo "FAILED (left running; $0 down)"; exit 1; }

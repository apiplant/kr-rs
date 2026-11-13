#!/bin/bash
# The kernel (nftables) Service datapath on a real multi-node cluster (#133, #205): server krp1 +
# agents krp2, krp3 in throwaway privileged containers (dev only). Checks ClusterIP, DNS name and
# NodePort across nodes, NetworkPolicy (deny, podSelector, ipBlock with except, named port) through
# ClusterIPs, then a `kr server` restart keeps it all.
#   tools/test/nft-cluster.sh [down]       (needs target/release/kr) - kr's built-in bridge
#   KR_TEST_CNI=calico tools/test/nft-cluster.sh   - Calico (tigera operator, VXLAN, pool
#       10.244.0.0/16) as an external CNI with KR_PROXY=nft; Calico enforces the policies.
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
NODES="krp1 krp2 krp3"
docker rm -f $NODES >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
CNI=${KR_TEST_CNI:-}
ENV=""
[ "$CNI" = calico ] && ENV="KR_PROXY=nft KR_CNI_CONF_DIR=/etc/cni/net.d KR_CNI_BIN_DIR=/opt/cni/bin"
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krp1 kubectl"
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
for n in $NODES; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    -v /lib/modules:/lib/modules:ro archlinux:base-devel sleep infinity >/dev/null
  docker exec $n mkdir -p /etc/cni/net.d /opt/cni/bin
done
start_server() { docker exec -d krp1 sh -c "echo \$\$ > /tmp/srv.pid; KR_REGISTRY_MIRRORS=$MIRRORS $ENV KR_ROOT=/store exec /krbin/kr server --data /var/tmp/srv >> /tmp/srv.log 2>&1"; }
start_server
for _ in $(seq 60); do $K get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec krp1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krp1)
for n in krp2 krp3; do
  docker exec $n sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
  docker exec -d $n sh -c "KR_REGISTRY_MIRRORS=$MIRRORS $ENV KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
done
for _ in $(seq 90); do [ "$($K get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 3 ] && break; sleep 1; done
$K get nodes
if [ "$CNI" = calico ]; then
  helm template calico-crds projectcalico/crd.projectcalico.org.v1 | $K apply --server-side -f - >/dev/null
  $K create namespace tigera-operator >/dev/null
  helm template calico projectcalico/tigera-operator -n tigera-operator --no-hooks \
    --set installation.calicoNetwork.bgp=Disabled \
    --set 'installation.calicoNetwork.ipPools[0].cidr=10.244.0.0/16' \
    --set 'installation.calicoNetwork.ipPools[0].encapsulation=VXLAN' \
    --set 'installation.calicoNetwork.ipPools[0].natOutgoing=Enabled' \
    --set 'installation.calicoNetwork.ipPools[0].nodeSelector=all()' | $K apply --server-side -n tigera-operator -f - >/dev/null
  for _ in $(seq 120); do [ "$($K get ds -n calico-system calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null)" = 3 ] && break; sleep 5; done
  check "calico-node Ready on all nodes" "[ \"\$($K get ds -n calico-system calico-node -o jsonpath='{.status.numberReady}')\" = 3 ]"
  [ $FAIL = 0 ] || { $K get pods -A -o wide; echo "FAILED (Calico not up; left running)"; exit 1; }
fi
check "krp1: nftables datapath" "docker exec krp1 grep -q 'nftables datapath' /tmp/srv.log"
for n in krp2 krp3; do check "$n: nftables datapath" "docker exec $n grep -q 'nftables datapath' /tmp/agent.log"; done

cat <<Y | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: web, labels: {app: web}}
spec:
  nodeName: krp2
  containers:
  - name: web
    image: busybox
    command: [sh, -c, 'mkdir -p /www && echo hello > /www/index.html && exec httpd -f -p 8080 -h /www']
    ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: http}]
---
apiVersion: v1
kind: Service
metadata: {name: web-np}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: 30080}]
---
apiVersion: v1
kind: Pod
metadata: {name: client, labels: {role: client}}
spec:
  nodeName: krp3
  containers: [{name: c, image: busybox, command: [sleep, '3600']}]
---
apiVersion: v1
kind: Pod
metadata: {name: other, labels: {role: other}}
spec:
  nodeName: krp1
  containers: [{name: c, image: busybox, command: [sleep, '3600']}]
Y
$K wait --for=condition=Ready pod/web pod/client pod/other --timeout=180s >/dev/null || { $K get pods -o wide; FAIL=1; }
CIP=$($K get svc web -o jsonpath='{.spec.clusterIP}')
CLIENT_IP=$($K get pod client -o jsonpath='{.status.podIP}')
POD_NET=$(echo "$CLIENT_IP" | cut -d. -f1-2).0.0/16
IP2=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krp2)
get() { $K exec "$1" -- wget -q -T 3 -O - "$2" 2>/dev/null | grep -q hello; }
# A few tries: rules land within a sync period after the endpoints appear.
eventually() { for _ in $(seq 15); do eval "$1" && return 0; sleep 1; done; return 1; }
never() { for _ in $(seq 15); do eval "$1" || break; sleep 1; done; for _ in $(seq 3); do eval "$1" && return 1; sleep 1; done; return 0; }
basic() {
  check "$1: client (krp3) -> ClusterIP -> web (krp2)" "eventually 'get client http://$CIP'"
  check "$1: other (krp1) -> ClusterIP -> web (krp2)" "eventually 'get other http://$CIP'"
  check "$1: client -> DNS name" "eventually 'get client http://web.default.svc.cluster.local'"
  check "$1: krp3 host -> ClusterIP" "eventually 'docker exec krp3 curl -s -m 3 http://$CIP | grep -q hello'"
  check "$1: NodePort on krp2 from krp1 host" "eventually 'docker exec krp1 curl -s -m 3 http://$IP2:30080 | grep -q hello'"
  check "$1: NodePort on krp1 (pod elsewhere) from krp3 host" "eventually 'docker exec krp3 curl -s -m 3 http://$IP1:30080 | grep -q hello'"
}
basic before
check "nft table present on every node" "for n in $NODES; do docker exec \$n nft list tables | grep -q kr || exit 1; done"

np() { cat <<Y | $K apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web}
spec:
  podSelector: {matchLabels: {app: web}}
  policyTypes: [Ingress]
  ingress: $1
Y
}
np '[]'
check "deny-all: client blocked via ClusterIP" "never 'get client http://$CIP'"
np '[{from: [{podSelector: {matchLabels: {role: client}}}]}]'
check "podSelector: client allowed" "eventually 'get client http://$CIP'"
check "podSelector: other blocked" "never 'get other http://$CIP'"
np "[{from: [{ipBlock: {cidr: $POD_NET, except: [$CLIENT_IP/32]}}]}]"
check "ipBlock except: client blocked" "never 'get client http://$CIP'"
check "ipBlock except: other allowed" "eventually 'get other http://$CIP'"
np '[{ports: [{port: http}]}]'
check "named port: allowed on http" "eventually 'get client http://$CIP'"
np '[{ports: [{port: 9999}]}]'
check "other port only: blocked" "never 'get client http://$CIP'"
$K delete networkpolicy web >/dev/null
check "policy removed: allowed again" "eventually 'get client http://$CIP'"

# Server restart: the datapath must keep working while it is down and after it is back.
# Only the main process is killed: pod shims are detached copies with the same command line,
# and the server node's pods must survive and be adopted.
SLEEP_PID=$(docker exec krp1 pgrep -n -f 'sleep 3600' || true)
docker exec krp1 sh -c 'kill $(cat /tmp/srv.pid)'
for _ in $(seq 20); do docker exec krp1 sh -c 'kill -0 $(cat /tmp/srv.pid) 2>/dev/null' || break; sleep 1; done
check "server down: krp3 host -> ClusterIP still works" "eventually 'docker exec krp3 curl -s -m 3 http://$CIP | grep -q hello'"
check "server down: krp3 host -> NodePort on krp2" "eventually 'docker exec krp3 curl -s -m 3 http://$IP2:30080 | grep -q hello'"
start_server
for _ in $(seq 60); do $K get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
for _ in $(seq 60); do [ "$($K get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 3 ] && break; sleep 1; done
check "server restarted (new process listening)" "docker exec krp1 sh -c '[ \$(grep -c \"listening on\" /tmp/srv.log) = 2 ] && ! grep -q \"listener failed\" /tmp/srv.log'"
basic "after restart"
check "after restart: server node's pod was adopted (no restart)" "[ \"\$($K get pod other -o jsonpath='{.status.containerStatuses[0].restartCount}')\" = 0 ]"
check "after restart: same container process on krp1" "[ -n '$SLEEP_PID' ] && [ \"\$(docker exec krp1 pgrep -n -f 'sleep 3600')\" = '$SLEEP_PID' ]"
check "after restart: adoption logged" "eventually 'docker exec krp1 grep -q \"adopted [1-9]\" /tmp/srv.log'"
np '[]'
check "after restart: a new policy applies" "never 'get client http://$CIP'"
$K delete networkpolicy web >/dev/null
[ $FAIL = 0 ] && echo PASS || { echo "FAILED (cluster left running; tools/test/nft-cluster.sh down)"; exit 1; }
docker rm -f $NODES >/dev/null

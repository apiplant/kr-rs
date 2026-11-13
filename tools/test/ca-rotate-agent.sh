#!/bin/bash
# CA rotation on a running single server with an agent, no restarts (#189): server krc1, agent krc2
# in throwaway privileged containers (dev only). prepare/activate/finish while everything runs;
# finish without --yes must see the agent's renewed certificate; logs through the agent's kubelet
# and the admin kubeconfig work afterwards with only the new CA.
#   tools/test/ca-rotate-agent.sh [down]     (needs target/release/kr)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
N="krc1 krc2"
docker rm -f $N >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krc1 kubectl"
KR="docker exec -e KR_ROOT=/store krc1 /krbin/kr"
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 2; done; return 1; }
for n in $N; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
done
docker exec -d krc1 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
waitfor "$K get --raw /healthz >/dev/null 2>&1" 30
TOKEN=$(docker exec krc1 cat /var/tmp/srv/node-token)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krc1)
docker exec krc2 sh -c "umask 077; echo '$TOKEN' > /root/kr-token"
docker exec -d krc2 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
waitfor '[ "$($K get nodes --no-headers 2>/dev/null | grep -c " Ready")" = 2 ]' 45
$K run probe --image=busybox --overrides='{"spec":{"nodeName":"krc2"}}' -- sh -c 'while true; do echo alive; sleep 5; done' >/dev/null
waitfor "$K logs probe 2>/dev/null | grep -q alive" 60
check "probe on the agent" "$K logs probe | grep -q alive"
SRV=$(docker exec krc1 pgrep -o -x kr)

$KR pki rotate --ca prepare --data /var/tmp/srv >/dev/null || FAIL=1
check "prepare: agent trusts the bundle" "waitfor 'docker exec krc2 grep -q \"trusting the new one\" /tmp/agent.log' 50"
$KR pki rotate --ca activate --data /var/tmp/srv >/dev/null || FAIL=1
check "activate: server reloaded its certificates" "waitfor 'docker exec krc1 grep -q \"now serving and trusting the new ones\" /tmp/srv.log' 10"
check "activate: agent renewed with the new CA" "waitfor 'docker exec krc2 grep -q \"renewed with the new CA\" /tmp/agent.log' 50"
check "finish without --yes accepts the renewed agent" "$KR pki rotate --ca finish --data /var/tmp/srv >/dev/null"
sleep 6
check "finish: ca.pem holds one CA" "[ \$(docker exec krc1 grep -c 'BEGIN CERT' /var/tmp/srv/pki/ca.pem) = 1 ]"
check "finish: admin kubeconfig works" "$K get nodes >/dev/null"
check "finish: logs through the agent's kubelet" "waitfor '$K logs probe --tail=1 | grep -q alive' 10"
check "finish: agent follows the single-CA bundle" "waitfor '[ \$(docker exec krc2 grep -c \"BEGIN CERT\" /store/agent/pki/ca.pem) = 1 ]' 50"
check "finish: nodes Ready" "waitfor '[ \"\$($K get nodes --no-headers | grep -c \" Ready\")\" = 2 ]' 30"
check "server never restarted" "[ \"\$(docker exec krc1 pgrep -o -x kr)\" = '$SRV' ]"
[ $FAIL = 0 ] && { echo PASS; docker rm -f $N >/dev/null; } || { echo "FAILED (left running; $0 down)"; exit 1; }

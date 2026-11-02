#!/usr/bin/env bash
# Rootless pods survive a crash of the agent (ADR-036): server kr1 (root) + rootless agent kr2.
# Pods keep their processes, IPs, outbound connectivity (the egress helper) and terminal logs
# while the agent is down; a container that ends meanwhile keeps its real exit status.
# Needs docker, kubectl, target/release/kr, archlinux:base-devel.
set -u
cd "$(dirname "$0")/../.."
REPO=$PWD
docker rm -f kr1 kr2 >/dev/null 2>&1; docker network create krnet >/dev/null 2>&1 || true
for n in kr1 kr2; do
  docker run -d --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" archlinux:base-devel sleep infinity >/dev/null
done
KC="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
MIRRORS=$(tools/test/registry-cache.sh env krnet)
docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
for _ in $(seq 60); do $KC get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
TOKEN=$(docker exec kr1 cat /var/tmp/srv/node-token)
docker exec kr2 bash -c "
useradd -m u && echo u:100000:65536 > /etc/subuid && echo u:100000:65536 > /etc/subgid
chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap
mkdir -p /home/u/kr && mount -t tmpfs -o size=2g,exec tmpfs /home/u/kr && chown u /home/u/kr
echo '$TOKEN' > /home/u/token && chown u /home/u/token && chmod 600 /home/u/token"
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
start_agent() { docker exec -d kr2 su u -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/home/u/kr /krbin/kr agent --server https://$IP1:6443 --token-file /home/u/token > /home/u/agent.$1.log 2>&1"; }
start_agent 1
for _ in $(seq 90); do [ "$($KC get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 2 ] && break; sleep 1; done
CACHE=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr-cache-docker)
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
$KC apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: egresser}
spec:
  nodeSelector: {kubernetes.io/hostname: kr2}
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sh, -c, "i=0; while true; do wget -q -T3 -O /dev/null http://$CACHE:5000/v2/ && echo ok-\$i || echo fail-\$i; i=\$((i+1)); sleep 1; done"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: ttyp}
spec:
  nodeSelector: {kubernetes.io/hostname: kr2}
  containers: [{name: c, image: docker.io/library/alpine:3.20, tty: true, stdin: true, command: [sh, -c, "i=0; while true; do echo tick-\$i; i=\$((i+1)); sleep 1; done"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: exit3}
spec:
  nodeSelector: {kubernetes.io/hostname: kr2}
  restartPolicy: Never
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sh, -c, "sleep 45; exit 3"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: stdinp}
spec:
  nodeSelector: {kubernetes.io/hostname: kr2}
  containers: [{name: c, image: docker.io/library/alpine:3.20, stdin: true, command: [sh, -c, "while read l; do echo got:\$l; done"]}]
Y
for _ in $(seq 90); do [ "$($KC get pods --no-headers | grep -c '1/1 *Running')" = 3 ] && break; sleep 2; done
sleep 8
BEFORE=$($KC get pods -o wide --no-headers | awk '{print $1,$4,$6}' | sort)
echo "$BEFORE" | sed 's/^/   before: /'
echo "one" | /usr/bin/timeout 8 $KC attach -i stdinp >/dev/null 2>&1
# The agent is the one kr process not parented by init (shims are detached copies with the same command line).
AG=$(docker exec kr2 sh -c "ps -u u -o pid=,ppid=,args= | awk '\$2 != 1 && /krbin\/kr agent/ && !/bash/ {print \$1; exit}'")
echo "-- kill -9 agent (pid $AG); down for 60s"
docker exec kr2 kill -9 $AG
sleep 60
start_agent 2
sleep 25
AFTER=$($KC get pods -o wide --no-headers | awk '{print $1,$4,$6}' | sort)
echo "$AFTER" | sed 's/^/   after:  /'
check "same pods, restart counts and IPs" "$AFTER" "$BEFORE" 2>&1 | sed 's/got.*want.*//'
[ "$AFTER" = "$BEFORE" ] || fail=1
# exit3 ended while the agent was down: its real status is kept
check "exit status survived the outage" "$($KC get pod exit3 -o jsonpath='{.status.phase} {.status.containerStatuses[0].state.terminated.exitCode}')" "Failed 3"
check "no failed downloads during the outage (egress kept running)" "$($KC logs egresser | grep -c '^fail')" 0
check "egress works after the restart" "$($KC logs egresser --tail=1 | cut -d- -f1)" ok
check "terminal log has no gaps across the outage" "$($KC logs ttyp | tr -d '\r' | awk -F- '{print $2}' | awk 'NR>1 && $1!=p+1 {g=1} {p=$1} END{print g?"gap":"none"}')" none
echo "two" | /usr/bin/timeout 8 $KC attach -i stdinp >/dev/null 2>&1
check "attach -i works again after the restart" "$($KC logs stdinp | tr '\n' ' ')" "got:one got:two "
[ -n "${KEEP:-}" ] || docker rm -f kr1 kr2 >/dev/null 2>&1
[ $fail = 0 ] && echo "rootless survive: all checks passed" || echo "rootless survive: FAILED"
exit $fail

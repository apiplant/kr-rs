#!/usr/bin/env bash
# Failure injection for pods surviving the kubelet process (ADR-036), root mode, server kr1 +
# agent kr2 in throwaway containers.
#   binary swap + SIGTERM (agent and server) | killed shim | stale/recycled pid records |
#   crash loop | crash while pods are being created | second agent on the same root
set -u
cd "$(dirname "$0")/../.."
REPO=$PWD
fails=0
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1"; fails=$((fails+1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
KC="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
waitfor() { local t=$1; shift; for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

KR_STORE_SIZE=3g tools/test/two-node.sh up >/dev/null
MIRRORS=$(tools/test/registry-cache.sh env krnet)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
agent_pid() { docker exec kr2 sh -c "ps -eo pid=,ppid=,args= | awk '\$2 != 1 && / agent --server/ && !/sh -c/ {print \$1; exit}'"; }
server_pid() { docker exec kr1 sh -c "ps -eo pid=,ppid=,args= | awk '\$2 != 1 && / server --data/ && !/sh -c/ {print \$1; exit}'"; }
start_agent() { docker exec -d kr2 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store ${1:-/krbin/kr} agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.$2.log 2>&1"; }
start_server() { docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store ${1:-/krbin/kr} server --data /var/tmp/srv > /tmp/srv.$2.log 2>&1"; }
pods_kr2() { $KC get pods -o wide --no-headers | awk '$7=="kr2" && $3!="Completed" {print $1,$4,$6}' | sort; }
procs() { docker exec "$1" sh -c "ps -eo args= | grep -c '^sleep $2\$'"; }

mk() { # name sleep
cat <<Y
apiVersion: v1
kind: Pod
metadata: {name: $1}
spec:
  nodeName: kr2
  containers: [{name: c, image: alpine:3.20, command: [sleep, "$2"]}]
Y
}
for i in 1 2 3; do mk base$i 3601; echo ---; done | $KC apply -f - >/dev/null
check "base pods running" waitfor 60 bash -c "[ \$($KC get pods --no-headers | grep -c '1/1 *Running') = 3 ]"
BASE=$(pods_kr2)

echo "== 1. binary swap with a graceful stop"
docker exec kr2 cp /krbin/kr /tmp/kr-next; docker exec kr1 cp /krbin/kr /tmp/kr-next
docker exec kr2 kill -TERM $(agent_pid); sleep 2
start_agent /tmp/kr-next 2; sleep 12
eq "agent: SIGTERM + new binary keeps pods, IPs, restart counts" "$(pods_kr2)" "$BASE"
eq "agent: no duplicate processes" "$(procs kr2 3601)" 3
docker exec kr2 grep -q "adopted 3 pods" /tmp/agent.2.log && ok "agent: reports the adopted pods" || bad "agent: reports the adopted pods"
docker exec kr1 kill -TERM $(server_pid); sleep 3
start_server /tmp/kr-next 2
check "server: API back after the swap" waitfor 40 $KC get --raw /healthz
sleep 10
eq "server: pods of the node kept" "$(pods_kr2)" "$BASE"

echo "== 2. a shim is killed"
SHIM=$(docker exec kr2 sh -c "ps -eo pid=,args= | awk '/kr shim/ && !/awk/ {print \$1; exit}'")
docker exec kr2 kill -9 $SHIM; sleep 15
R=$($KC get pods --no-headers | awk '{s+=$4} END{print s}')
eq "killed shim: its container is restarted (once), the others untouched" "$R" 1
eq "killed shim: no leftover process" "$(procs kr2 3601)" 3
eq "killed shim: all pods have shims again" "$(docker exec kr2 sh -c "ps -eo args= | grep -c '^kr shim'")" 3

echo "== 3. records of a previous boot (recycled pids)"
BASE=$(pods_kr2)
AP=$(agent_pid); [ -n "$AP" ] || bad "stale records: found the agent"; docker exec kr2 kill -9 $AP; sleep 1
# make every record claim a different start time, as after a reboot where the pids are reused
docker exec kr2 sh -c 'for f in /store/pods/*/.adopt; do awk "BEGIN{OFS=\" \"} \$1==\"sb\"{\$3=\$3+1} \$1==\"c\"{\$4=\$4+1} {print}" $f > $f.n && mv $f.n $f; done'
start_agent /krbin/kr 3; sleep 25
check "stale records: pods are running again" waitfor 30 bash -c "[ \$($KC get pods --no-headers | grep -c '1/1 *Running') = 3 ]"
eq "stale records: exactly one process per pod (old ones killed)" "$(procs kr2 3601)" 3

echo "== 4. crash loop"
BASE=$(pods_kr2)
for i in 1 2 3 4 5; do AP=$(agent_pid); [ -n "$AP" ] || bad "crash loop $i: found the agent"; docker exec kr2 kill -9 $AP; sleep 1; start_agent /krbin/kr loop$i; sleep 5; done
sleep 10
eq "5 crashes in a row: same pods, IPs and restart counts" "$(pods_kr2)" "$BASE"

echo "== 5. crash while pods are being created"
for i in $(seq 1 12); do mk burst$i 3602; echo ---; done | $KC apply -f - >/dev/null
sleep 2; AP=$(agent_pid); [ -n "$AP" ] || bad "burst: found the agent"; docker exec kr2 kill -9 $AP; sleep 1; start_agent /krbin/kr burst
check "burst: all 12 pods running" waitfor 60 bash -c "[ \$($KC get pods --no-headers | grep -c 'burst.*1/1 *Running') = 12 ]"
sleep 5
eq "burst: one process per pod (no duplicates or orphans)" "$(procs kr2 3602)" 12
eq "burst: one sandbox per pod" "$(docker exec kr2 sh -c "ps -eo args= | grep -c '^kr pause'")" 15
eq "burst: one IP lease per pod" "$(docker exec kr2 sh -c 'ls /store/ipam | wc -l')" 15

echo "== 6. a second agent on the same root"
docker exec kr2 sh -c "KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/second.log 2>&1; echo exit=\$? >> /tmp/second.log"
docker exec kr2 grep -q "already runs the pods" /tmp/second.log && ok "second agent refuses to run" || { bad "second agent refuses to run"; docker exec kr2 tail -3 /tmp/second.log; }
eq "second agent changed nothing" "$(procs kr2 3601)" 3

docker rm -f kr1 kr2 >/dev/null 2>&1
echo; [ $fails = 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
exit $((fails>0))

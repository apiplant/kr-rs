#!/usr/bin/env bash
# Scale and soak for pods surviving the kubelet process (ADR-036), root mode: 200 pods on one
# node, pod churn, and a kill -9 of the agent every minute for SOAK_MIN minutes (default 8).
# Afterwards nothing may have leaked (processes, sandboxes, IP leases, descriptors, memory).
set -u
cd "$(dirname "$0")/../.."
SOAK_MIN=${SOAK_MIN:-8}
PODS=${PODS:-100}   # a node advertises 110 pods; PODS=200 SOAK_MIN=0 checks adoption of 200 (beyond that)
fails=0
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1"; fails=$((fails+1)); }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
KC="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
KR_STORE_SIZE=6g tools/test/two-node.sh up >/dev/null
MIRRORS=$(tools/test/registry-cache.sh env krnet)
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
agent_pid() { docker exec kr2 sh -c "ps -eo pid=,ppid=,args= | awk '\$2 != 1 && / agent --server/ && !/sh -c/ {print \$1; exit}'"; }
start_agent() { docker exec -d kr2 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.$1.log 2>&1"; }
n_running() { $KC get pods --no-headers -l soak=1 2>/dev/null | grep -c '1/1 *Running'; }
waitn() { for _ in $(seq 240); do [ "$(n_running)" = "$1" ] && return 0; sleep 2; done; return 1; }
gen() { # prefix count
  for i in $(seq 1 "$2"); do
    printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: %s%s, labels: {soak: "1", gen: "%s"}}\nspec:\n  nodeName: kr2\n  terminationGracePeriodSeconds: 1\n  containers: [{name: c, image: alpine:3.20, command: [sleep, "86400"]}]\n---\n' "$1" "$i" "${1%-}"
  done
}
stats() { # label
  local ap; ap=$(agent_pid)
  docker exec kr2 sh -c "
    ap=$ap
    rss=\$(awk '/VmRSS/{print \$2}' /proc/\$ap/status); fds=\$(ls /proc/\$ap/fd | wc -l)
    shims=\$(ps -eo args= | grep -c '^kr shim'); shim_kb=\$(for p in \$(pgrep -f '^kr shim'); do awk '/VmRSS/{print \$2}' /proc/\$p/status; done | awk '{s+=\$1} END{print s+0}')
    echo \"$1: agent rss=\${rss}kB fds=\$fds | shims=\$shims (\${shim_kb}kB total) | sleeps=\$(ps -eo args= | grep -c '^sleep 86400\$') pauses=\$(ps -eo args= | grep -c '^kr pause') leases=\$(ls /store/ipam | wc -l) poddirs=\$(ls /store/pods | wc -l) exitfiles=\$(ls /store/pods/*/*.exit 2>/dev/null | wc -l) containers=\$(ls /store/containers | wc -l)\""
}
field() { stats x | sed -n "s/.*$1=\([0-9]*\).*/\1/p" | head -1; }

echo "== $PODS pods on one node"
T0=$(date +%s)
gen a "$PODS" | $KC apply -f - >/dev/null
waitn "$PODS" && ok "$PODS pods running after $(( $(date +%s)-T0 ))s" || bad "$PODS pods running ($(n_running))"
sleep 5
stats "after start"
RSS0=$(field "agent rss"); FDS0=$(field fds)

echo "== kill -9 of the agent with $PODS pods"
BEFORE=$($KC get pods -l soak=1 --no-headers -o wide | awk '{print $1,$4,$6}' | sort | md5sum)
T1=$(date +%s); docker exec kr2 kill -9 "$(agent_pid)"; start_agent 0
for _ in $(seq 120); do docker exec kr2 grep -q "adopted" /tmp/agent.0.log 2>/dev/null && break; sleep 1; done
echo "   adopted line after $(( $(date +%s)-T1 ))s: $(docker exec kr2 grep adopted /tmp/agent.0.log)"
sleep 10
eq "all pods kept their IPs and restart counts" "$($KC get pods -l soak=1 --no-headers -o wide | awk '{print $1,$4,$6}' | sort | md5sum)" "$BEFORE"
eq "one process per pod" "$(docker exec kr2 sh -c "ps -eo args= | grep -c '^sleep 86400\$'")" "$PODS"

echo "== churn + a crash every minute for ${SOAK_MIN} min"
SKIP_CHURN=0; [ "$SOAK_MIN" = 0 ] && SKIP_CHURN=1
END=$(( $(date +%s) + SOAK_MIN*60 )); round=0; NEXT_CRASH=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$END" ]; do
  round=$((round+1))
  # replace half of the pods
  $KC delete pods -l soak=1,gen=a --wait=false >/dev/null 2>&1 | head -0
  gen "g${round}-" "$((PODS/2))" | $KC apply -f - >/dev/null
  if [ "$(date +%s)" -ge "$NEXT_CRASH" ]; then
    docker exec kr2 kill -9 "$(agent_pid)"; start_agent "r$round"; NEXT_CRASH=$(( $(date +%s) + 60 )); echo "   round $round: agent crashed"
  fi
  sleep 20
  # drop the oldest generation so the total stays bounded
  OLD=$($KC get pods -l soak=1 --no-headers 2>/dev/null | wc -l)
  [ "$OLD" -gt "$PODS" ] && $KC get pods -l soak=1 --no-headers -o custom-columns=N:.metadata.name,T:.metadata.creationTimestamp --sort-by=.metadata.creationTimestamp | head -n "$((OLD-PODS))" | awk '{print $1}' | xargs -r $KC delete pod --wait=false >/dev/null 2>&1
done
echo "== end of churn (steady $PODS pods again)"
# stop the churn; let pods that are still terminating go, then measure at the same load as the start
for _ in $(seq 60); do [ "$($KC get pods -l soak=1 --no-headers 2>/dev/null | wc -l)" = "$PODS" ] && break; sleep 3; done
sleep 30
stats "end of churn"
RSS1=$(field "agent rss"); FDS1=$(field fds)
[ "$FDS1" -le "$((FDS0+30))" ] && ok "agent descriptors did not grow ($FDS0 -> $FDS1)" || bad "agent descriptors grew ($FDS0 -> $FDS1)"
[ "$RSS1" -le "$((RSS0*3/2))" ] && ok "agent memory grew less than 50% ($RSS0 -> $RSS1 kB)" || bad "agent memory grew ($RSS0 -> $RSS1 kB)"
[ "$($KC get pods -l soak=1 --no-headers | grep -c '1/1 *Running')" -ge "$((PODS-20))" ] && ok "churn kept about $PODS pods running" || bad "churn left too few pods running"
N=$($KC get pods -l soak=1 --no-headers | wc -l)
IPS=$($KC get pods -l soak=1 -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}')
eq "every pod has an IP" "$(echo "$IPS" | grep -c .)" "$N"
eq "pod IPs are unique" "$(echo "$IPS" | sort | uniq -d | wc -l)" 0
eq "one process per pod after the churn" "$(field sleeps)" "$($KC get pods -l soak=1 --no-headers | wc -l)"
eq "one sandbox per pod after the churn" "$(field pauses)" "$($KC get pods -l soak=1 --no-headers | wc -l)"
eq "one IP lease per pod after the churn" "$(field leases)" "$($KC get pods -l soak=1 --no-headers | wc -l)"
eq "one pod directory per pod after the churn" "$(field poddirs)" "$($KC get pods -l soak=1 --no-headers | wc -l)"
eq "one container directory per pod after the churn" "$(field containers)" "$($KC get pods -l soak=1 --no-headers | wc -l)"
echo "== settle and account"
$KC delete pods -l soak=1 --wait=false >/dev/null 2>&1; sleep 60
for _ in $(seq 60); do [ "$($KC get pods -l soak=1 --no-headers 2>/dev/null | wc -l)" = 0 ] && break; sleep 3; done
eq "all pods gone from the API" "$($KC get pods -l soak=1 --no-headers 2>/dev/null | wc -l)" 0
stats "after soak (no pods)"
eq "no container processes left" "$(field sleeps)" 0
eq "no sandboxes left" "$(field pauses)" 0
eq "no IP leases left" "$(field leases)" 0
eq "no shims left" "$(field shims)" 0
eq "no exit files left" "$(field exitfiles)" 0
eq "no container directories left" "$(field containers)" 0
docker rm -f kr1 kr2 >/dev/null 2>&1
echo; [ $fails = 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
exit $((fails>0))

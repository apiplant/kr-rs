#!/bin/bash
# Realistic workload and node-lifecycle test on a three-node cluster (dev only, throwaway containers):
# Postgres and Redis StatefulSets on PVCs, a spread Deployment, Services/DNS/NodePort, Jobs, CronJob,
# DaemonSet, rollout/rollback, a node joining, drain, a frozen (unreachable) node with eviction, and recovery.
#   tools/test/stress.sh            # runs everything, prints PASS/FAIL per check, exits non-zero on failure
#   KR_SKIP_EVICT=1 tools/test/stress.sh   # skip the 5-minute wait for pod eviction from the frozen node
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
D=$REPO/tools/test/stress
fails=0
k() { docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl "$@"; }
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1"; fails=$((fails+1)); }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
waitfor() { local t=$1; shift; for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
running() { [ "$(k -n apps get pods "${@:2}" --no-headers 2>/dev/null | grep -c '1/1 *Running')" -ge "$1" ]; }

"$REPO/tools/test/two-node.sh" up >/dev/null
docker rm -f kr3 >/dev/null 2>&1
docker run -d --name kr3 --hostname kr3 --network krnet --privileged --tmpfs /store:exec,size=${KR_STORE_SIZE:-2g} \
  -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" archlinux:base-devel sleep infinity >/dev/null
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
docker exec kr3 sh -c "umask 077; echo '$(docker exec kr1 cat /var/tmp/srv/node-token)' > /root/kr-token"
docker exec -d kr3 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) KR_ROOT=/store /krbin/kr agent --server https://$IP1:6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
check "third node joins" waitfor 30 bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get nodes --no-headers | grep -q 'kr3 *Ready'"

k apply -f - < "$D/apps.yaml" >/dev/null
check "apps running (pg, redis, 6 web)" waitfor 150 running 8
check "secret stringData folded into data" bash -c "[ -n \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get secret pg -o jsonpath='{.data.POSTGRES_PASSWORD}')\" ]"
check "pvcs bound" bash -c "[ \$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pvc -o jsonpath='{.items[*].status.phase}' | wc -w) = 2 ]"
check "postgres write" k -n apps exec pg-0 -- psql -U postgres -c "create table t as select g from generate_series(1,50000) g"
check "redis write" k -n apps exec redis-0 -- redis-cli set k v
k -n apps delete pod pg-0 redis-0 --wait >/dev/null
check "databases back after pod delete" waitfor 60 running 2 pg-0 redis-0
check "postgres data persisted" bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps exec pg-0 -- psql -U postgres -tAc 'select count(*) from t')\" = 50000 ]"
check "redis data persisted" bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps exec redis-0 -- redis-cli get k)\" = v ]"

for n in kr1 kr2 kr3; do k -n apps run c-$n --image=alpine:3.20 --restart=Never --overrides="{\"spec\":{\"nodeName\":\"$n\"}}" --command -- sleep 7200 >/dev/null; done
check "client pods running" waitfor 60 running 3 c-kr1 c-kr2 c-kr3
for n in kr1 kr2 kr3; do
  check "[$n] service load-balances across all web pods" bash -c "[ \$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps exec c-$n -- sh -c 'for i in \$(seq 30); do wget -qO- -T3 http://web.apps/; done' | sort -u | wc -l) = 6 ]"
  check "[$n] reaches postgres and redis by DNS" k -n apps exec c-$n -- sh -c 'nc -z -w3 pg-0.pg 5432 && nc -z -w3 redis 6379'
done
for n in kr1 kr2 kr3; do
  ip=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' $n)
  check "NodePort on $n" docker exec kr2 sh -c "curl -s -m3 http://$ip:30080/ | grep -q hello"
done

k apply -f - < "$D/controllers.yaml" >/dev/null
check "job completes (6/6)" waitfor 60 bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get job pi -o jsonpath='{.status.succeeded}')\" = 6 ]"
check "daemonset on every node" waitfor 60 bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get ds ds -o jsonpath='{.status.numberReady}')\" = 3 ]"
check "multi-container pod with init + emptyDir" waitfor 60 bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pod multi --no-headers | grep -q ' 2/2 *Running'"
check "rolling update" bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 sh -c 'kubectl -n apps set image deploy/web nginx=nginx:1.27-alpine && kubectl -n apps rollout status deploy/web --timeout=150s'"
check "rollback" bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 sh -c 'kubectl -n apps rollout undo deploy/web && kubectl -n apps rollout status deploy/web --timeout=150s'"
k -n apps scale deploy web --replicas=15 >/dev/null
check "scale to 15, spread over 3 nodes" waitfor 60 bash -c "[ \$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pods -l app=web -o jsonpath='{range .items[*]}{.spec.nodeName}{\"\\n\"}{end}' | sort -u | wc -l) = 3 ]"

check "web fully ready before drain" waitfor 60 bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get deploy web -o jsonpath='{.status.readyReplicas}')\" = 15 ]"
k drain kr3 --ignore-daemonsets --delete-emptydir-data --force --timeout=120s >/dev/null 2>&1
check "drain leaves no web pods on kr3" bash -c "! docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pods -o wide --no-headers | grep -q 'web.*kr3'"
k uncordon kr3 >/dev/null

# --- unreachable node ---
docker pause kr3 >/dev/null
check "frozen node goes NotReady within ~60s" waitfor 30 bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get node kr3 --no-headers | grep -q NotReady"
check "unreachable NoExecute taint" bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl get node kr3 -o jsonpath='{.spec.taints[*].effect}' | grep -q NoExecute"
k -n apps run victim --image=alpine:3.20 --restart=Never --overrides='{"spec":{"nodeName":"kr3"}}' --command -- sleep 7200 >/dev/null 2>&1
if [ -z "${KR_SKIP_EVICT:-}" ]; then
  check "pods of the dead node are evicted after 300s" waitfor 160 bash -c "! docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pod victim --no-headers 2>/dev/null | grep -qv Terminating"
fi
docker unpause kr3 >/dev/null
check "node recovers (Ready, taints removed)" waitfor 40 bash -c "docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 sh -c 'kubectl get node kr3 --no-headers | grep -q \" Ready\" && [ -z \"\$(kubectl get node kr3 -o jsonpath={.spec.taints})\" ]'"
check "all web pods Ready again" waitfor 60 bash -c "[ \"\$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get deploy web -o jsonpath='{.status.readyReplicas}')\" = 15 ]"
check "postgres still serves" k -n apps exec pg-0 -- psql -U postgres -tAc "select count(*) from t"

# --- pods survive a crash of the agent / server process ---
KC="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
KCI="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"   # with stdin, for attach -i
pidof_kr() { docker exec "$1" sh -c "ps -eo pid=,ppid=,args= | awk '\$2 != 1 && /krbin\/kr $2/ && !/sh -c/ {print \$1; exit}'"; }
pod_ips() { $KC -n apps get pods -o wide --no-headers | grep " $1 " | grep -v Succeeded | awk '{print $1,$4,$6}' | sort; }
k -n apps exec redis-0 -- redis-cli set survivor 42 >/dev/null
k -n apps apply -f - < "$D/shim.yaml" >/dev/null
check "shim pods running (exit0, exit3, tty, stdin)" waitfor 60 bash -c "[ \$(docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl -n apps get pods exit0 exit3 ttyp stdinp --no-headers | grep -c '1/1 *Running') = 4 ]"
echo one | /usr/bin/timeout 8 $KCI -n apps attach -i stdinp >/dev/null 2>&1
BEFORE=$(pod_ips kr2 | grep -v -E '^exit')
docker exec kr2 kill -9 $(pidof_kr kr2 agent)
sleep 55   # exit0 and exit3 end while the agent is down
IPK=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1)
docker exec -d kr2 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) KR_ROOT=/store /krbin/kr agent --server https://$IPK:6443 --token-file /root/kr-token > /tmp/agent2.log 2>&1"
sleep 20
AFTER=$(pod_ips kr2 | grep -v -E '^exit')
[ "$BEFORE" = "$AFTER" ] && ok "agent kill -9: same pods, restart counts and IPs on kr2" || { bad "agent kill -9: same pods, restart counts and IPs on kr2"; echo "$BEFORE" "---" "$AFTER"; }
[ "$($KC -n apps get pod exit0 -o jsonpath='{.status.phase} {.status.containerStatuses[0].state.terminated.exitCode}')" = "Succeeded 0" ] && ok "agent kill -9: exit 0 during the outage is kept" || bad "agent kill -9: exit 0 during the outage is kept"
[ "$($KC -n apps get pod exit3 -o jsonpath='{.status.phase} {.status.containerStatuses[0].state.terminated.exitCode}')" = "Failed 3" ] && ok "agent kill -9: exit 3 during the outage is kept" || bad "agent kill -9: exit 3 during the outage is kept"
[ "$($KC -n apps logs ttyp | tr -d '\r' | awk -F- '{print $2}' | awk 'NR>1 && $1!=p+1 {g=1} {p=$1} END{print g?"gap":"none"}')" = none ] && ok "agent kill -9: terminal log has no gap" || bad "agent kill -9: terminal log has no gap"
echo two | /usr/bin/timeout 8 $KCI -n apps attach -i stdinp >/dev/null 2>&1
[ "$($KC -n apps logs stdinp | grep -c '^got:')" = 2 ] && ok "agent kill -9: attach -i works again" || bad "agent kill -9: attach -i works again"
[ "$($KC -n apps exec redis-0 -- redis-cli get survivor)" = 42 ] && ok "agent kill -9: redis data intact" || bad "agent kill -9: redis data intact"
PGPID=$(docker exec kr1 pgrep -x postgres | head -1)
docker exec kr1 kill -9 $(pidof_kr kr1 server)
docker exec -d kr1 sh -c "KR_REGISTRY_MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet) KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv2.log 2>&1"
check "server kill -9: API back" waitfor 40 $KC get --raw /healthz
sleep 15
[ "$PGPID" = "$(docker exec kr1 pgrep -x postgres | head -1)" ] && ok "server kill -9: postgres is the same process" || bad "server kill -9: postgres is the same process"
check "server kill -9: postgres still serves" k -n apps exec pg-0 -- psql -U postgres -tAc "select count(*) from t"

echo; [ $fails = 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
exit $((fails>0))

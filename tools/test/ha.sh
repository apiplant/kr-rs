#!/bin/bash
# HA cluster test (ADR-026): servers krs1..krs3 (Raft) + agent kra1 in throwaway privileged
# containers (dev only). Checks joining, replication, write forwarding from followers,
# leader failover after kill -9, restart catch-up and server removal.
#   tools/test/ha.sh [up|test|import|down]   (default: up + test; leaves the cluster running)
#   import: a single-server install converted with --cluster-init, a second server joins
#           (InstallSnapshot), then the first restarts and must reach its peer (2 voters).
# Then: docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krs1 kubectl get nodes
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
SERVERS="krs1 krs2 krs3"
KC="-e KUBECONFIG=/var/tmp/srv/admin.kubeconfig"
k() { local n=$1; shift; docker exec $KC "$n" kubectl "$@"; }
ip() { docker inspect -f '{{.NetworkSettings.Networks.krha.IPAddress}}' "$1"; }
start() { # name, extra args
  local n=$1; shift
  docker exec -d "$n" sh -c "KR_ROOT=/store /krbin/kr server --data /var/tmp/srv $* >> /tmp/srv.log 2>&1"
}
wait_api() { for _ in $(seq 60); do k "$1" get --raw /healthz >/dev/null 2>&1 && return 0; sleep 1; done; echo "API on $1 not up"; return 1; }
fail() { echo "FAIL: $*"; for n in $SERVERS; do echo "== $n"; docker exec "$n" tail -20 /tmp/srv.log || true; done; exit 1; }
voters() { k "$1" get --raw /kr/debug/raft 2>/dev/null || true; }

down() {
  docker rm -f $SERVERS kra1 >/dev/null 2>&1 || true
  docker network rm krha >/dev/null 2>&1 || true
}

up() {
  down
  docker network create krha >/dev/null
  for n in $SERVERS kra1; do
    docker run -d --name $n --hostname $n --network krha --privileged --tmpfs /store:exec,size=2g \
      -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
      archlinux:base-devel sleep infinity >/dev/null
  done
  start krs1 --cluster-init
  wait_api krs1
  TOKEN=$(docker exec krs1 cat /var/tmp/srv/server-token)
  for n in krs2 krs3; do
    docker exec "$n" sh -c "umask 077; echo '$TOKEN' > /root/server-token"
    start "$n" --server "https://$(ip krs1):6443" --token-file /root/server-token
    wait_api "$n"
    for _ in $(seq 60); do docker exec "$n" grep -q "joined as voter" /tmp/srv.log && break; sleep 1; done
    docker exec "$n" grep -q "joined as voter" /tmp/srv.log || fail "$n did not become a voter"
  done
  NTOKEN=$(docker exec krs1 cat /var/tmp/srv/node-token)
  docker exec kra1 sh -c "umask 077; echo '$NTOKEN' > /root/kr-token"
  docker exec -d kra1 sh -c "KR_ROOT=/store /krbin/kr agent --server https://$(ip krs2):6443 --token-file /root/kr-token > /tmp/agent.log 2>&1"
  for _ in $(seq 90); do
    [ "$(k krs1 get nodes --no-headers 2>/dev/null | grep -c ' Ready')" = 4 ] && break; sleep 1
  done
  k krs1 get nodes
  [ "$(k krs1 get nodes --no-headers | grep -c ' Ready')" = 4 ] || fail "not all nodes Ready"
}

# The server whose log says it leads (latest "leader" line wins), via the debug endpoint.
leader() {
  for n in $SERVERS; do
    docker exec "$n" pgrep -x kr >/dev/null 2>&1 || continue
    k "$n" get --raw /kr/debug/raft 2>/dev/null | grep -q 'role=Leader' && { echo "$n"; return; }
  done
}

test_() {
  # Every server serves the same data; writes on any server (followers forward).
  for n in $SERVERS; do k "$n" create configmap "from-$n" --from-literal=a=b >/dev/null || fail "write on $n"; done
  for n in $SERVERS; do
    for m in $SERVERS; do k "$n" get configmap "from-$m" >/dev/null || fail "$n lacks from-$m"; done
  done
  # The kubernetes Service has all three servers as endpoints.
  [ "$(k krs1 get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[*].ip}' | wc -w)" = 3 ] || fail "endpoints"
  # Workloads run (controllers + scheduler on the leader only).
  k krs2 create deployment web --image=busybox --replicas=4 -- sleep 3600 >/dev/null
  for _ in $(seq 90); do [ "$(k krs3 get pods -l app=web --no-headers 2>/dev/null | grep -c Running)" = 4 ] && break; sleep 1; done
  [ "$(k krs3 get pods -l app=web --no-headers | grep -c Running)" = 4 ] || fail "deployment did not come up"

  L=$(leader); [ -n "$L" ] || fail "no leader"
  echo "leader: $L; kill -9"
  docker exec "$L" pkill -9 -x kr
  OTHER=$(for n in $SERVERS; do [ "$n" != "$L" ] && echo "$n"; done | head -1)
  for _ in $(seq 30); do k "$OTHER" create configmap after-failover --from-literal=x=y >/dev/null 2>&1 && break; sleep 1; done
  k "$OTHER" get configmap after-failover >/dev/null || fail "no writes after the leader died"
  NL=$(leader); [ -n "$NL" ] && [ "$NL" != "$L" ] || fail "no new leader"
  echo "new leader: $NL"
  # The scheduler and controllers moved: scaling still works.
  k "$OTHER" scale deployment web --replicas=5 >/dev/null
  for _ in $(seq 90); do [ "$(k "$OTHER" get pods -l app=web --no-headers 2>/dev/null | grep -c Running)" -ge 5 ] && break; sleep 1; done
  [ "$(k "$OTHER" get pods -l app=web --no-headers | grep -c Running)" -ge 5 ] || fail "controllers did not move to the new leader"

  # The old leader restarts from its disk and catches up.
  start "$L"
  wait_api "$L"
  for _ in $(seq 30); do k "$L" get configmap after-failover >/dev/null 2>&1 && break; sleep 1; done
  k "$L" get configmap after-failover >/dev/null || fail "$L did not catch up"
  for n in $SERVERS; do
    echo "$n: $(k "$n" get configmaps -o jsonpath='{.metadata.resourceVersion}') $(k "$n" get configmaps --no-headers | wc -l) configmaps"
  done
  A=$(k krs1 get configmaps -A -o jsonpath='{range .items[*]}{.metadata.uid}{.metadata.resourceVersion}{end}')
  for n in krs2 krs3; do
    [ "$(k "$n" get configmaps -A -o jsonpath='{range .items[*]}{.metadata.uid}{.metadata.resourceVersion}{end}')" = "$A" ] || fail "$n diverged"
  done
  # The agent's server (krs2) dies: the agent fails over to another server from the
  # kubernetes endpoints and keeps renewing its node lease.
  R0=$(k krs1 get lease -n kube-node-lease kra1 -o jsonpath='{.spec.renewTime}')
  docker exec krs2 pkill -9 -x kr
  sleep 25
  R1=$(k krs1 get lease -n kube-node-lease kra1 -o jsonpath='{.spec.renewTime}')
  [ "$R0" != "$R1" ] || fail "agent did not fail over (lease $R0 not renewed)"
  echo "agent failed over: lease $R0 -> $R1"
  # ...and restarts while its --server is still down (saved server list).
  docker exec kra1 pkill -9 -x kr; sleep 1
  docker exec -d kra1 sh -c "KR_ROOT=/store /krbin/kr agent --server https://$(ip krs2):6443 >> /tmp/agent.log 2>&1"
  sleep 40
  R2=$(k krs1 get lease -n kube-node-lease kra1 -o jsonpath='{.spec.renewTime}')
  [ "$R2" != "$R1" ] || fail "restarted agent did not reach another server"
  start krs2; wait_api krs2
  # Remove a server (retried: removing the leader first hands leadership over).
  ID3=$(docker exec krs3 cat /var/tmp/srv/server-id)
  docker exec $KC krs1 sh -c "echo '{\"id\":$ID3}' > /tmp/rm.json"
  for _ in $(seq 10); do k krs1 create --raw /kr/remove-server -f /tmp/rm.json >/dev/null 2>&1 && break; sleep 2; done
  k krs1 get --raw /kr/debug/raft | grep -q "voters=\[.*$ID3" && fail "krs3 still a voter"
  docker exec krs3 pkill -9 -x kr || true
  k krs1 create configmap after-remove >/dev/null || fail "no writes after removing a server"
  [ "$(k krs2 get endpoints kubernetes -o jsonpath='{.subsets[0].addresses[*].ip}' | wc -w)" = 2 ] || fail "endpoints after removal"
  echo "PASS"
}

import_() {
  down
  docker network create krha >/dev/null
  for n in krs1 krs2; do
    docker run -d --name $n --hostname $n --network krha --privileged --tmpfs /store:exec,size=2g \
      -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
      archlinux:base-devel sleep infinity >/dev/null
  done
  start krs1; wait_api krs1
  k krs1 create configmap legacy --from-literal=a=b >/dev/null
  WANT=$(k krs1 get configmap legacy -o jsonpath='{.metadata.uid}/{.metadata.resourceVersion}')
  docker exec krs1 pkill -x kr; sleep 2
  start krs1 --cluster-init; wait_api krs1
  docker exec krs1 grep -q "imported the single-server datastore" /tmp/srv.log || fail "no import"
  [ "$(k krs1 get configmap legacy -o jsonpath='{.metadata.uid}/{.metadata.resourceVersion}')" = "$WANT" ] || fail "legacy object changed"
  k krs1 create configmap after-import >/dev/null
  TOKEN=$(docker exec krs1 cat /var/tmp/srv/server-token)
  docker exec krs2 sh -c "umask 077; echo '$TOKEN' > /root/server-token"
  start krs2 --server "https://$(ip krs1):6443" --token-file /root/server-token; wait_api krs2
  for _ in $(seq 60); do docker exec krs2 grep -q "joined as voter" /tmp/srv.log && break; sleep 1; done
  for _ in $(seq 30); do k krs2 get configmap legacy after-import >/dev/null 2>&1 && break; sleep 1; done
  k krs2 get configmap legacy after-import >/dev/null || fail "krs2 did not get the snapshot"
  # Two voters: the restarted server is needed for quorum and must find krs2 on its own.
  docker exec krs1 pkill -9 -x kr; sleep 1
  start krs1; wait_api krs1
  for _ in $(seq 30); do k krs1 get configmap after-import >/dev/null 2>&1 && break; sleep 1; done
  k krs1 get configmap after-import >/dev/null || fail "krs1 did not recover after restart"
  for _ in $(seq 30); do k krs1 create configmap after-restart >/dev/null 2>&1 && break; sleep 1; done
  k krs2 get configmap after-restart >/dev/null || fail "no quorum after restart"
  echo "PASS (import)"
}

case "${1:-all}" in
  up) up ;;
  test) test_ ;;
  import) import_ ;;
  down) down ;;
  all) up; test_ ;;
esac

#!/bin/bash
# tools/upgrade/kr-upgrade.sh for real (#179): server kru1 + agent kru2 in throwaway privileged
# containers (dev only), upgraded in place with --no-drain to a binary that differs from the
# running one. Checks the script's health check (new process on the new binary, Lease renewed),
# that pods keep their container processes (ADR-036), and that a restart that does nothing is
# reported as a failure instead of passing on the stale Ready condition.
#   tools/test/upgrade.sh [down]     (needs target/release/kr)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
N="kru1 kru2"
docker rm -f $N >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 2; done; return 1; }
for n in $N; do
  docker run -d --init --name $n --hostname $n --network krnet --privileged --tmpfs /store:exec,size=2g \
    -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
  docker exec $n cp /krbin/kr /usr/local/bin/kr
done
# A "service" without systemd: the pid file is the main process, restart = kill + start.
cat > "$W/svc" <<'S'
#!/bin/sh
# svc start|restart|noop ROLE ARGS...
cmd=$1; shift
case $cmd in
  noop) exit 0 ;;
  restart) kill "$(cat /tmp/kr.pid)" 2>/dev/null; while kill -0 "$(cat /tmp/kr.pid)" 2>/dev/null; do sleep 0.2; done ;;
esac
setsid sh -c 'echo $$ > /tmp/kr.pid; exec /usr/local/bin/kr "$@" >> /tmp/kr.log 2>&1' kr "$@" < /dev/null &
S
chmod +x "$W/svc"
for n in $N; do docker cp "$W/svc" $n:/usr/local/bin/svc >/dev/null; done
docker exec kru1 sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store svc start server --data /var/tmp/srv"
waitfor "docker exec kru1 test -f /var/tmp/srv/admin.kubeconfig" 30
IP1=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kru1)
docker cp kru1:/var/tmp/srv/admin.kubeconfig "$W/kc" >/dev/null
sed -i "s|server: https://[^:]*:|server: https://$IP1:|" "$W/kc"
export KUBECONFIG=$W/kc
waitfor "kubectl get --raw /healthz >/dev/null 2>&1" 30
TOKEN=$(docker exec kru1 cat /var/tmp/srv/node-token)
docker exec kru2 sh -c "umask 077; echo '$TOKEN' > /root/kr-token; KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store svc start agent --server https://$IP1:6443 --token-file /root/kr-token"
waitfor '[ "$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready")" = 2 ]' 45
for n in $N; do kubectl run "p-$n" --image=busybox:1.36 --overrides="{\"spec\":{\"nodeName\":\"$n\"}}" -- sleep 3600 >/dev/null; done
waitfor '[ "$(kubectl get pods --no-headers | grep -c Running)" = 2 ]' 60
before() { docker exec "$1" pgrep -n -f 'sleep 3600'; }
P1=$(before kru1); P2=$(before kru2)
# ssh/scp stand-ins: "ssh NODE CMD" and "scp LOCAL NODE:PATH".
printf '#!/bin/sh\nn=$1; shift; exec docker exec -i "$n" sh -c "$*"\n' > "$W/ssh"
printf '#!/bin/sh\nexec docker cp "$1" "$2"\n' > "$W/scp"
chmod +x "$W/ssh" "$W/scp"
cp "$REPO/target/release/kr" "$W/kr-new"; printf 'x' >> "$W/kr-new"   # differs, still runs
UP="$REPO/tools/upgrade/kr-upgrade.sh --no-drain --ssh $W/ssh --scp $W/scp --dest /usr/local/bin/kr --pid-cmd 'cat /tmp/kr.pid' --timeout 90"

# Node by node, with the role's arguments for the restart.
eval "$UP --restart 'KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store svc restart server --data /var/tmp/srv' '$W/kr-new' kru1" > "$W/up1.log" 2>&1
check "server upgraded (script succeeded)" "grep -q 'kru1 upgraded' '$W/up1.log'"
check "health check saw the new process on the new binary" "grep -q 'runs the new binary' '$W/up1.log'"
check "health check saw a Lease renewal from it" "grep -q 'lease renewed' '$W/up1.log'"
eval "$UP --restart 'KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store svc restart agent --server https://$IP1:6443 --token-file /root/kr-token' '$W/kr-new' kru2" > "$W/up2.log" 2>&1
check "agent upgraded (script succeeded)" "grep -q 'kru2 upgraded' '$W/up2.log'"
for n in $N; do check "$n runs the new binary" "[ \"\$(docker exec $n sh -c 'sha256sum /proc/\$(cat /tmp/kr.pid)/exe' | cut -d' ' -f1)\" = \"\$(sha256sum $W/kr-new | cut -d' ' -f1)\" ]"; done
check "pod on the server node kept its process" "[ \"\$(before kru1)\" = '$P1' ]"
check "pod on the agent kept its process" "[ \"\$(before kru2)\" = '$P2' ]"
check "nodes uncordoned and Ready" "[ \"\$(kubectl get nodes --no-headers | grep -c ' Ready ')\" = 2 ] && ! kubectl get nodes | grep -q SchedulingDisabled"
# A restart command that does nothing must fail the health check (Ready alone would pass).
cp "$W/kr-new" "$W/kr-newer"; printf 'y' >> "$W/kr-newer"
eval "$REPO/tools/upgrade/kr-upgrade.sh --no-drain --ssh $W/ssh --scp $W/scp --dest /usr/local/bin/kr --pid-cmd 'cat /tmp/kr.pid' --timeout 20 --restart 'svc noop' '$W/kr-newer' kru2" > "$W/up3.log" 2>&1
check "a restart that did nothing is reported as a failure" "! grep -q 'kru2 upgraded' '$W/up3.log' && grep -q 'no new kr process' '$W/up3.log'"
[ $FAIL = 0 ] && { echo PASS; docker rm -f $N >/dev/null; } || { echo "FAILED (left running; $0 down)"; for f in "$W"/up*.log; do echo "== $f"; tail -5 "$f"; done; exit 1; }

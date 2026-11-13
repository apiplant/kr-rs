#!/bin/bash
# Rolling upgrade of kr nodes, one at a time (docs/UPGRADING.md): cordon, drain, replace the
# binary, restart the service, wait for Ready, uncordon.
#
#   tools/upgrade/kr-upgrade.sh [options] NEW-KR-BINARY [NODE...]
#
# Without NODE arguments every node of the cluster is upgraded, control-plane nodes first.
# Run it from a machine outside the cluster (the API may restart while a server is upgraded).
# Needs kubectl (KUBECONFIG) and ssh/scp access to every node.
#
# Options (or environment):
#   --no-drain        only cordon, do not drain (KR_UPGRADE_DRAIN=0). Safe once the nodes run a
#                     build with ADR-036 (pods survive the restart); the FIRST upgrade onto such a
#                     build must drain, because older builds kill their pods with the process.
#   --first-upgrade   accepted for clarity: draining is the default
#   --ssh CMD         how to reach a node; the node name and the remote command are appended
#                     (default "ssh", e.g. --ssh "ssh -i key -l root", KR_UPGRADE_SSH)
#   --scp CMD         how to copy the binary: CMD LOCAL NODE:REMOTE (default "scp", KR_UPGRADE_SCP)
#   --dest PATH       binary path on the node (default /usr/local/bin/kr, KR_UPGRADE_DEST)
#   --restart CMD     command run on the node to restart the service (KR_UPGRADE_RESTART);
#                     default: `systemctl restart` of whichever of kr-server / kr-agent is active
#                     on the node (an error if both or neither are)
#   --pid-cmd CMD     command run on the node that prints the main kr process id (KR_UPGRADE_PID_CMD);
#                     default: `systemctl show -p MainPID --value` of that unit
#   --timeout SEC     wait for the new process and the node after the restart (default 300)
#   --dry-run         print what would be done
# Pod-preserving upgrades need KillMode=process in the units (tools/systemd/*.service).
# Servers: in an HA cluster upgrade one server at a time (this script does) and keep a quorum;
# take `kr snapshot save` first.
set -euo pipefail

SSH=${KR_UPGRADE_SSH:-ssh}
SCP=${KR_UPGRADE_SCP:-scp}
DEST=${KR_UPGRADE_DEST:-/usr/local/bin/kr}
RESTART=${KR_UPGRADE_RESTART:-}
PIDCMD=${KR_UPGRADE_PID_CMD:-}
TIMEOUT=${KR_UPGRADE_TIMEOUT:-300}
DRAIN=${KR_UPGRADE_DRAIN:-1}
[ "$DRAIN" != 0 ] || DRAIN=
DRY=
while [ $# -gt 0 ]; do
  case $1 in
    --first-upgrade) DRAIN=1 ;;
    --no-drain) DRAIN= ;;
    --ssh) SSH=$2; shift ;;
    --scp) SCP=$2; shift ;;
    --dest) DEST=$2; shift ;;
    --restart) RESTART=$2; shift ;;
    --pid-cmd) PIDCMD=$2; shift ;;
    --timeout) TIMEOUT=$2; shift ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,/^set -e/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
  shift
done
[ $# -ge 1 ] || { echo "usage: $0 [options] NEW-KR-BINARY [NODE...]" >&2; exit 2; }
BIN=$1; shift
[ -f "$BIN" ] || { echo "$BIN: no such file" >&2; exit 2; }

run() { echo "+ $*"; [ -n "$DRY" ] || "$@"; }
# shellcheck disable=SC2086
remote() { local n=$1; shift; run $SSH "$n" "$@"; }

if [ $# -gt 0 ]; then
  NODES=("$@")
else
  # control-plane nodes (label set by kr servers) first, then the rest.
  mapfile -t NODES < <(kubectl get nodes -l node-role.kubernetes.io/control-plane -o name | sed 's|node/||'
                       kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name | sed 's|node/||')
fi
[ ${#NODES[@]} -gt 0 ] || { echo "no nodes" >&2; exit 1; }

SUM=$(sha256sum "$BIN" | cut -d' ' -f1)
# shellcheck disable=SC2086
q() { local n=$1; shift; $SSH "$n" "$@"; }   # remote query (also in a dry run)

# The kr unit active on node $1 (kr-server or kr-agent); fails unless exactly one is.
unit_of() {
  local a
  a=$(q "$1" 'for u in kr-server kr-agent; do systemctl is-active --quiet $u && echo $u; done' || true)
  [ "$(echo "$a" | grep -c .)" = 1 ] || { echo "node $1: expected exactly one active kr-server/kr-agent unit, found: ${a:-none}" >&2; return 1; }
  echo "$a"
}

# Healthy after the restart: a new main process running the new binary (the old one would show
# its replaced file as deleted), then a renewal of the node's Lease after that, and Ready.
wait_healthy() {
  local n=$1 old_pid=$2 pidcmd=$3 t=$TIMEOUT pid exe renew
  [ -z "$DRY" ] || return 0
  until pid=$(q "$n" "$pidcmd" 2>/dev/null | tr -dc 0-9) && [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$pid" != "$old_pid" ] \
        && exe=$(q "$n" "sha256sum /proc/$pid/exe 2>/dev/null" | cut -d' ' -f1) && [ "$exe" = "$SUM" ]; do
    t=$((t - 2)); [ $t -gt 0 ] || { echo "node $n: no new kr process running the new binary after ${TIMEOUT}s (pid ${pid:-?})" >&2; return 1; }
    sleep 2
  done
  echo "  new process $pid runs the new binary"
  # A renewal after this point is the new process's (the old one is gone); no clock comparison.
  local before
  before=$(kubectl get lease -n kube-node-lease "$n" -o jsonpath='{.spec.renewTime}' 2>/dev/null || true)
  until renew=$(kubectl get lease -n kube-node-lease "$n" -o jsonpath='{.spec.renewTime}' 2>/dev/null) \
        && [ -n "$renew" ] && [ "$renew" != "$before" ] \
        && [ "$(kubectl get node "$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; do
    t=$((t - 2)); [ $t -gt 0 ] || { echo "node $n: Lease not renewed by the new process, or not Ready, after ${TIMEOUT}s" >&2; return 1; }
    sleep 2
  done
  echo "  lease renewed at $renew, Ready"
}

for n in "${NODES[@]}"; do
  echo "== $n"
  restart=$RESTART pidcmd=$PIDCMD
  if [ -z "$restart" ] || [ -z "$pidcmd" ]; then
    u=$(unit_of "$n")
    restart=${restart:-"systemctl restart $u"}
    pidcmd=${pidcmd:-"systemctl show -p MainPID --value $u"}
  fi
  old_pid=$(q "$n" "$pidcmd" 2>/dev/null | tr -dc 0-9 || true)
  run kubectl cordon "$n"
  if [ -n "$DRAIN" ]; then
    run kubectl drain "$n" --ignore-daemonsets --delete-emptydir-data --timeout=10m
  fi
  # Copy next to the target, then rename: the running process keeps the old file open.
  # shellcheck disable=SC2086
  run $SCP "$BIN" "$n:$DEST.new"
  remote "$n" "chmod 755 '$DEST.new' && mv -f '$DEST.new' '$DEST'"
  remote "$n" "$restart"
  wait_healthy "$n" "$old_pid" "$pidcmd"
  run kubectl uncordon "$n"
  echo "$n upgraded"
done
echo "all nodes upgraded"

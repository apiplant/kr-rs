#!/bin/bash
# Sonobuoy conformance against kr in a throwaway privileged container (dev/test only).
#
#   tools/test/conformance.sh run [quick|full]   restart kr (fresh state) and start a run
#   tools/test/conformance.sh status             sonobuoy status
#   tools/test/conformance.sh wait               block until the run completes
#   tools/test/conformance.sh results [DIR]      retrieve, extract to DIR, summarize failures
#   tools/test/conformance.sh shell              shell in the container (KUBECONFIG set)
#   tools/test/conformance.sh rm                 delete the container
#
# Needs docker, kubectl and sonobuoy on the host; uses target/release/kr (cargo build --release
# first). The image store lives on a tmpfs in the container; it survives `run` but not `rm`.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
C=${KR_TEST_CONTAINER:-krc}
K="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig $C"

ensure() {
  if [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ]; then return; fi
  if docker inspect "$C" >/dev/null 2>&1; then docker start "$C" >/dev/null; return; fi
  docker run -d --name "$C" --hostname "$C" --privileged --tmpfs /store:exec,size=8g \
    -v "$REPO/target/release:/krbin:ro" \
    -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
    -v "$(command -v sonobuoy):/usr/local/bin/sonobuoy:ro" \
    archlinux:base-devel sleep infinity >/dev/null
}

restart_kr() {
  docker exec "$C" sh -c 'pkill -x kr; sleep 1; rm -rf /var/tmp/srv /store/pods /store/containers /store/ipam' || true
  docker exec -d -e KR_REGISTRY_MIRRORS="$("$REPO/tools/test/registry-cache.sh" env)" "$C" sh -c 'KR_ROOT=/store /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1'
  for _ in $(seq 30); do $K kubectl get nodes 2>/dev/null | grep -q ' Ready' && return; sleep 1; done
  echo "kr did not become ready; see: docker exec $C cat /tmp/srv.log" >&2; exit 1
}

case "${1:-}" in
  run)
    ensure; restart_kr
    case "${2:-full}" in
      quick) $K sonobuoy run --skip-preflight --mode quick ;;
      full) $K sonobuoy run --skip-preflight --mode non-disruptive-conformance --plugin-env e2e.E2E_PARALLEL=true --timeout 21600 ;;
      *) echo "mode: quick|full" >&2; exit 2 ;;
    esac >/dev/null
    echo "started (${2:-full}); kr log: docker exec $C cat /tmp/srv.log" ;;
  status) $K sonobuoy status ;;
  wait) until $K sonobuoy status 2>&1 | grep -q 'has completed'; do sleep 60; done; $K sonobuoy status ;;
  results)
    out=${2:-$REPO/target/conformance}; rm -rf "$out"; mkdir -p "$out"
    $K sh -c 'cd /tmp && rm -f *_sonobuoy_*.tar.gz && sonobuoy retrieve >/dev/null && ls *_sonobuoy_*.tar.gz' | head -1 | xargs -I{} docker cp "$C:/tmp/{}" "$out/results.tar.gz"
    tar xzf "$out/results.tar.gz" -C "$out"
    log=$out/plugins/e2e/results/global/e2e.log
    echo "e2e log: $log"
    echo "failed: $(grep -cE '^• \[(FAILED|PANICKED|TIMEDOUT)\]' "$log" || true)"
    echo "--- failures by SIG"
    grep -A1 -E '^• \[(FAILED|PANICKED|TIMEDOUT)\]' "$log" | grep -oE '^\[sig-[a-z-]+\]' | sort | uniq -c | sort -rn || true
    echo "--- top failure messages"
    grep -E '^  \[(FAILED|PANICKED)\] ' "$log" | grep -v ' in \[' | cut -c1-160 \
      | sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27}/UID/g; s/[a-z]+-[0-9]{3,5}/NS/g; s/[0-9]+/N/g' | sort | uniq -c | sort -rn | head -40
    awk '/^• \[(FAILED|PANICKED|TIMEDOUT)\]/{getline t; print t}' "$log" | sort > "$out/failed-tests.txt"
    echo "--- failed test names: $out/failed-tests.txt" ;;
  shell) ensure; docker exec -it -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig "$C" bash ;;
  rm) docker rm -f "$C" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac

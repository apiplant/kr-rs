#!/bin/bash
# Runs every library crate's tests; fails (non-zero) if any crate fails, aborts or hangs.
# The `kr` binary crate is excluded: it provides _start/panic handler and has no std harness.
#   tools/test/unit.sh [crate...]
set -uo pipefail
cd "$(dirname "$0")/../.."
crates=("$@")
[ ${#crates[@]} -eq 0 ] && crates=(kr-sys kr-rt kr-fmt kr-archive kr-crypto kr-store kr-raft kr-net kr-runtime kr-apiserver kr-controllers kr-kubelet)
fail=0
for c in "${crates[@]}"; do
  out=$(/usr/bin/timeout 900 cargo test -q -p "$c" 2>&1); rc=$?
  passed=$(grep -oE '[0-9]+ passed' <<<"$out" | awk '{s+=$1} END{print s+0}')
  if [ $rc -ne 0 ]; then
    fail=1; echo "FAIL $c (exit $rc, $passed passed before failing)"; grep -E 'panicked|FAILED|overflow|error(\[|:)' <<<"$out" | head -5 | sed 's/^/     /'
  else
    echo "ok   $c ($passed passed)"
  fi
done
exit $fail

#!/usr/bin/env bash
# Layers unpacked one by one and mounted as overlayfs lower layers (ADR-056), without root:
# the test runs in `unshare -Urm` (overlay with userxattr).   tools/test/layers.sh
set -u
cd "$(dirname "$0")/../.."
EXE=$(cargo test --release -p kr-runtime --test layers_overlay --no-run 2>&1 | sed -n 's/.*Executable .*(\(.*\))/\1/p')
[ -x "$EXE" ] || { echo "cannot build the test binary"; exit 2; }
KR_TEST_DIR=${KR_TEST_DIR:-$PWD/target} unshare -Urm "$EXE" --ignored --nocapture 2>&1 | tail -5
exit ${PIPESTATUS[0]}

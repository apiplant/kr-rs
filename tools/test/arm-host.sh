#!/bin/bash
# The arm64 suite on a real aarch64 host (#11): cross-builds kr and every test binary here, copies
# them to the host and runs them there natively, then the multi-node scripts in podman/docker
# containers (their own network namespaces: safe next to another Kubernetes on the host).
#   KR_ARM_HOST=user@host tools/test/arm-host.sh [unit|nodes|all]   (default all)
# Host needs: passwordless sudo, podman or docker, kernel >= 5.9 with nf_tables. Nothing is
# installed outside /opt/krtest (and the container image localhost/krtest:arm); the host's own
# binaries (e.g. a k3s `kubectl` symlink) are not touched. Exit status: 0 when everything passed.
# Needs here: rustup targets aarch64-unknown-linux-gnu and aarch64-unknown-linux-musl.
set -uo pipefail
cd "$(dirname "$0")/../.."
H=${KR_ARM_HOST:?set KR_ARM_HOST=user@host}
WHAT=${1:-all}
SSH="ssh -o BatchMode=yes -o LogLevel=ERROR $H"
LD="$PWD/tools/test/aarch64-ld.sh"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$LD CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$LD
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FAIL=0

$SSH 'uname -m' | grep -q aarch64 || { echo "$H is not aarch64"; exit 2; }
$SSH 'sudo mkdir -p /opt/krtest/bin /opt/krtest/repo/target/release && sudo chown -R $(id -u) /opt/krtest'

if [ "$WHAT" != nodes ]; then
  echo "== unit tests (native aarch64, musl)"
  cargo test --release --target aarch64-unknown-linux-musl --workspace --no-run 2>&1 | sed -n 's/.*Executable .*(\(.*\))/\1/p' > "$TMP/tests"
  tar czf "$TMP/t.tgz" --transform 's|.*/||' $(cat "$TMP/tests")
  scp -q -o LogLevel=ERROR "$TMP/t.tgz" "$H:/opt/krtest/tests.tgz" || { echo "FAIL uploading tests"; exit 1; }
  # Some tests use paths fixed at compile time (CARGO_MANIFEST_DIR, CARGO_TARGET_TMPDIR).
  $SSH "sudo mkdir -p '$PWD/target/tmp' '$PWD/crates' && sudo chown -R \$(id -u) '$PWD'"
  $SSH 'rm -rf /opt/krtest/tests && mkdir /opt/krtest/tests && cd /opt/krtest/tests && tar xzf ../tests.tgz && f=0; for t in *; do r=$(timeout 900 ./$t 2>&1 | grep "^test result" | tail -1); case "$r" in *" 0 failed"*) ;; *) echo "FAIL $t: $r"; f=1;; esac; done; echo "unit: $(ls | wc -l) binaries"; exit $f' || FAIL=1
fi

if [ "$WHAT" != unit ]; then
  echo "== multi-node scripts (containers on the host)"
  cargo build --release --target aarch64-unknown-linux-gnu -p kr 2>&1 | tail -1
  # Upload beside it and rename: the old binary may still be running (ETXTBSY on overwrite).
  scp -q -o LogLevel=ERROR target/aarch64-unknown-linux-gnu/release/kr "$H:/opt/krtest/repo/target/release/kr.new" \
    && $SSH 'mv -f /opt/krtest/repo/target/release/kr.new /opt/krtest/repo/target/release/kr' || { echo "FAIL uploading kr"; exit 1; }
  tar cf - tools/test | $SSH 'tar xf - -C /opt/krtest/repo'
  $SSH 'set -e; [ -x /opt/krtest/bin/kubectl ] || { V=$(curl -sL https://dl.k8s.io/release/stable.txt); curl -sLo /opt/krtest/bin/kubectl https://dl.k8s.io/release/$V/bin/linux/arm64/kubectl; chmod 755 /opt/krtest/bin/kubectl; }
    sudo podman image exists localhost/krtest:arm 2>/dev/null || sudo docker image inspect localhost/krtest:arm >/dev/null 2>&1 || {
      mkdir -p /tmp/krimg; printf "FROM docker.io/library/fedora:41\nRUN dnf install -y --setopt=install_weak_deps=False iproute procps-ng nftables curl findutils which && dnf clean all\n" > /tmp/krimg/Containerfile
      (command -v podman >/dev/null && sudo podman build -q -t localhost/krtest:arm /tmp/krimg) || sudo docker build -q -t localhost/krtest:arm /tmp/krimg; }'
  run() { # script [args...]
    if $SSH "cd /opt/krtest/repo && sudo env PATH=/opt/krtest/bin:\$PATH KR_TEST_IMAGE=localhost/krtest:arm timeout 2400 tools/test/$* > /tmp/krtest.log 2>&1"; then echo "ok   $*"; else echo "FAIL $* (log: $H:/tmp/krtest-fail-${1%.sh}.log)"; $SSH "cp /tmp/krtest.log /tmp/krtest-fail-${1%.sh}.log"; FAIL=1; fi
  }
  run ca-rotate-agent.sh
  run nft-cluster.sh
  run embedded-registry.sh
  run vxlan.sh
  run ha.sh up && run ha.sh test
  run ha.sh up && run ha.sh keysync && run ha.sh carotate
  run ha.sh down
fi
[ $FAIL = 0 ] && echo "arm64: PASS" || { echo "arm64: FAILED"; exit 1; }

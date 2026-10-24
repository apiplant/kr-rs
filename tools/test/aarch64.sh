#!/bin/sh
# Cross-build kr for aarch64 and run it + the low-level unit tests under qemu-user.
#
# Prerequisites (no root needed beyond having them installed):
#   - rustup nightly with `rustup target add aarch64-unknown-linux-gnu`
#     (its bundled rust-lld is the linker, via tools/test/aarch64-ld.sh; no cross gcc/sysroot)
#   - qemu-aarch64 (Arch: qemu-user) on PATH; binfmt_misc registration is NOT required
#   - python3 (echo smoke client)
#   - `rustup target add aarch64-unknown-linux-musl` for the unit tests (self-contained libc)
set -eu
cd "$(dirname "$0")/../.."
T=aarch64-unknown-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$PWD/tools/test/aarch64-ld.sh"
Q="${QEMU:-qemu-aarch64}"

cargo build --release --target $T -p kr
K="target/$T/release/kr"
file "$K" 2>/dev/null || true

echo "== version";    "$Q" "$K" version
echo "== sleep-test"; /usr/bin/timeout 30 "$Q" "$K" sleep-test

echo "== echo"
/usr/bin/timeout 15 "$Q" "$K" echo 18080 &
sleep 2
out=$(python3 -I -c "import socket;s=socket.create_connection(('127.0.0.1',18080),3);s.sendall(b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello');print(s.recv(512).decode().split(chr(13))[0])" || true)
wait || true
[ "$out" = "HTTP/1.1 200 OK" ] && echo "echo ok" || { echo "echo FAILED: '$out'"; exit 1; }

# Unit tests: musl target, self-contained (crt + libc.a ship with rustup), run via qemu.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$PWD/tools/test/aarch64-ld.sh"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$Q"
for c in kr-sys kr-rt kr-fmt kr-crypto kr-archive kr-store kr-net; do
  /usr/bin/timeout 900 cargo test --target aarch64-unknown-linux-musl -p $c
done
echo "aarch64 OK"

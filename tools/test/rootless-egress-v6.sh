#!/usr/bin/env bash
# Rootless IPv6 egress (ADR-030/031) in a throwaway privileged container: a non-root user runs
# `kr ctr run`; a network namespace with fd01::2 plays the outside world. Checks that the container
# has its IPv6 address, fetches over IPv6, pings and sees `traceroute` end at the target.
# Needs docker, target/release/kr and the archlinux:base-devel image (network for the alpine pull).
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
docker run --rm --privileged -v "$KR:/kr:ro" archlinux:base-devel sh -c '
set -u
useradd -m u && echo u:100000:65536 > /etc/subuid && echo u:100000:65536 > /etc/subgid
mkdir -p /home/u/kr && mount -t tmpfs -o size=2g,exec tmpfs /home/u/kr && chown u /home/u/kr
chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap
ip netns add t && ip link add vt0 type veth peer name vt1 netns t && ip addr add fd01::1/64 dev vt0 nodad && ip link set vt0 up
ip -n t addr add fd01::2/64 dev vt1 nodad && ip -n t link set vt1 up && ip -n t link set lo up
mkdir -p /srv && echo hello-v6 > /srv/index.html
(cd /srv && ip netns exec t python3 -m http.server 8000 --bind fd01::2 >/dev/null 2>&1 &)
sleep 1
cat > /home/u/run.sh <<S
echo addr=\$(ip -6 addr show eth0 | grep -c "inet6 fd00:88:")
echo get=\$(wget -qO- -T5 http://[fd01::2]:8000/)
echo ping=\$(ping -6 -c1 -W3 fd01::2 | grep -c "1 packets received")
echo trace=\$(traceroute -6 -n -m3 -w2 fd01::2 2>&1 | grep -c "^ 3  fd01::2")
echo hop=\$(traceroute -6 -n -m3 -w2 fd01::2 2>&1 | grep -c "^ 2  fd00:88:ffff:1::2")
S
OUT=$(su u -c "KR_ROOT=/home/u/kr /kr ctr run docker.io/library/alpine:3.20 -- sh -c \"\$(cat /home/u/run.sh)\"" 2>&1)
fail=0
check() { v=$(echo "$OUT" | sed -n "s/^$1=//p"); if [ "$v" = "$2" ]; then echo "ok   $1"; else echo "FAIL $1: got $v want $2"; fail=1; fi; }
check addr 1; check get hello-v6; check ping 1; check trace 1; check hop 1
[ $fail = 0 ] && echo "rootless IPv6 egress: all checks passed" || { echo "$OUT" | tail -15; exit 1; }
'

#!/usr/bin/env bash
# The nftables Service datapath (ADR-054) against a real kernel, without root: everything runs in
# `unshare -Urn` namespaces (needs nf_tables, ip, nsenter, python3; no network).
#   tools/test/nft-proxy.sh
# Topology: this namespace is the node (10.88.N.1 on a veth per pod); pod A (10.88.0.2) is the
# client, pods B (10.88.1.2) and C (10.88.2.2) run servers that answer with their name and the
# address the connection came from.
set -u
cd "$(dirname "$0")/../.."
EXE=$(cargo test --release -p kr-net --test nft_proxy_kernel --no-run 2>&1 | sed -n 's/.*Executable .*(\(.*\))/\1/p')
[ -x "$EXE" ] || { echo "cannot build the test binary"; exit 2; }
export EXE
exec unshare -Urn bash -c '
set -u
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2], want [$3]"; fail=1; fi; }
cleanup() { kill $A $B $C $D $SB $SC $SB2 2>/dev/null; }
trap cleanup EXIT
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
unshare -n sleep 600 & A=$!
unshare -n sleep 600 & B=$!
unshare -n sleep 600 & C=$!
unshare -n sleep 600 & D=$!
sleep 0.3
n=0
for p in "$A:0" "$B:1" "$C:2" "$D:3"; do
  pid=${p%:*}; i=${p#*:}
  ip link add v$i type veth peer name eth0 netns $pid
  ip addr add 10.88.$i.1/24 dev v$i; ip link set v$i up
  ip addr add fd00:88:0:$i::1/64 dev v$i nodad
  nsenter -t $pid -n sh -c "ip link set lo up; ip addr add 10.88.$i.2/24 dev eth0; ip addr add fd00:88:0:$i::2/64 dev eth0 nodad; ip link set eth0 up; ip route add default via 10.88.$i.1; ip -6 route add default via fd00:88:0:$i::1"
done
ip route add local 10.96.0.0/16 dev lo; ip -6 route add local fd00:96::/112 dev lo
cat > /tmp/srv.py <<Y
import socket, sys
name, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(64)
s6 = socket.socket(socket.AF_INET6); s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s6.bind(("::", port)); s6.listen(64)
import threading
def loop(sock):
    while True:
        c, a = sock.accept()
        c.sendall((name + " " + a[0] + "\\n").encode()); c.close()
threading.Thread(target=loop, args=(s6,), daemon=True).start()
while True:
    c, a = s.accept()
    c.sendall((name + " " + a[0] + "\n").encode()); c.close()
Y
cat > /tmp/cli.py <<Y
import socket, sys
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(n):
    try:
        s = socket.create_connection((host, port), timeout=2)
        print(s.recv(100).decode().strip())
    except Exception as e:
        print("error", type(e).__name__)
Y
nsenter -t $B -n python3 /tmp/srv.py B 9090 &
SB=$!
nsenter -t $C -n python3 /tmp/srv.py C 9090 &
SC=$!
nsenter -t $B -n python3 /tmp/srv.py B 9091 &
SB2=$!
sleep 0.5
scenario() { KR_NFT_SCENARIO=$1 "$EXE" --ignored --exact apply >/dev/null 2>/tmp/apply.err || { echo "FAIL scenario $1: $(tail -2 /tmp/apply.err)"; fail=1; return 1; }; }
client() { nsenter -t $A -n python3 /tmp/cli.py "$@"; }
clientD() { nsenter -t $D -n python3 /tmp/cli.py "$@"; }

scenario basic
check "ClusterIP reaches the endpoint with the client address kept" "$(client 10.96.0.50 8080 1)" "B 10.88.0.2"
# A client outside the pod network (the node itself, 192.0.2.1) on the NodePort: masqueraded.
ip addr add 192.0.2.1/32 dev lo
check "host to NodePort works" "$(python3 /tmp/cli.py 192.0.2.1 30080 1 | cut -d" " -f1)" "B"
check "NodePort client is masqueraded (source is the gateway, not the host address)" "$(python3 /tmp/cli.py 192.0.2.1 30080 1 | cut -d" " -f2 | sed "s/^10.88.1.1$/gateway/")" "gateway"
check "host to ClusterIP (output hook)" "$(python3 /tmp/cli.py 10.96.0.50 8080 1 | cut -d" " -f1)" "B"
check "a ClusterIP without rule is refused" "$(client 10.96.0.51 8080 1)" "error ConnectionRefusedError"

scenario spread
out=$(client 10.96.0.50 8080 60 | cut -d" " -f1 | sort | uniq -c | tr -s " " | tr "\n" ",")
b=$(client 10.96.0.50 8080 60 | grep -c "^B"); c=$((60-b))
if [ "$b" -ge 15 ] && [ "$c" -ge 15 ]; then echo "ok   traffic spreads over both endpoints ($b/$c)"; else echo "FAIL spread: $b/$c"; fail=1; fi

scenario affinity
first=$(client 10.96.0.50 8080 1 | cut -d" " -f1)
all=$(client 10.96.0.50 8080 20 | cut -d" " -f1 | sort -u | tr "\n" ",")
check "ClientIP affinity keeps one endpoint" "$all" "$first,"

scenario local-none
check "externalTrafficPolicy Local without a local endpoint drops" "$(python3 /tmp/cli.py 192.0.2.1 30080 1)" "error TimeoutError"
scenario local-one
check "externalTrafficPolicy Local with a local endpoint works" "$(python3 /tmp/cli.py 192.0.2.1 30080 1 | cut -d" " -f1)" "B"
check "...and keeps the client address (no masquerade)" "$(python3 /tmp/cli.py 192.0.2.1 30080 1 | cut -d" " -f2)" "192.0.2.1"

# NetworkPolicy (ADR-049) in a real kernel, and with Services in front (#165).
scenario pol-a-9090
check "policy: the allowed client reaches the pod" "$(client 10.88.1.2 9090 1)" "B 10.88.0.2"
check "policy: another client is dropped" "$(clientD 10.88.1.2 9090 1)" "error TimeoutError"
check "policy: the allowed client on another port is dropped" "$(client 10.88.1.2 9091 1)" "error TimeoutError"
check "policy through a ClusterIP: the allowed client (source kept by the DNAT)" "$(client 10.96.0.50 8080 1)" "B 10.88.0.2"
check "policy through a ClusterIP: the other client is dropped (#165)" "$(clientD 10.96.0.50 8080 1)" "error TimeoutError"
scenario pol-set
check "policy with a set of peers: a member reaches the pod" "$(client 10.88.1.2 9090 1)" "B 10.88.0.2"
check "policy with a set of peers: a non-member is dropped" "$(clientD 10.88.1.2 9090 1)" "error TimeoutError"
check "policy with a set of peers: a member on another port is dropped" "$(client 10.88.1.2 9091 1)" "error TimeoutError"
check "the peers are in a set" "$(nft list set inet kr-netpol i4_0-s1 2>&1 | grep -c "10.88.9.1")" "1"
scenario pol-deny-all
check "policy: default deny drops everyone" "$(client 10.88.1.2 9090 1)" "error TimeoutError"
scenario pol-egress
check "policy: egress to the allowed peer works" "$(client 10.88.1.2 9090 1 | cut -d" " -f1)" "B"
check "policy: egress to another pod is dropped" "$(client 10.88.2.2 9090 1)" "error TimeoutError"
nft delete table inet kr-netpol 2>/dev/null
scenario basic
conn_before=$(client 10.96.0.50 8080 1 | cut -d" " -f1)
scenario v6
check "IPv6 ClusterIP keeps the client address" "$(client fd00:96::50 8080 1)" "B fd00:88::2"
ip -6 addr add 2001:db8::1/128 dev lo nodad
check "IPv6 NodePort works and is masqueraded" "$(python3 /tmp/cli.py 2001:db8::1 30080 1 | cut -d" " -f1)" "B"
scenario empty
check "removing the service stops the DNAT" "$(client 10.96.0.50 8080 1)" "error ConnectionRefusedError"
if KR_NFT_SCENARIO= "$EXE" --ignored --exact apply_sequence --nocapture >/tmp/seq.out 2>&1; then echo "ok   generations: 40, 500, 3, 0, 3000 (a batch larger than the socket buffer) and 10 Services in a row"; grep services /tmp/seq.out | tr "\n" " "; echo; else echo "FAIL generations: $(tail -3 /tmp/seq.out)"; fail=1; fi
check "the table after the sequence still serves its service" "$(client 10.96.0.50 8080 1 | cut -d" " -f1)" "B"
rules=$(nft list ruleset | grep -c "chain g")
check "old generations are gone (only the last one remains)" "$([ "$rules" -le 12 ] && echo yes || echo "no: $rules chains")" "yes"
ip link add d0 type dummy; ip link set d0 up; ip addr add fd00::1/64 dev d0 nodad
if "$EXE" --ignored --exact ipv6_routes_by_proto >/tmp/r6.out 2>&1; then echo "ok   IPv6 routes of a protocol: add, dump, delete"; else echo "FAIL IPv6 routes: $(tail -3 /tmp/r6.out)"; fail=1; fi
exit $fail
'

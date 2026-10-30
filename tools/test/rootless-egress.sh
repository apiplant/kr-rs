#!/usr/bin/env bash
# Rootless egress check (ADR-030): runs a rootless `kr server` as the current (non-root) user and
# checks that a pod and a `kr ctr run` container reach a host HTTP server (download and upload
# byte-exact), resolve names and ping. Needs target/release/kr, an image in the local store
# (IMAGE, default localhost:5002/alpine:3.20) and python3, kubectl.
set -u
cd "$(dirname "$0")/../.."
[ "$(id -u)" != 0 ] || { echo "run as a normal user"; exit 2; }
IMAGE=${IMAGE:-localhost:5002/alpine:3.20}
KR=${KR:-target/release/kr}
HOST_IP=${HOST_IP:-$(ip -4 route get 1.1.1.1 | grep -o 'src [0-9.]*' | cut -d' ' -f2)}
T=$(mktemp -d)
PORT=${PORT:-6555}
HPORT=${HPORT:-8099}
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }

mkdir -p "$T/www"
head -c 30000000 /dev/urandom > "$T/www/big"
BIG=$(sha256sum "$T/www/big" | cut -c1-16)
cat > "$T/srv.py" <<'P'
import functools, hashlib, http.server, sys
class H(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); h = hashlib.sha256(); left = n
        while left:
            b = self.rfile.read(min(65536, left)); h.update(b); left -= len(b)
        out = h.hexdigest()[:16].encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), functools.partial(H, directory=sys.argv[2])).serve_forever()
P
python3 "$T/srv.py" "$HPORT" "$T/www" > /dev/null 2>&1 &
pids+=($!)
UP=$(head -c 20000000 /dev/zero | sha256sum | cut -c1-16)

SCRIPT="
echo down=\$(wget -qO- -T 30 http://$HOST_IP:$HPORT/big | sha256sum | cut -c1-16)
head -c 20000000 /dev/zero > /tmp/up
echo up=\$( (printf 'POST / HTTP/1.0\\r\\nContent-Length: 20000000\\r\\n\\r\\n'; cat /tmp/up) | nc -w 20 $HOST_IP $HPORT | tail -c 16)
echo dns=\$(nslookup example.com 2>/dev/null | grep -q '^Address.*[0-9]\\.[0-9]' && echo ok)
echo ping=\$(ping -c1 -W3 $HOST_IP | grep -c '1 packets received')
echo bigping=\$(ping -c1 -s 3000 -W3 $HOST_IP | grep -c '1 packets received')
echo trace=\$(traceroute -n -m4 -w2 $HOST_IP 2>&1 | grep -c '^ *3  $HOST_IP')
echo noreply=\$(ping -c1 -W2 10.99.99.99 | grep -c '1 packets received')
"

echo "== kr ctr run"
OUT=$(/usr/bin/timeout 120 "$KR" ctr run "$IMAGE" -- sh -c "$SCRIPT" 2>&1)
check ctr-download "$(echo "$OUT" | sed -n 's/^down=//p')" "$BIG"
check ctr-upload "$(echo "$OUT" | sed -n 's/^up=//p')" "$UP"
check ctr-dns "$(echo "$OUT" | sed -n 's/^dns=//p')" ok
check ctr-ping "$(echo "$OUT" | sed -n 's/^ping=//p')" 1
check ctr-fragmented-ping "$(echo "$OUT" | sed -n 's/^bigping=//p')" 1
check ctr-traceroute "$(echo "$OUT" | sed -n 's/^trace=//p')" 1
check ctr-ping-unreachable "$(echo "$OUT" | sed -n 's/^noreply=//p')" 0

echo "== pod (dnsPolicy Default)"
setsid "$KR" server --port "$PORT" --data "$T/srv" > "$T/kr.log" 2>&1 &
pids+=($!)
export KUBECONFIG="$T/srv/admin.kubeconfig"
for _ in $(seq 60); do kubectl get nodes 2>/dev/null | grep -q ' Ready' && break; sleep 1; done
INDENTED=$(echo "$SCRIPT" | sed 's/^/        /')
kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: egress}
spec:
  restartPolicy: Never
  dnsPolicy: Default
  containers:
  - name: c
    image: "$IMAGE"
    imagePullPolicy: IfNotPresent
    command: [sh, -c, 'eval "\$S"']
    env:
    - name: S
      value: |
$INDENTED
Y
for _ in $(seq 90); do kubectl get pod egress -o jsonpath='{.status.phase}' 2>/dev/null | grep -qE 'Succeeded|Failed' && break; sleep 1; done
OUT=$(kubectl logs egress 2>&1)
check pod-download "$(echo "$OUT" | sed -n 's/^down=//p')" "$BIG"
check pod-upload "$(echo "$OUT" | sed -n 's/^up=//p')" "$UP"
check pod-dns "$(echo "$OUT" | sed -n 's/^dns=//p')" ok
check pod-ping "$(echo "$OUT" | sed -n 's/^ping=//p')" 1
check pod-fragmented-ping "$(echo "$OUT" | sed -n 's/^bigping=//p')" 1
check pod-traceroute "$(echo "$OUT" | sed -n 's/^trace=//p')" 1
check pod-ping-unreachable "$(echo "$OUT" | sed -n 's/^noreply=//p')" 0
[ $fail = 0 ] && echo "rootless egress: all checks passed" || { echo "rootless egress: FAILED"; echo "$OUT" | tail -20; }
exit $fail

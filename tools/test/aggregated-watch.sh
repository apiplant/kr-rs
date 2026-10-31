#!/usr/bin/env bash
# Live check of a watch through an aggregated API (ADR-033): a tiny extension API server (python,
# TLS, streams three events a second apart) behind an APIService; `kubectl get --raw ...?watch=true`
# must print the events as they come. Needs a running two-node cluster (tools/test/two-node.sh up).
set -euo pipefail
K="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
KI="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
IMG=${PYIMG:-python:3.12-alpine}
T=$(mktemp -d)
trap 'rm -rf "$T"; $K delete apiservice/v1.ext.example.com pod/ext svc/ext configmap/ext-code secret/ext-tls --ignore-not-found >/dev/null 2>&1 || true' EXIT
cd "$T"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj /CN=ext-ca -days 2 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr -subj /CN=ext >/dev/null 2>&1
printf 'subjectAltName=DNS:ext.default.svc\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 2 -extfile ext.cnf >/dev/null 2>&1
cat > server.py <<'PY'
import http.server, ssl, json, time
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p, _, q = self.path.partition("?")
        if p == "/apis/ext.example.com/v1":
            return self.send(200, {"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "ext.example.com/v1", "resources": [{"name": "things", "singularName": "thing", "namespaced": False, "kind": "Thing", "verbs": ["get", "list", "watch"]}]})
        if p == "/apis/ext.example.com/v1/things" and "watch=true" in q:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            for i in range(3):
                ev = (json.dumps({"type": "ADDED", "object": {"kind": "Thing", "apiVersion": "ext.example.com/v1", "metadata": {"name": "t%d" % i}}}) + "\n").encode()
                self.wfile.write(b"%x\r\n" % len(ev) + ev + b"\r\n"); self.wfile.flush(); time.sleep(1)
            self.wfile.write(b"0\r\n\r\n"); return
        if p == "/apis/ext.example.com/v1/things":
            return self.send(200, {"kind": "ThingList", "apiVersion": "ext.example.com/v1", "metadata": {}, "items": []})
        self.send(404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 404})
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
docker cp tls.crt kr1:/tmp/ext-tls.crt; docker cp tls.key kr1:/tmp/ext-tls.key; docker cp server.py kr1:/tmp/ext-server.py
$K create secret generic ext-tls --from-file=tls.crt=/tmp/ext-tls.crt --from-file=tls.key=/tmp/ext-tls.key >/dev/null
$K create configmap ext-code --from-file=server.py=/tmp/ext-server.py >/dev/null
CA=$(base64 -w0 < ca.crt)
$KI apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: ext, labels: {app: ext}}
spec:
  containers:
  - name: s
    image: $IMG
    command: [python, /code/server.py]
    volumeMounts: [{name: code, mountPath: /code}, {name: tls, mountPath: /tls}]
  volumes: [{name: code, configMap: {name: ext-code}}, {name: tls, secret: {secretName: ext-tls}}]
---
apiVersion: v1
kind: Service
metadata: {name: ext}
spec: {selector: {app: ext}, ports: [{port: 443, targetPort: 8443}]}
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata: {name: v1.ext.example.com}
spec: {group: ext.example.com, version: v1, groupPriorityMinimum: 1000, versionPriority: 15, caBundle: $CA, service: {name: ext, namespace: default, port: 443}}
Y
$K wait --for=condition=Ready pod/ext --timeout=120s >/dev/null
for _ in $(seq 40); do [ "$($K get apiservice v1.ext.example.com -o jsonpath='{.status.conditions[?(@.type=="Available")].status}')" = True ] && break; sleep 1; done
echo "available: $($K get apiservice v1.ext.example.com -o jsonpath='{.status.conditions[?(@.type=="Available")].status}')"
echo "list: $($K get --raw /apis/ext.example.com/v1/things)"
start=$(date +%s.%N)
$K get --raw '/apis/ext.example.com/v1/things?watch=true' | while read -r line; do printf '%5.1fs %s\n' "$(awk -v a="$(date +%s.%N)" -v b="$start" 'BEGIN{print a-b}')" "${line:0:70}"; done

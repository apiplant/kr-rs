#!/bin/bash
# Rootless end-to-end test of ADR-046: audit log (policy, secrets redaction, rotation) and
# Pod Security audit mode / exemptions.   tools/test/audit.sh [path/to/kr]   (needs kubectl; port 17453)
set -euo pipefail
KR=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/kr}
W=${KEEP_DIR:-$(mktemp -d)}; trap 'kill $(jobs -p) 2>/dev/null || true; [ -n "${KEEP_DIR:-}" ] || rm -rf "$W"' EXIT
A=$W/a; mkdir -p "$A"
k() { KUBECONFIG=$A/server/admin.kubeconfig kubectl "$@"; }
cat > "$W/policy.yaml" <<'P'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: None
  nonResourceURLs: ["/healthz*", "/livez*", "/readyz*", "/version", "/openapi*", "/api", "/apis*", "/api/*"]
- level: RequestResponse
  resources: [{group: "", resources: ["secrets"]}]
- level: RequestResponse
P
cat > "$W/psa.yaml" <<'P'
apiVersion: pod-security.admission.config.k8s.io/v1
kind: PodSecurityConfiguration
defaults: {enforce: privileged, audit: baseline, audit-version: latest}
exemptions: {namespaces: [exempt-ns]}
P
KR_ROOT=$A $KR server --port 17453 --audit-policy-file "$W/policy.yaml" --pod-security-config "$W/psa.yaml" --audit-log-maxsize 1 --audit-log-maxbackup 2 >"$W/a.log" 2>&1 & P=$!
for _ in $(seq 60); do k get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
L=$A/server/audit/audit.log
k create ns t >/dev/null; k -n t create cm c --from-literal=a=b >/dev/null
k -n t create secret generic s --from-literal=pw=hunter2 >/dev/null; k -n t get secret s -o yaml >/dev/null
k -n t create -f - >/dev/null <<'P'
apiVersion: v1
kind: Pod
metadata: {name: hp}
spec: {hostNetwork: true, containers: [{name: c, image: x}]}
P
k create ns exempt-ns >/dev/null
k -n exempt-ns create -f - >/dev/null <<'P'
apiVersion: v1
kind: Pod
metadata: {name: hp}
spec: {hostNetwork: true, containers: [{name: c, image: x}]}
P
k -n t delete cm c >/dev/null
sleep 3
echo "--- sample audit lines"; grep '"verb":"create"' "$L" | grep configmaps | head -1; grep '"verb":"delete"' "$L" | grep configmaps | head -1
fail=0; ck() { if ! eval "$2"; then echo "FAIL $1"; fail=1; fi; }
ck "configmap create has requestObject" "grep configmaps $L | grep -q '\"verb\":\"create\".*\"requestObject\"'"
ck "delete logged" "grep -q '\"verb\":\"delete\".*\"resource\":\"configmaps\"' $L"
ck "secret value never logged" "! grep -q 'hunter2\|aHVudGVyMg' $L"
ck "secret metadata logged" "grep -q '\"resource\":\"secrets\"' $L"
ck "healthz not logged" "! grep -q '/healthz' $L"
ck "psa audit annotation" "grep -q 'pod-security.kubernetes.io/audit-violations' $L"
ck "psa exempt annotation" "grep -q '\"pod-security.kubernetes.io/exempt\":\"namespace\"' $L"
ck "event format" "grep -q '\"kind\":\"Event\",\"apiVersion\":\"audit.k8s.io/v1\"' $L"
# rotation: fill the 1 MB log with big configmaps
head -c 300000 /dev/urandom | base64 -w0 > "$W/big"
for i in 1 2 3 4 5 6; do k -n t create cm big$i --from-file=d="$W/big" >/dev/null; done; sleep 3
# Bodies over 256 KB are encoded by an offload worker after the response (ADR-052): the event
# is complete and still carries the request object (and, for the list below, the response).
ck "big request body logged (offload worker)" "[ \$(cat $A/server/audit/audit*.log | grep -c '\"requestObject\".*\"name\":\"big[0-9]\"') -ge 1 ]"
for i in 1 2 3; do k -n t get cm -o json >/dev/null; done; sleep 2
ck "big response body logged (offload worker)" "[ \$(cat $A/server/audit/audit*.log | grep '\"verb\":\"list\"' | grep -c '\"responseObject\".*big[0-9]') -ge 1 ]"
ck "rotated" "[ \$(ls $A/server/audit | grep -c '^audit-') -ge 1 ]"
[ $fail = 0 ] && echo "audit: all checks passed" || { echo "audit: FAILED"; exit 1; }

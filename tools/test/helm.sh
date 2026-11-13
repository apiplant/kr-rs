#!/bin/bash
# The Helm controller (ADR-061, #154) with a real cluster and the real rancher/klipper-helm Job:
# a single kr server krh1 in a throwaway privileged container plus a private chart repository
# (nginx, HTTPS with its own CA and basic auth) on the same network (dev only).
#   tools/test/helm.sh [down]     (needs target/release/kr, helm, openssl; internet for podinfo)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f krh1 krhrepo >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krh1 kubectl"
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 3; done; return 1; }
job_done() { [ "$($K get job -n kube-system "$1" -o jsonpath='{.status.succeeded}' 2>/dev/null)" = 1 ]; }

# --- a tiny chart (for chartContent and the private repository)
mkdir -p "$W/tiny/templates"
printf 'apiVersion: v2\nname: tiny\nversion: 0.1.0\n' > "$W/tiny/Chart.yaml"
printf 'greeting: hello\n' > "$W/tiny/values.yaml"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: "{{ .Release.Name }}-cm"}\ndata: {greeting: "{{ .Values.greeting }}"}\n' > "$W/tiny/templates/cm.yaml"
helm package -d "$W/pkg" "$W/tiny" >/dev/null
CONTENT=$(base64 -w0 "$W/pkg/tiny-0.1.0.tgz")

# --- private repository: HTTPS with its own CA, basic auth user/pass
docker run -d --name krhrepo --network krnet nginx:alpine sleep infinity >/dev/null 2>&1 || true
docker rm -f krhrepo >/dev/null
docker run -d --name krhrepo --network krnet nginx:alpine >/dev/null
RIP=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krhrepo)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=repo-ca -keyout "$W/ca.key" -out "$W/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=repo -keyout "$W/srv.key" -out "$W/srv.csr" 2>/dev/null
printf "subjectAltName=IP:$RIP\n" > "$W/ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$W/ext" -out "$W/srv.pem" 2>/dev/null
mkdir -p "$W/www/charts"; cp "$W/pkg/tiny-0.1.0.tgz" "$W/www/charts/"
helm repo index "$W/www/charts" --url "https://$RIP/charts"
printf "user:$(openssl passwd -apr1 pass)\n" > "$W/htpasswd"
cat > "$W/nginx.conf" <<'C'
events {}
http { server { listen 443 ssl; ssl_certificate /w/srv.pem; ssl_certificate_key /w/srv.key;
  location /charts/ { root /w/www; auth_basic "charts"; auth_basic_user_file /w/htpasswd; } } }
C
docker cp "$W/." krhrepo:/w/ >/dev/null
docker exec krhrepo chmod -R a+rX /w   # mktemp's mode 700 would keep nginx's worker out
docker exec krhrepo sh -c 'cp /w/nginx.conf /etc/nginx/nginx.conf && nginx -s reload'

docker run -d --name krh1 --hostname krh1 --network krnet --privileged --tmpfs /store:exec,size=3g \
  -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
  ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
start_server() { docker exec -d krh1 sh -c "echo \$\$ > /tmp/srv.pid; KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --data /var/tmp/srv >> /tmp/srv.log 2>&1"; waitfor "$K get --raw /healthz >/dev/null 2>&1" 20; }
stop_server() { docker exec krh1 sh -c 'kill $(cat /tmp/srv.pid)'; waitfor "! docker exec krh1 sh -c 'kill -0 \$(cat /tmp/srv.pid) 2>/dev/null'" 10; }
start_server
waitfor '$K get nodes --no-headers 2>/dev/null | grep -q " Ready"' 20

# 1. from a public repository, then an upgrade when the values change
cat <<'Y' | $K apply -f - >/dev/null
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: podinfo, namespace: kube-system}
spec:
  repo: https://stefanprodan.github.io/podinfo
  chart: podinfo
  version: 6.7.1
  targetNamespace: web
  createNamespace: true
  valuesContent: "replicaCount: 1\n"
Y
check "repo: install Job succeeds" "waitfor 'job_done helm-install-podinfo' 60"
check "repo: the chart's Deployment is Available" "waitfor '[ \"\$($K get deploy -n web podinfo -o jsonpath={.status.availableReplicas} 2>/dev/null)\" = 1 ]' 40"
check "repo: status.jobName set" "$K get helmchart -n kube-system podinfo -o jsonpath={.status.jobName} | grep -q helm-install-podinfo"
$K patch helmchart -n kube-system podinfo --type merge -p '{"spec":{"valuesContent":"replicaCount: 2\n"}}' >/dev/null
check "upgrade on change: Deployment scaled to 2 by a new Job" "waitfor '[ \"\$($K get deploy -n web podinfo -o jsonpath={.spec.replicas} 2>/dev/null)\" = 2 ]' 60"

# 2. chartContent
cat <<Y | $K apply -f - >/dev/null
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: inline, namespace: kube-system}
spec: {chartContent: "$CONTENT", targetNamespace: default, set: {greeting: from-content}}
Y
check "chartContent: release installed with the set value" "waitfor '$K get cm inline-cm -o jsonpath={.data.greeting} 2>/dev/null | grep -qx from-content' 60"

# 3. private repository: HTTPS with repoCA, basic auth with authSecret
$K -n kube-system create secret generic repo-auth --type kubernetes.io/basic-auth --from-literal=username=user --from-literal=password=pass >/dev/null
CA_IND=$(sed 's/^/    /' "$W/ca.pem")
cat <<Y | $K apply -f - >/dev/null
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: private, namespace: kube-system}
spec:
  repo: https://$RIP/charts
  chart: tiny
  version: 0.1.0
  targetNamespace: default
  authSecret: {name: repo-auth}
  repoCA: |
$CA_IND
  set: {greeting: from-private}
Y
check "authSecret + repoCA: release installed from the private repository" "waitfor '$K get cm private-cm -o jsonpath={.data.greeting} 2>/dev/null | grep -qx from-private' 60"
check "authSecret + repoCA: the repository saw an authenticated request" "docker logs krhrepo 2>&1 | grep -q '\" user \\[\\|user .*GET /charts/index.yaml\\|GET /charts/index.yaml.* 200 '"

# 4. bootstrap: host network, runs on a node that is not Ready for pods yet (tolerations)
cat <<Y | $K apply -f - >/dev/null
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: boot, namespace: kube-system}
spec: {chartContent: "$CONTENT", targetNamespace: default, bootstrap: true, set: {greeting: boot}}
Y
check "bootstrap: Job pod on the host network" "waitfor '$K get pods -n kube-system -l job-name=helm-install-boot -o jsonpath={.items[0].spec.hostNetwork} 2>/dev/null | grep -q true' 30"
check "bootstrap: release installed" "waitfor '$K get cm boot-cm -o jsonpath={.data.greeting} 2>/dev/null | grep -qx boot' 60"

# 5. a failing uninstall keeps the HelmChart (finalizer) until it succeeds
$K patch helmchart -n kube-system inline --type merge -p '{"spec":{"jobImage":"rancher/klipper-helm:does-not-exist"}}' >/dev/null
$K delete helmchart -n kube-system inline --wait=false >/dev/null
sleep 25
check "failing uninstall: HelmChart still there (finalizer)" "$K get helmchart -n kube-system inline >/dev/null 2>&1"
check "failing uninstall: release objects still there" "$K get cm inline-cm >/dev/null 2>&1"
$K patch helmchart -n kube-system inline --type json -p '[{"op":"remove","path":"/spec/jobImage"}]' >/dev/null
check "after fixing the image: uninstall completes and the HelmChart goes" "waitfor '! $K get helmchart -n kube-system inline >/dev/null 2>&1' 60"
check "after fixing the image: release objects removed" "! $K get cm inline-cm >/dev/null 2>&1"

# 6. a HelmChart file in <data>/manifests, removed while the server is down
docker exec -i krh1 sh -c 'mkdir -p /var/tmp/srv/manifests && cat > /var/tmp/srv/manifests/file.yaml' <<Y
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata: {name: fromfile, namespace: kube-system}
spec: {chartContent: "$CONTENT", targetNamespace: default, set: {greeting: from-file}}
Y
check "manifests/: HelmChart applied from the file on a live server" "waitfor '$K get cm fromfile-cm -o jsonpath={.data.greeting} 2>/dev/null | grep -qx from-file' 60"
stop_server
docker exec krh1 rm /var/tmp/srv/manifests/file.yaml
start_server
check "manifests/: file removed while down: HelmChart pruned after the restart" "waitfor '! $K get helmchart -n kube-system fromfile >/dev/null 2>&1' 60"
check "manifests/: and its release uninstalled" "waitfor '! $K get cm fromfile-cm >/dev/null 2>&1' 30"
[ $FAIL = 0 ] && { echo PASS; docker rm -f krh1 krhrepo >/dev/null; } || { echo "FAILED (left running; $0 down)"; exit 1; }

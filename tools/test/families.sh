#!/usr/bin/env bash
# Pod network address families on a two-node cluster: tools/test/families.sh 4|6|4,6
# brings the cluster up with KR_POD_FAMILIES (add KR_V6_UNDERLAY=1 for IPv6 hosts) and checks pod
# addresses, cross-node pod traffic, Services, DNS, the kubernetes Service, NodePort and egress.
set -u
MODE=${1:?usage: families.sh 4|6|4,6}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f kr1 kr2 >/dev/null 2>&1
KR_POD_FAMILIES=$MODE KR_HOST_V6=1 "$REPO/tools/test/two-node.sh" up >/dev/null 2>&1 || { echo "cluster did not start"; exit 1; }
K="docker exec -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
KI="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig kr1 kubectl"
IMG=${IMG:-registry.k8s.io/e2e-test-images/agnhost:2.66.1}
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
V4=0; V6=0; case $MODE in *4*) V4=1;; esac; case $MODE in *6*) V6=1;; esac

echo "== nodes and pods (families $MODE)"
CIDRS=$($K get node kr2 -o jsonpath='{.spec.podCIDRs[*]}')
WANT=""; [ $V4 = 1 ] && WANT="10.88.1.0/24"; [ $V6 = 1 ] && WANT="${WANT:+$WANT }fd00:88:0:1::/64"
check node-podcidrs "$CIDRS" "$WANT"
$KI apply -f - >/dev/null <<Y
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      topologySpreadConstraints: [{maxSkew: 1, topologyKey: kubernetes.io/hostname, whenUnsatisfiable: DoNotSchedule, labelSelector: {matchLabels: {app: web}}}]
      containers: [{name: web, image: $IMG, args: [netexec], env: [{name: IPS, valueFrom: {fieldRef: {fieldPath: status.podIPs}}}]}]
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec: {selector: {app: web}, ports: [{port: 80, targetPort: 8080}]}
---
apiVersion: v1
kind: Service
metadata: {name: webnp}
spec: {type: NodePort, selector: {app: web}, ports: [{port: 80, targetPort: 8080, nodePort: 30098}]}
---
apiVersion: v1
kind: Pod
metadata: {name: probe}
spec:
  containers: [{name: c, image: $IMG, command: [sleep, "3600"]}]
Y
$K rollout status deploy/web --timeout=120s >/dev/null; $K wait --for=condition=Ready pod/probe --timeout=60s >/dev/null
sleep 6
IPS=$($K get pod -l app=web -o jsonpath='{range .items[*]}{.status.podIPs[*].ip}{"\n"}{end}' | head -1)
n=$(echo $IPS | wc -w); check pod-ip-count "$n" "$((V4 + V6))"
echo "$IPS" | grep -q : && h6=1 || h6=0; echo "$IPS" | grep -q '\.' && h4=1 || h4=0
check pod-has-v4 "$h4" "$V4"; check pod-has-v6 "$h6" "$V6"
PODIP=$($K get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
check podip-primary-family "$(case $PODIP in *:*) echo 6;; *) echo 4;; esac)" "$([ $V4 = 1 ] && echo 4 || echo 6)"
fmt() { case $1 in *:*) echo "[$1]";; *) echo "$1";; esac; }

echo "== pod to pod across nodes"
for ip in $($K get pod -l app=web -o jsonpath='{.items[*].status.podIP}'); do
  check "probe->pod $ip" "$($K exec probe -- /agnhost connect "$(fmt $ip):8080" --timeout=3s 2>&1; echo rc=$?)" "rc=0"
done

echo "== Services and DNS"
CIP=$($K get svc web -o jsonpath='{.spec.clusterIP}')
check service-family "$(case $CIP in *:*) echo 6;; *) echo 4;; esac)" "$([ $V4 = 1 ] && echo 4 || echo 6)"
seen() { for _ in 1 2 3 4 5 6; do docker exec kr1 curl -s -m3 "$2"; echo; done | sort -u | grep -c web; }
check clusterip-reaches-both-pods "$(seen "$(fmt $CIP):80" "http://$(fmt $CIP):80/hostname")" 2
check dns-service "$($K exec probe -- /agnhost connect web.default.svc.cluster.local:80 --timeout=3s >/dev/null 2>&1; echo $?)" 0
NS=$($K exec probe -- grep nameserver /etc/resolv.conf | awk '{print $2}')
check resolv-nameserver "$(case $NS in *:*) echo 6;; *) echo 4;; esac)" "$([ $V4 = 1 ] && echo 4 || echo 6)"
check kube-dns-clusterip "$($K -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}' | grep -c ':')" "$([ $V4 = 1 ] && echo 0 || echo 1)"
check kubernetes-svc "$($K exec probe -- /agnhost connect kubernetes.default.svc.cluster.local:443 --timeout=3s >/dev/null 2>&1; echo $?)" 0
KH=$($K exec probe -- sh -c 'cat /proc/1/environ' | tr '\0' '\n' | sed -n 's/^KUBERNETES_SERVICE_HOST=//p')
check kubernetes-host-env-family "$(case $KH in *:*) echo 6;; *) echo 4;; esac)" "$([ $V4 = 1 ] && echo 4 || echo 6)"

echo "== NodePort, env, egress"
NPH=127.0.0.1; [ $V4 = 0 ] && NPH='[::1]'
check nodeport "$(docker exec kr1 curl -s -m3 http://$NPH:30098/hostname | cut -c1-4)" "web-"
POD=$($K get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
check env-podips "$($K exec $POD -- sh -c "tr '\\0' '\\n' </proc/1/environ | sed -n s/^IPS=//p" | tr ',' '\n' | grep -c .)" "$((V4 + V6))"
docker exec kr1 sh -c 'mkdir -p /srvx && echo hi > /srvx/index.html; cd /srvx; (python3 -m http.server 8001 --bind 0.0.0.0 >/dev/null 2>&1 &); (python3 -m http.server 8002 --bind :: >/dev/null 2>&1 &)' 2>/dev/null
sleep 1
if [ $V4 = 1 ]; then H4=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' kr1); check egress-v4 "$($K exec probe -- /agnhost connect $H4:8001 --timeout=3s >/dev/null 2>&1; echo $?)" 0; fi
if [ $V6 = 1 ]; then check egress-v6 "$($K exec probe -- /agnhost connect '[fd05::1]:8002' --timeout=3s >/dev/null 2>&1; echo $?)" 0; fi
[ $fail = 0 ] && echo "families $MODE: all checks passed" || { echo "families $MODE: FAILED"; exit 1; }

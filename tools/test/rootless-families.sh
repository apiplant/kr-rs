#!/usr/bin/env bash
# Rootless pod network families (ADR-034): tools/test/rootless-families.sh 4|6|4,6
# In a throwaway privileged container a non-root user runs (1) `kr ctr run` and (2) a rootless
# `kr server` with a pod, both with KR_POD_FAMILIES=MODE. A network namespace with fd01::2 and
# 10.99.0.2 plays the outside world. Checks the addresses the workloads have (and lack), egress
# over each family, name lookup through the forwarder and cluster DNS.
# Needs docker, kubectl, target/release/kr and the ${KR_TEST_IMAGE:-archlinux:base-devel} image (network for the alpine pull).
set -u
MODE=${1:?usage: rootless-families.sh 4|6|4,6}
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
docker run --rm --privileged -e MODE="$MODE" -v "$KR:/kr:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" ${KR_TEST_IMAGE:-archlinux:base-devel} bash -c '
set -u
V4=0; V6=0; case $MODE in *4*) V4=1;; esac; case $MODE in *6*) V6=1;; esac
useradd -m u && echo u:100000:65536 > /etc/subuid && echo u:100000:65536 > /etc/subgid
mkdir -p /home/u/kr /home/u/srv-root && mount -t tmpfs -o size=3g,exec tmpfs /home/u/kr && chown u /home/u/kr
chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap
ip netns add t && ip link add vt0 type veth peer name vt1 netns t
ip addr add fd01::1/64 dev vt0 nodad && ip addr add 10.99.0.1/24 dev vt0 && ip link set vt0 up
ip -n t addr add fd01::2/64 dev vt1 nodad && ip -n t addr add 10.99.0.2/24 dev vt1 && ip -n t link set vt1 up && ip -n t link set lo up
mkdir -p /srv && echo hello > /srv/index.html
(cd /srv && ip netns exec t python3 -m http.server 8000 --bind :: >/dev/null 2>&1 &)
(cd /srv && ip netns exec t python3 -m http.server 8001 --bind 0.0.0.0 >/dev/null 2>&1 &)
sleep 1
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got $2 want $3"; fail=1; fi; }
cat > /home/u/run.sh <<'"'"'S'"'"'
echo v4addr=$(ip -4 addr show eth0 | grep -c "inet 10.88")
echo v6addr=$(ip -6 addr show eth0 | grep -c "inet6 fd00:88:")
echo dns=$(nslookup example.com 2>/dev/null | grep -c "^Address.*[0-9a-f]")
echo ns=$(grep -c nameserver /etc/resolv.conf)
echo get4=$(wget -qO- -T5 http://10.99.0.2:8001/ 2>/dev/null)
echo get6=$(wget -qO- -T5 http://[fd01::2]:8000/ 2>/dev/null)
S
echo "== kr ctr run (families $MODE)"
OUT=$(su u -c "KR_POD_FAMILIES=$MODE KR_ROOT=/home/u/kr /kr ctr run docker.io/library/alpine:3.20 -- sh -c \"\$(cat /home/u/run.sh)\"" 2>&1)
v() { echo "$OUT" | sed -n "s/^$1=//p"; }
check ctr-v4addr "$(v v4addr)" $V4; check ctr-v6addr "$(v v6addr)" $V6
check ctr-dns "$([ "$(v dns)" -ge 1 ] 2>/dev/null && echo ok)" ok
check ctr-ns "$(v ns)" 1
check ctr-get6 "$(v get6)" "$([ $V6 = 1 ] && echo hello)"
check ctr-get4 "$(v get4)" "$([ $V4 = 1 ] && echo hello)"

echo "== rootless kr server pod (families $MODE)"
su u -c "KR_POD_FAMILIES=$MODE KR_ROOT=/home/u/kr /kr server --data /home/u/srv > /home/u/srv.log 2>&1 &"
export KUBECONFIG=/home/u/srv/admin.kubeconfig
for _ in $(seq 60); do kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 1; done
echo "node podCIDRs: $(kubectl get node -o jsonpath="{.items[0].spec.podCIDRs}")"
kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sleep, "3600"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: d}
spec:
  dnsPolicy: Default
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sleep, "3600"]}]
Y
kubectl wait --for=condition=Ready pod/p pod/d --timeout=120s >/dev/null 2>&1
sleep 3
IPS=$(kubectl get pod p -o jsonpath="{.status.podIPs[*].ip}")
echo "pod IPs: $IPS"
check pod-v4 "$(echo $IPS | grep -c "\.")" $V4; check pod-v6 "$(echo $IPS | grep -c :)" $V6
P() { kubectl exec p -- sh -c "$1" 2>&1; }
D() { kubectl exec d -- sh -c "$1" 2>&1; }
[ $V6 = 1 ] && check pod-egress-v6 "$(P "wget -qO- -T5 http://[fd01::2]:8000/")" hello
[ $V4 = 1 ] && check pod-egress-v4 "$(P "wget -qO- -T5 http://10.99.0.2:8001/")" hello
check pod-cluster-dns "$([ "$(P "nslookup kubernetes.default.svc.cluster.local" | grep -c "^Address.*[0-9a-f]")" -ge 2 ] && echo ok)" ok
check pod-external-dns "$([ "$(P "nslookup example.com" | grep -c "^Address.*[0-9a-f]")" -ge 1 ] && echo ok)" ok
check default-policy-dns "$([ "$(D "nslookup example.com" | grep -c "^Address.*[0-9a-f]")" -ge 1 ] && echo ok)" ok
check pod-reaches-kubernetes-svc "$(P "wget -qO- -T5 --no-check-certificate https://kubernetes.default.svc.cluster.local/healthz 2>&1" | head -c 40 | grep -c -e ok -e Forbidden -e Unauthorized -e 401 -e 403)" 1
# pods/proxy reaches a rootless pod through the node (the API server cannot route to the pod network)
kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: w}
spec:
  containers: [{name: c, image: docker.io/library/alpine:3.20, command: [sh, -c, "while true; do printf \"HTTP/1.0 200 OK\\r\\nContent-Length: 8\\r\\n\\r\\nproxied\\n\" | nc -l -p 8080; done"]}]
Y
kubectl wait --for=condition=Ready pod/w --timeout=120s >/dev/null 2>&1; sleep 2
check pod-proxy "$(kubectl get --raw /api/v1/namespaces/default/pods/w:8080/proxy/ 2>&1)" proxied
[ $fail = 0 ] && echo "rootless families $MODE: all checks passed" || { echo "FAILED"; tail -5 /home/u/srv.log; exit 1; }
'

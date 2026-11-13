#!/bin/bash
# NVIDIA GPUs for real (#160, #164, #166): a single kr server krgpu in a throwaway privileged
# container given the host's GPUs (docker --gpus all, nvidia-container-toolkit on the host), with
# the real k8s-device-plugin, MPS control daemon and dcgm-exporter (dev only).
#  1. time-slicing (replicas 4): 4 pods share one GPU, a 5th is Pending
#  2. a server restart keeps the GPU pods' processes and their allocations
#  3. RuntimeClass nvidia + NVIDIA_VISIBLE_DEVICES; a CDI poststop hook runs on pod deletion
#  4. PodResources: dcgm-exporter --kubernetes labels metrics with pod/namespace/container
#  5. MPS (replicas 4): 4 pods run CUDA through one nvidia-cuda-mps-server (needs hostPID)
# MIG needs an A100/H100-class GPU and is not covered.
#   tools/test/gpu.sh [down]     (needs target/release/kr, nvidia-ctk + nvidia-cdi-hook on the host)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f krgpu >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
K="docker exec -i -e KUBECONFIG=/var/tmp/srv/admin.kubeconfig krgpu kubectl"
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 3; done; return 1; }
alloc() { $K get node krgpu -o jsonpath='{.status.allocatable.nvidia\.com/gpu}' 2>/dev/null; }
DP=nvcr.io/nvidia/k8s-device-plugin:v0.17.0

docker run -d --init --name krgpu --hostname krgpu --network krnet --privileged --gpus all \
  -e NVIDIA_DRIVER_CAPABILITIES=all --tmpfs /store:exec,size=12g \
  -v "$REPO/target/release:/krbin:ro" -v "$(command -v kubectl):/usr/local/bin/kubectl:ro" \
  ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
# What the NVIDIA toolkit installs on a GPU node: its hooks, a CDI spec owned by root, and a
# shared mount for MPS (systemd makes / shared on a real host; a container's / is private).
docker cp -L "$(command -v nvidia-cdi-hook)" krgpu:/usr/bin/nvidia-cdi-hook >/dev/null
docker cp -L "$(command -v nvidia-ctk)" krgpu:/usr/bin/nvidia-ctk >/dev/null
docker exec krgpu sh -c 'mkdir -p /etc/cdi && nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml >/dev/null 2>&1
  # Distributions with a merged /usr/sbin (Arch) get the MPS binaries mapped to /usr/sbin, where
  # the MPS daemon (started without PATH) does not look: map them where NVIDIA puts them.
  sed -i "s|containerPath: /usr/sbin/nvidia-cuda-mps-|containerPath: /usr/bin/nvidia-cuda-mps-|" /etc/cdi/nvidia.yaml
  chown -R root:root /etc/cdi /usr/bin/nvidia-cdi-hook /usr/bin/nvidia-ctk; chmod 644 /etc/cdi/nvidia.yaml
  mkdir -p /run/nvidia/mps && mount --bind /run/nvidia/mps /run/nvidia/mps && mount --make-rshared /run/nvidia/mps'
start_server() { docker exec -d krgpu sh -c "echo \$\$ > /tmp/srv.pid; KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --data /var/tmp/srv >> /tmp/srv.log 2>&1"; waitfor "$K get --raw /healthz >/dev/null 2>&1" 30; }
stop_server() { docker exec krgpu sh -c 'kill $(cat /tmp/srv.pid)'; waitfor "! docker exec krgpu sh -c 'kill -0 \$(cat /tmp/srv.pid) 2>/dev/null'" 10; }
start_server
waitfor '$K get nodes --no-headers 2>/dev/null | grep -q " Ready"' 20

sharing() { # time-slicing|mps
  cat <<Y | $K apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata: {name: dp-config, namespace: kube-system}
data:
  config.yaml: |
    version: v1
    sharing:
      ${1}:
        resources: [{name: nvidia.com/gpu, replicas: 4}]
Y
}
sharing timeSlicing
cat <<Y | $K apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: nvidia}
handler: nvidia
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: nvidia-device-plugin, namespace: kube-system}
spec:
  selector: {matchLabels: {app: ndp}}
  template:
    metadata: {labels: {app: ndp}}
    spec:
      runtimeClassName: nvidia
      priorityClassName: system-node-critical
      tolerations: [{operator: Exists}]
      containers:
      - name: p
        image: $DP
        env:
        - {name: CONFIG_FILE, value: /cfg/config.yaml}
        - {name: DEVICE_LIST_STRATEGY, value: cdi-cri}
        - {name: NVIDIA_VISIBLE_DEVICES, value: all}
        - {name: NVIDIA_DRIVER_CAPABILITIES, value: all}
        - {name: NVIDIA_DRIVER_ROOT, value: /}
        - {name: CONTAINER_DRIVER_ROOT, value: /driver-root}
        - {name: MPS_ROOT, value: /run/nvidia/mps}
        - {name: FAIL_ON_INIT_ERROR, value: "true"}
        securityContext: {privileged: true}
        volumeMounts:
        - {name: dp, mountPath: /var/lib/kubelet/device-plugins}
        - {name: cdi, mountPath: /var/run/cdi}
        - {name: cfg, mountPath: /cfg}
        - {name: root, mountPath: /driver-root, readOnly: true}
        - {name: mps, mountPath: /run/nvidia/mps}
        - {name: mps, mountPath: /mps}
      volumes:
      - {name: dp, hostPath: {path: /var/lib/kubelet/device-plugins}}
      - {name: cdi, hostPath: {path: /var/run/cdi, type: DirectoryOrCreate}}
      - {name: cfg, configMap: {name: dp-config}}
      - {name: root, hostPath: {path: /}}
      - {name: mps, hostPath: {path: /run/nvidia/mps, type: DirectoryOrCreate}}
Y
check "device plugin registered, time-slicing: 4 nvidia.com/gpu from one GPU" "waitfor '[ \"\$(alloc)\" = 4 ]' 100"

# 1. time-slicing
cat <<'Y' | $K apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: ts}
spec:
  replicas: 5
  selector: {matchLabels: {app: ts}}
  template:
    metadata: {labels: {app: ts}}
    spec:
      containers:
      - name: c
        image: nvcr.io/nvidia/cuda:12.6.3-base-ubuntu24.04
        command: [sh, -c, 'nvidia-smi -L; sleep 3600']
        resources: {limits: {nvidia.com/gpu: 1}}
Y
check "time-slicing: 4 pods Running, each sees the GPU" "waitfor '[ \"\$($K logs -l app=ts --tail=-1 2>/dev/null | grep -c \"^GPU 0\")\" = 4 ]' 100"
check "time-slicing: the 5th pod is Pending (Insufficient nvidia.com/gpu)" "$K get pods -l app=ts --field-selector status.phase=Pending -o jsonpath='{.items[*].status.conditions[0].message}' | grep -q 'Insufficient nvidia.com/gpu'"

# 2. a server restart
procs() { docker exec krgpu sh -c 'pgrep -f "^sleep 3600" | sort | tr "\n" " "'; }
BEFORE=$(procs)
stop_server; start_server
sleep 15
check "restart: GPU pods kept their processes" "[ \"\$(procs)\" = '$BEFORE' ]"
check "restart: still 4 allocatable, 4 Running, 1 Pending" "[ \"\$(alloc)\" = 4 ] && [ \"\$($K get pods -l app=ts --no-headers | grep -c Running)\" = 4 ] && [ \"\$($K get pods -l app=ts --no-headers | grep -c Pending)\" = 1 ]"
check "restart: the server ignores SIGPIPE (hooks that skip stdin cannot kill it)" "docker exec krgpu sh -c 'grep SigIgn /proc/\$(cat /tmp/srv.pid)/status' | grep -q '1000\$'"
$K delete deploy ts --wait=true >/dev/null

# 3. RuntimeClass + a CDI poststop hook (plus one that never reads its stdin)
docker exec krgpu sed -i '0,/^    hooks:$/s//    hooks:\n        - {hookName: poststop, path: \/bin\/sh, args: [sh, -c, "cat >> \/tmp\/poststop.log; echo >> \/tmp\/poststop.log"]}\n        - {hookName: poststop, path: \/bin\/true, args: ["true"]}/' /etc/cdi/nvidia.yaml
cat <<'Y' | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: rc}
spec:
  runtimeClassName: nvidia
  containers:
  - name: c
    image: nvcr.io/nvidia/cuda:12.6.3-base-ubuntu24.04
    env: [{name: NVIDIA_VISIBLE_DEVICES, value: all}]
    command: [sh, -c, 'nvidia-smi -L; grep SigIgn /proc/self/status; sleep 3600']
Y
check "RuntimeClass nvidia: nvidia-smi sees the GPU" "waitfor '$K logs rc 2>/dev/null | grep -q \"^GPU 0\"' 40"
check "containers start with default signal dispositions" "$K logs rc | grep -q 'SigIgn:.*0000000000000000'"
$K delete pod rc --wait=true >/dev/null
check "CDI poststop hook ran on deletion with the stopped state" "waitfor 'docker exec krgpu grep -q \"\\\"status\\\":\\\"stopped\\\"\" /tmp/poststop.log' 5"
check "server still up after a hook that ignores its stdin" "$K get --raw /healthz >/dev/null"

# 4. PodResources with dcgm-exporter
$K run hold --image=nvcr.io/nvidia/cuda:12.6.3-base-ubuntu24.04 --overrides='{"spec":{"containers":[{"name":"hold","image":"nvcr.io/nvidia/cuda:12.6.3-base-ubuntu24.04","command":["sleep","3600"],"resources":{"limits":{"nvidia.com/gpu":1}}}]}}' >/dev/null
cat <<'Y' | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: dcgm, namespace: kube-system}
spec:
  runtimeClassName: nvidia
  containers:
  - name: e
    image: nvcr.io/nvidia/k8s/dcgm-exporter:4.1.1-4.0.4-ubuntu22.04
    args: [-f, /etc/dcgm-exporter/dcp-metrics-included.csv, --kubernetes]
    env: [{name: NVIDIA_VISIBLE_DEVICES, value: all}]
    securityContext: {privileged: true}
    volumeMounts: [{name: pr, mountPath: /var/lib/kubelet/pod-resources}]
  volumes: [{name: pr, hostPath: {path: /var/lib/kubelet/pod-resources}}]
Y
scrape() { docker exec krgpu curl -s -m5 "$($K get pod -n kube-system dcgm -o jsonpath='{.status.podIP}'):9400/metrics"; }
check "dcgm-exporter: GPU metrics carry pod/namespace/container" "waitfor 'scrape | grep \"^DCGM_FI_DEV_FB_USED\" | grep -q \"container=\\\"hold\\\",namespace=\\\"default\\\",pod=\\\"hold\\\"\"' 60"
check "dcgm-exporter: no PodResources errors" "! $K logs -n kube-system dcgm | grep -q 'failure getting pod resources'"
$K delete pod hold --wait=false >/dev/null; $K delete pod -n kube-system dcgm --wait=false >/dev/null

# 5. MPS
sharing mps
cat <<Y | $K apply -f - >/dev/null
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: mps, namespace: kube-system}
spec:
  selector: {matchLabels: {app: mps}}
  template:
    metadata: {labels: {app: mps}}
    spec:
      runtimeClassName: nvidia
      hostPID: true
      tolerations: [{operator: Exists}]
      initContainers:
      - name: mounts
        image: $DP
        command: [mps-control-daemon, mount-shm]
        securityContext: {privileged: true}
        volumeMounts: [{name: mps-root, mountPath: /mps, mountPropagation: Bidirectional}]
      containers:
      - name: d
        image: $DP
        command: [mps-control-daemon]
        env:
        - {name: NODE_NAME, valueFrom: {fieldRef: {fieldPath: spec.nodeName}}}
        - {name: CONFIG_FILE, value: /cfg/config.yaml}
        - {name: NVIDIA_VISIBLE_DEVICES, value: all}
        - {name: NVIDIA_DRIVER_CAPABILITIES, value: "compute,utility"}
        securityContext: {privileged: true}
        volumeMounts:
        - {name: mps-root, mountPath: /mps}
        - {name: mps-shm, mountPath: /dev/shm}
        - {name: cfg, mountPath: /cfg}
      volumes:
      - {name: mps-root, hostPath: {path: /run/nvidia/mps, type: DirectoryOrCreate}}
      - {name: mps-shm, hostPath: {path: /run/nvidia/mps/shm}}
      - {name: cfg, configMap: {name: dp-config}}
Y
check "MPS: control daemon Running, shm tmpfs propagated to the node (Bidirectional)" "waitfor '$K get pods -n kube-system -l app=mps --no-headers 2>/dev/null | grep -q 1/1' 60 && docker exec krgpu findmnt -n -o FSTYPE /run/nvidia/mps/shm | grep -q tmpfs"
check "MPS: control daemon in the node's pid namespace (hostPID)" "docker exec krgpu sh -c 'for p in /proc/[0-9]*; do grep -q \"^nvidia-cuda-mps-control\" \$p/cmdline 2>/dev/null && { grep NSpid \$p/status; break; }; done' | awk '{exit NF!=2}'"
$K -n kube-system delete pod -l app=ndp --wait=true >/dev/null
check "MPS: device plugin re-registered with 4 replicas" "waitfor '$K logs -n kube-system -l app=ndp --tail=3 2>/dev/null | grep -q Registered && [ \"\$(alloc)\" = 4 ]' 60"
cat <<'Y' | $K apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: mpsc}
spec:
  replicas: 4
  selector: {matchLabels: {app: mpsc}}
  template:
    metadata: {labels: {app: mpsc}}
    spec:
      containers:
      - name: c
        image: nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0-ubuntu22.04
        command: [sh, -c, 'for i in 1 2 3; do /cuda-samples/vectorAdd | tail -1; done; sleep 3600']
        resources: {limits: {nvidia.com/gpu: 1}}
Y
check "MPS: 4 pods x 3 CUDA vectorAdd runs pass (an image with a repeated layer)" "waitfor '[ \"\$($K logs -l app=mpsc --tail=-1 2>/dev/null | grep -c ^Done)\" = 12 ]' 100"
check "MPS: one nvidia-cuda-mps-server serves them" "docker exec krgpu nvidia-smi --query-compute-apps=process_name --format=csv,noheader | grep -q nvidia-cuda-mps-server"
[ $FAIL = 0 ] && { echo PASS; docker rm -f krgpu >/dev/null; } || { echo "FAILED (left running; $0 down)"; exit 1; }

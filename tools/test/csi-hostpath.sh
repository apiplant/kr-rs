#!/bin/bash
# CSI with a real driver (#136, #137): csi-driver-host-path v1.15.0 on a single kr server krcsi in a
# throwaway privileged container (dev only). Block claims (volumeDevices), inline (Ephemeral)
# volumes, generic ephemeral volumes, offline and online expansion.
#   tools/test/csi-hostpath.sh [down]     (needs target/release/kr, git, internet)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
docker rm -f krcsi >/dev/null 2>&1 || true
[ "${1:-up}" = down ] && exit 0
docker network create krnet >/dev/null 2>&1 || true
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
MIRRORS=$("$REPO/tools/test/registry-cache.sh" env krnet)
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 3; done; return 1; }
docker run -d --init --name krcsi --hostname krcsi --network krnet --privileged --tmpfs /store:exec,size=3g \
  -v "$REPO/target/release:/krbin:ro" ${KR_TEST_IMAGE:-archlinux:base-devel} sleep infinity >/dev/null
# A privileged container's /dev is a snapshot: loop devices the host creates later (losetup -f in
# the driver for Block claims) have no node in it. Make the first 64.
docker exec krcsi sh -c 'for i in $(seq 0 63); do [ -e /dev/loop$i ] || mknod -m 660 /dev/loop$i b 7 $i; done'
# The plugin mounts volumes back into /var/lib/kubelet (Bidirectional): it must be a shared mount.
docker exec krcsi sh -c 'mkdir -p /var/lib/kubelet && mount --bind /var/lib/kubelet /var/lib/kubelet && mount --make-rshared /var/lib/kubelet'
docker exec -d krcsi sh -c "KR_REGISTRY_MIRRORS=$MIRRORS KR_ROOT=/store exec /krbin/kr server --data /var/tmp/srv > /tmp/srv.log 2>&1"
waitfor "docker exec krcsi test -f /var/tmp/srv/admin.kubeconfig" 20
IP=$(docker inspect -f '{{.NetworkSettings.Networks.krnet.IPAddress}}' krcsi)
docker cp krcsi:/var/tmp/srv/admin.kubeconfig "$W/kc" >/dev/null
sed -i "s|server: https://[^:]*:|server: https://$IP:|" "$W/kc"
export KUBECONFIG=$W/kc
waitfor 'kubectl get nodes --no-headers 2>/dev/null | grep -q " Ready"' 20

git clone -q --depth 1 --branch v8.1.0 https://github.com/kubernetes-csi/external-snapshotter "$W/snap"
kubectl apply -f "$W/snap/client/config/crd" >/dev/null
git clone -q --depth 1 --branch v1.15.0 https://github.com/kubernetes-csi/csi-driver-host-path "$W/hp"
"$W/hp/deploy/kubernetes-latest/deploy.sh" > "$W/deploy.log" 2>&1 || { tail -20 "$W/deploy.log"; FAIL=1; }
check "driver pod Running (all containers ready)" "waitfor '[ \"\$(kubectl get pod csi-hostpathplugin-0 -o jsonpath={.status.containerStatuses[*].ready} 2>/dev/null | tr \" \" \"\\n\" | grep -c true)\" -ge 8 ]' 60"
check "driver registered with the kubelet (CSINode)" "waitfor 'kubectl get csinode krcsi -o jsonpath={.spec.drivers[*].name} | grep -q hostpath.csi.k8s.io' 30"
cat <<'Y' | kubectl apply -f - >/dev/null
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: hp}
provisioner: hostpath.csi.k8s.io
allowVolumeExpansion: true
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: blk}
spec: {storageClassName: hp, volumeMode: Block, accessModes: [ReadWriteOnce], resources: {requests: {storage: 16Mi}}}
---
apiVersion: v1
kind: Pod
metadata: {name: blk}
spec:
  volumes: [{name: d, persistentVolumeClaim: {claimName: blk}}]
  containers:
  - name: c
    image: busybox:1.36
    command: [sh, -c, 'dd if=/dev/urandom of=/tmp/in bs=4k count=16 2>/dev/null && dd if=/tmp/in of=/dev/xvda bs=4k count=16 conv=fsync 2>/dev/null && dd if=/dev/xvda of=/tmp/out bs=4k count=16 2>/dev/null && cmp /tmp/in /tmp/out && echo BLOCK-IO-OK; ls -l /dev/xvda; sleep 3600']
    volumeDevices: [{name: d, devicePath: /dev/xvda}]
---
apiVersion: v1
kind: Pod
metadata: {name: inline}
spec:
  volumes: [{name: v, csi: {driver: hostpath.csi.k8s.io, volumeAttributes: {size: 8Mi}}}]
  containers: [{name: c, image: busybox:1.36, command: [sh, -c, 'echo inline > /v/f && cat /v/f && grep " /v " /proc/mounts; sleep 3600'], volumeMounts: [{name: v, mountPath: /v}]}]
---
apiVersion: v1
kind: Pod
metadata: {name: generic}
spec:
  volumes:
  - name: v
    ephemeral:
      volumeClaimTemplate:
        spec: {storageClassName: hp, accessModes: [ReadWriteOnce], resources: {requests: {storage: 8Mi}}}
  containers: [{name: c, image: busybox:1.36, command: [sh, -c, 'echo generic > /v/f && cat /v/f; sleep 3600'], volumeMounts: [{name: v, mountPath: /v}]}]
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: grow}
spec: {storageClassName: hp, accessModes: [ReadWriteOnce], resources: {requests: {storage: 16Mi}}}
Y
check "block: raw device in the container, write/read back" "waitfor 'kubectl logs blk 2>/dev/null | grep -q BLOCK-IO-OK' 60"
check "block: a block device node (not a file)" "kubectl logs blk | grep -q '^b'"
check "inline (Ephemeral) CSI volume mounted and writable" "waitfor 'kubectl logs inline 2>/dev/null | grep -q ^inline' 60"
check "generic ephemeral volume: claim created and bound" "waitfor '[ \"\$(kubectl get pvc generic-v -o jsonpath={.status.phase} 2>/dev/null)\" = Bound ]' 30"
check "generic ephemeral volume: mounted and writable" "waitfor 'kubectl logs generic 2>/dev/null | grep -q ^generic' 60"
check "generic ephemeral volume: claim owned by the pod" "kubectl get pvc generic-v -o jsonpath={.metadata.ownerReferences[0].kind} | grep -qx Pod"
kubectl delete pod generic --wait=true >/dev/null
check "generic ephemeral volume: claim deleted with the pod" "waitfor '! kubectl get pvc generic-v >/dev/null 2>&1' 30"
# Offline expansion (no pod), then online (mounted).
check "offline: claim bound" "waitfor '[ \"\$(kubectl get pvc grow -o jsonpath={.status.phase})\" = Bound ]' 30"
kubectl patch pvc grow -p '{"spec":{"resources":{"requests":{"storage":"32Mi"}}}}' >/dev/null
check "offline expansion: capacity 32Mi" "waitfor '[ \"\$(kubectl get pvc grow -o jsonpath={.status.capacity.storage})\" = 32Mi ]' 40"
cat <<'Y' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: grower}
spec:
  volumes: [{name: v, persistentVolumeClaim: {claimName: grow}}]
  containers: [{name: c, image: busybox:1.36, command: [sh, -c, 'while true; do df -k /v | tail -1; sleep 3; done'], volumeMounts: [{name: v, mountPath: /v}]}]
Y
check "online: pod running on the claim" "waitfor 'kubectl logs grower 2>/dev/null | grep -q /v' 60"
kubectl patch pvc grow -p '{"spec":{"resources":{"requests":{"storage":"64Mi"}}}}' >/dev/null
check "online expansion: capacity 64Mi while mounted" "waitfor '[ \"\$(kubectl get pvc grow -o jsonpath={.status.capacity.storage})\" = 64Mi ]' 60"
check "online expansion: no resize condition left pending" "! kubectl get pvc grow -o jsonpath={.status.conditions[*].type} | grep -q Resizing"
[ $FAIL = 0 ] && { echo PASS; docker rm -f krcsi >/dev/null; } || { cp "$W/kc" "${TMPDIR:-/tmp}/krcsi.kubeconfig"; echo "FAILED (left running: KUBECONFIG=${TMPDIR:-/tmp}/krcsi.kubeconfig; $0 down)"; exit 1; }

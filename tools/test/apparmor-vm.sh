#!/bin/bash
# AppArmor for real (#131): a rootful kr server on an Ubuntu 24.04 cloud VM (QEMU/KVM, user-mode
# network, ssh on localhost:$KR_VM_PORT). Profiles are loaded with apparmor_parser on the VM:
#  - Localhost with a loaded profile that denies a write: the write fails, attr/current names it
#  - Localhost with a profile that is not loaded: CreateContainerConfigError, never started
#  - RuntimeDefault: the host's cri-containerd.apparmor.d (loaded here), and the pod default
#  - Unconfined; the legacy annotation; `kubectl exec` runs under the container's profile
# The VM image and a throwaway ssh key are cached in ~/.cache/kr-vm (dev only).
#   tools/test/apparmor-vm.sh [down]     (needs target/release/kr, qemu-system-x86_64, xorriso, /dev/kvm)
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
C=${XDG_CACHE_HOME:-$HOME/.cache}/kr-vm
PORT=${KR_VM_PORT:-2229}
IMG=noble-server-cloudimg-amd64.img
mkdir -p "$C"
[ -f "$C/vm.pid" ] && { kill "$(cat "$C/vm.pid")" 2>/dev/null; rm -f "$C/vm.pid"; sleep 1; }
[ "${1:-up}" = down ] && exit 0
FAIL=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAIL=1; fi; }
waitfor() { for _ in $(seq "$2"); do eval "$1" && return 0; sleep 3; done; return 1; }
[ -f "$C/$IMG" ] || curl -sfL -o "$C/$IMG.part" "https://cloud-images.ubuntu.com/noble/current/$IMG" && [ -f "$C/$IMG.part" ] && mv "$C/$IMG.part" "$C/$IMG"
[ -f "$C/id" ] || ssh-keygen -q -t ed25519 -N '' -f "$C/id"
rm -f "$C/disk.qcow2"; qemu-img create -q -f qcow2 -F qcow2 -b "$C/$IMG" "$C/disk.qcow2" 20G
mkdir -p "$C/seed"
printf 'instance-id: kr-%s\nlocal-hostname: krvm\n' "$(date +%s)" > "$C/seed/meta-data"
cat > "$C/seed/user-data" <<U
#cloud-config
users:
  - name: kr
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [$(cat "$C/id.pub")]
U
xorriso -as mkisofs -quiet -o "$C/seed.iso" -V cidata -J -r "$C/seed" 2>/dev/null
qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 4 -display none -daemonize -pidfile "$C/vm.pid" \
  -drive file="$C/disk.qcow2",if=virtio -drive file="$C/seed.iso",if=virtio,media=cdrom \
  -nic user,model=virtio,hostfwd=tcp:127.0.0.1:$PORT-:22
SSH="ssh -q -i $C/id -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes kr@127.0.0.1"
waitfor "$SSH true" 60 || { echo "VM did not come up"; exit 1; }
$SSH 'cloud-init status --wait >/dev/null 2>&1; true'
scp -q -i "$C/id" -P $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$REPO/target/release/kr" "$(command -v kubectl)" kr@127.0.0.1:/tmp/
$SSH 'sudo install -m 755 /tmp/kr /tmp/kubectl /usr/local/bin/'
K="$SSH sudo KUBECONFIG=/var/lib/kr/admin.kubeconfig kubectl"

# Profiles: one that denies writes under /data, and a stand-in for containerd's RuntimeDefault
# (k3s's containerd generates and loads it; kr uses it when the host has it).
$SSH 'sudo tee /etc/apparmor.d/kr-deny-data >/dev/null' <<'P'
#include <tunables/global>
profile kr-deny-data flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  file,
  network,
  capability,
  deny /data/** w,
}
P
$SSH 'sudo tee /etc/apparmor.d/cri-containerd.apparmor.d >/dev/null' <<'P'
#include <tunables/global>
profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  network,
  capability,
  file,
  umount,
  deny @{PROC}/sysrq-trigger rwklx,
  deny mount,
}
P
$SSH 'sudo apparmor_parser -r /etc/apparmor.d/kr-deny-data /etc/apparmor.d/cri-containerd.apparmor.d'
check "AppArmor enabled on the VM, both profiles loaded" "$SSH 'sudo cat /sys/kernel/security/apparmor/profiles' | grep -c -E '^(kr-deny-data|cri-containerd.apparmor.d) ' | grep -qx 2"
$SSH 'sudo sh -c "nohup kr server --data /var/lib/kr > /var/log/kr.log 2>&1 &"'
waitfor "$K get nodes --no-headers 2>/dev/null | grep -q ' Ready'" 40
check "kr server Ready on Ubuntu" "$K get nodes --no-headers | grep -q ' Ready'"

pod() { # name, pod securityContext (flow YAML), annotations (flow YAML)
  local sc=${2:-} an=${3:-}
  [ -n "$sc" ] || sc='{}'
  [ -n "$an" ] || an='{}'
  cat <<Y | $K apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $1, annotations: $an}
spec:
  securityContext: $sc
  containers:
  - name: c
    image: busybox:1.36
    command: [sh, -c, 'mkdir -p /data; echo attr=\$(cat /proc/self/attr/current); if echo x > /data/f 2>/dev/null; then echo write=ok; else echo write=denied; fi; sleep 3600']
Y
}
log() { $K logs "$1" 2>/dev/null; }
pod deny '{appArmorProfile: {type: Localhost, localhostProfile: kr-deny-data}}'
pod missing '{appArmorProfile: {type: Localhost, localhostProfile: kr-not-loaded}}'
pod rtdefault '{appArmorProfile: {type: RuntimeDefault}}'
pod nothing
pod unconfined '{appArmorProfile: {type: Unconfined}}'
pod legacy '' '{container.apparmor.security.beta.kubernetes.io/c: localhost/kr-deny-data}'
check "Localhost: the process runs under the profile" "waitfor 'log deny | grep -q \"attr=kr-deny-data (enforce)\"' 60"
check "Localhost: the profile denies the write" "log deny | grep -q write=denied"
check "Localhost, profile not loaded: CreateContainerConfigError" "waitfor '$K get pod missing -o jsonpath={.status.containerStatuses[0].state.waiting.reason} | grep -q CreateContainerConfigError' 30"
check "Localhost, profile not loaded: the message names it" "$K get pod missing -o jsonpath={.status.containerStatuses[0].state.waiting.message} | grep -q kr-not-loaded"
check "RuntimeDefault: cri-containerd.apparmor.d" "waitfor 'log rtdefault | grep -q \"attr=cri-containerd.apparmor.d (enforce)\"' 30"
check "no profile set: RuntimeDefault applies (as upstream with AppArmor on)" "waitfor 'log nothing | grep -q \"attr=cri-containerd.apparmor.d (enforce)\"' 30"
check "Unconfined: unconfined" "waitfor 'log unconfined | grep -q attr=unconfined' 30"
check "legacy annotation localhost/<name>" "waitfor 'log legacy | grep -q \"attr=kr-deny-data (enforce)\"' 30"
check "kubectl exec runs under the container's profile" "$K exec deny -- cat /proc/self/attr/current | grep -q 'kr-deny-data (enforce)'"
check "kubectl exec: the profile still denies the write" "! $K exec deny -- sh -c 'echo y > /data/g' 2>/dev/null"
check "RuntimeDefault denies mount" "! $K exec rtdefault -- mount -t tmpfs t /mnt 2>/dev/null"
[ $FAIL = 0 ] && { echo PASS; "$0" down; } || { echo "FAILED (VM left running: ssh -i $C/id -p $PORT kr@127.0.0.1; $0 down)"; exit 1; }

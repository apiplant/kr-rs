#!/usr/bin/env bash
# securityContext.seccompProfile on a rootless `kr server` (ADR-055): no profile and RuntimeDefault
# run the default filter, Unconfined runs without one, Localhost compiles a profile file (here one
# that makes mkdir fail with EPERM), a missing or invalid file is a CreateContainerConfigError.
#   KR=target/release/kr tools/test/seccomp.sh        (needs kubectl, systemd --user, network)
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-$PWD/target/release/kr}
T=$(mktemp -d); PORT=${PORT:-16449}
trap 'systemctl --user stop kr-seccomp-test.scope >/dev/null 2>&1; systemctl --user reset-failed kr-seccomp-test.scope >/dev/null 2>&1; rm -rf "$T"' EXIT
mkdir -p "$T/root/seccomp"
cat > "$T/root/seccomp/deny-mkdir.json" <<'Y'
{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["mkdir","mkdirat"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}
Y
echo '{"defaultAction":"SCMP_ACT_NOTIFY"}' > "$T/root/seccomp/bad.json"
KR_ROOT=$T/root systemd-run --user --scope --unit=kr-seccomp-test -p Delegate=yes "$KR" server --port "$PORT" --data "$T/data" >"$T/srv.log" 2>&1 &
export KUBECONFIG=$T/data/admin.kubeconfig
for _ in $(seq 60); do kubectl get --raw /healthz >/dev/null 2>&1 && break; sleep 1; done
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
pod() { # name, seccompProfile yaml (or empty)
  kubectl apply -f - >/dev/null <<Y
apiVersion: v1
kind: Pod
metadata: {name: $1}
spec:
  restartPolicy: Never
  containers:
  - name: c
    image: docker.io/library/alpine:3.20
    command: [sh, -c, "grep ^Seccomp: /proc/self/status | tr -d '\\t'; mkdir /tmp/x && echo mkdir-ok || echo mkdir-denied"]
    securityContext: {$2}
Y
}
pod plain ""
pod default 'seccompProfile: {type: RuntimeDefault}'
pod open 'seccompProfile: {type: Unconfined}'
pod local 'seccompProfile: {type: Localhost, localhostProfile: deny-mkdir.json}'
pod missing 'seccompProfile: {type: Localhost, localhostProfile: nothing.json}'
pod bad 'seccompProfile: {type: Localhost, localhostProfile: bad.json}'
pod escape 'seccompProfile: {type: Localhost, localhostProfile: ../root/seccomp/deny-mkdir.json}'
for p in plain default open local; do
  for _ in $(seq 90); do kubectl get pod $p -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Succeeded && break; sleep 1; done
done
out() { kubectl logs "$1" 2>&1 | tr '\n' ' '; }
check "no profile: the default filter, mkdir works" "$(out plain)" "Seccomp:2 mkdir-ok "
check "RuntimeDefault: the default filter" "$(out default)" "Seccomp:2 mkdir-ok "
check "Unconfined: no filter" "$(out open)" "Seccomp:0 mkdir-ok "
check "Localhost: the profile applies (mkdir refused with EPERM)" "$(out local | grep -c "Seccomp:2.*Operation not permitted.*mkdir-denied")" "1"
for p in missing bad escape; do
  for _ in $(seq 30); do kubectl get pod $p -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null | grep -q CreateContainerConfigError && break; sleep 1; done
done
check "missing profile is a config error" "$(kubectl get pod missing -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}')" "CreateContainerConfigError"
check "unsupported action is a config error" "$(kubectl get pod bad -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' | grep -c 'unsupported action')" "1"
check "a path out of the profile directory is refused" "$(kubectl get pod escape -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' | grep -c 'relative path')" "1"
exit $fail

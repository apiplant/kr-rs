#!/usr/bin/env bash
# Secrets encryption at rest (ADR-047): the raw datastore log must not hold a Secret's plaintext,
# the API must still return it, and it survives a restart, a key rotation and reencrypt/disable.
# Rootless; needs target/${PROFILE:-release}/kr (or KR=path) and kubectl.
set -u
cd "$(dirname "$0")/../.."
KR=${KR:-target/${PROFILE:-release}/kr}
T=$(mktemp -d); export KR_ROOT=$T/root; D=$T/srv; PORT=${PORT:-16443}
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
start() { $KR server --data $D --port $PORT >$T/srv.log 2>&1 & echo $! >$T/pid
  for _ in $(seq 60); do kubectl --kubeconfig $D/admin.kubeconfig get --raw /healthz >/dev/null 2>&1 && return; sleep 1; done; echo "server did not start"; cat $T/srv.log; exit 1; }
stop() { kill "$(cat $T/pid)"; wait "$(cat $T/pid)" 2>/dev/null; }
K() { kubectl --kubeconfig $D/admin.kubeconfig "$@"; }
start
K create secret generic s1 --from-literal=pw=hunter2-PLAINTEXT >/dev/null
K create configmap c1 --from-literal=v=visible-CONFIGMAP >/dev/null
check "api returns the secret" "$(K get secret s1 -o jsonpath='{.data.pw}' | base64 -d)" hunter2-PLAINTEXT
sleep 1
HID=$(printf hunter2-PLAINTEXT | base64)
check "plaintext absent from log"  "$(grep -c "hunter2-PLAINTEXT\|$HID" $D/db/log)" 0
check "configmap stays readable in log" "$(grep -c visible-CONFIGMAP $D/db/log)" 1
check "log holds ciphertext" "$([ "$(grep -c "k8s:enc:aesgcm:v1:" $D/db/log)" -gt 0 ] && echo yes)" yes
stop; $KR secrets-encrypt status --data $D
start
check "secret after restart" "$(K get secret s1 -o jsonpath='{.data.pw}' | base64 -d)" hunter2-PLAINTEXT
stop
$KR secrets-encrypt rotate-key --data $D
start
K create secret generic s2 --from-literal=pw=second >/dev/null
check "old secret readable after rotation" "$(K get secret s1 -o jsonpath='{.data.pw}' | base64 -d)" hunter2-PLAINTEXT
# Online re-encryption (#188): s1 still holds the old key's ciphertext; rewrite through the running server.
KEY=$($KR secrets-encrypt status --data $D | awk '/\(writes\)/{print $1}')
$KR secrets-encrypt reencrypt --online --data $D --server https://127.0.0.1:$PORT
sleep 1.5
check "online reencrypt: every stored secret uses the newest key" "$($KR secrets-encrypt status --data $D 2>/dev/null | awk '/stored objects/{f=1;next} f&&NF{print $1}' | tr -d : | sort -u | tr '\n' ' ')" "$KEY "
check "online reencrypt: the secret still reads back" "$(K get secret s1 -o jsonpath='{.data.pw}' | base64 -d)" hunter2-PLAINTEXT
stop
$KR secrets-encrypt reencrypt --data $D
check "no plaintext after reencrypt (snapshot)" "$(grep -c "hunter2-PLAINTEXT\|$HID" $D/db/snapshot)" 0
$KR secrets-encrypt disable --data $D
check "plaintext after disable" "$(grep -c "$HID" $D/db/snapshot)" 1
start
check "secret after disable" "$(K get secret s1 -o jsonpath='{.data.pw}' | base64 -d)" hunter2-PLAINTEXT
stop
# wrong key fails closed
cp $D/encryption-config.json $T/cfg.bak
$KR secrets-encrypt reencrypt --data $D >/dev/null   # identity_first: still plaintext; re-enable below
sed -i 's/"identityFirst":true/"identityFirst":false/' $D/encryption-config.json
$KR secrets-encrypt reencrypt --data $D >/dev/null
sed -i 's/"secret":"[^"]*"/"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="/g' $D/encryption-config.json
$KR server --data $D --port $PORT >$T/bad.log 2>&1; check "wrong key refuses to start" "$(grep -c 'cannot open the datastore' $T/bad.log)" 1
# No restart at all: rotate, then disable, through the running server (#188).
D=$T/srv2; PORT=$((PORT+1))
start
K create secret generic live1 --from-literal=pw=live-PLAINTEXT >/dev/null
HID2=$(printf live-PLAINTEXT | base64)
KEY1=$($KR secrets-encrypt status --data $D | awk '/\(writes\)/{print $1}')
$KR secrets-encrypt rotate-key --online --data $D --server https://127.0.0.1:$PORT
KEY2=$($KR secrets-encrypt status --data $D | awk '/\(writes\)/{print $1}')
check "online rotate-key adds a key" "$([ "$KEY1" != "$KEY2" ] && echo yes)" yes
sleep 1.5
check "online rotate-key: everything uses the new key" "$($KR secrets-encrypt status --data $D 2>/dev/null | awk '/stored objects/{f=1;next} f&&NF{print $1}' | tr -d : | sort -u | tr '\n' ' ')" "$KEY2 "
K create secret generic live2 --from-literal=pw=after >/dev/null
sleep 1.5
check "a secret written after the reload uses the new key" "$($KR secrets-encrypt status --data $D 2>/dev/null | awk '/stored objects/{f=1;next} f&&NF{print $1}' | tr -d : | sort -u | tr '\n' ' ')" "$KEY2 "
$KR secrets-encrypt disable --online --data $D --server https://127.0.0.1:$PORT
sleep 1.5
check "online disable: the log now holds the plaintext again" "$([ "$(grep -c "$HID2" $D/db/log)" -gt 0 ] && echo yes)" yes
check "online disable: the secret reads back" "$(K get secret live1 -o jsonpath='{.data.pw}' | base64 -d)" live-PLAINTEXT
stop
rm -rf $T
exit $fail

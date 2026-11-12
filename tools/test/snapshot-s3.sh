#!/bin/bash
# Rootless end-to-end test of snapshots to S3-compatible storage (ADR-061) against a real MinIO
# (docker, no sudo): scheduled upload + retention pruning, `kr snapshot save/list/restore/delete
# --s3`, then TLS with an endpoint CA / skip-verify / wrong CA.
#   tools/test/snapshot-s3.sh [path/to/kr]     (ports 17463, 19000, 19443; image chainguard/minio)
set -euo pipefail
KR=${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/kr}
command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo "skip: docker not available"; exit 0; }
IMG=${MINIO_IMAGE:-chainguard/minio}
W=${KEEP_DIR:-$(mktemp -d)}
cleanup() { kill $(jobs -p) 2>/dev/null || true; docker rm -f kr-minio-test kr-minio-tls >/dev/null 2>&1 || true; [ -n "${KEEP_DIR:-}" ] || rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/data/kr-bucket" "$W/certs" "$W/a"
export KR_S3_ACCESS_KEY=krtestkey KR_S3_SECRET_KEY=krtestsecret123
minio() { # name host-port [extra args]
  local n=$1 p=$2; shift 2
  docker run -d --name "$n" --user "$(id -u):$(id -g)" -p "127.0.0.1:$p:9000" -e MINIO_ROOT_USER=$KR_S3_ACCESS_KEY -e MINIO_ROOT_PASSWORD=$KR_S3_SECRET_KEY \
    -v "$W/data:/data" -v "$W/certs:/certs" "$IMG" server /data "$@" >/dev/null
}
minio kr-minio-test 19000
sleep 4
S3="--s3 --s3-endpoint 127.0.0.1:19000 --s3-insecure --s3-bucket kr-bucket --s3-folder cluster1"
# 1. scheduled uploads, retention
KR_ROOT=$W/a $KR server --port 17463 --snapshot-interval 3s --snapshot-keep 2 --snapshot-s3 --snapshot-s3-endpoint 127.0.0.1:19000 --snapshot-s3-insecure \
  --snapshot-s3-bucket kr-bucket --snapshot-s3-folder cluster1 >"$W/server.log" 2>&1 & P=$!
for _ in $(seq 60); do [ "$(grep -c 'uploaded snapshot' "$W/server.log" 2>/dev/null || true)" -ge 4 ] && break; sleep 1; done
kill $P; wait $P 2>/dev/null || true
[ "$(ls "$W/data/kr-bucket/cluster1" | wc -l)" = 2 ] || { echo "FAIL: expected 2 objects after pruning"; ls "$W/data/kr-bucket/cluster1"; exit 1; }
grep -q 'pruned 1 old' "$W/server.log" || { echo "FAIL: no prune message"; exit 1; }
# 2. CLI
$KR snapshot list --data "$W/a/server" $S3 | grep -q "s3://kr-bucket/cluster1/kr-snapshot-" || { echo "FAIL: list shows no S3 entry"; exit 1; }
$KR snapshot save --data "$W/a/server" $S3 >/dev/null
N=$(ls "$W/data/kr-bucket/cluster1" | head -1)
$KR snapshot restore "$N" $S3 --data "$W/restored" >/dev/null
[ -s "$W/restored/db/snapshot" ] && [ -s "$W/restored/pki/ca.key" ] || { echo "FAIL: restore from S3 incomplete"; exit 1; }
$KR snapshot delete "$N" $S3 >/dev/null
[ ! -e "$W/data/kr-bucket/cluster1/$N" ] || { echo "FAIL: delete"; exit 1; }
if $KR snapshot restore nope.tar $S3 --data "$W/r2" 2>"$W/err"; then echo "FAIL: restored a missing object"; exit 1; fi
grep -q NoSuchKey "$W/err" || { echo "FAIL: no S3 error text"; cat "$W/err"; exit 1; }
if $KR snapshot list --s3 --s3-endpoint 127.0.0.1:19000 --s3-insecure --s3-bucket kr-bucket --s3-access-key bad --s3-secret-key bad 2>"$W/err"; then echo "FAIL: bad credentials accepted"; exit 1; fi
grep -q InvalidAccessKeyId "$W/err" || { echo "FAIL: bad credentials error"; cat "$W/err"; exit 1; }
# 3. TLS
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/certs/ca.key" -out "$W/certs/ca.pem" -days 2 -subj /CN=s3test-ca >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/certs/private.key" -out "$W/certs/srv.csr" -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$W/certs/ext.cnf"
openssl x509 -req -in "$W/certs/srv.csr" -CA "$W/certs/ca.pem" -CAkey "$W/certs/ca.key" -CAcreateserial -out "$W/certs/public.crt" -days 2 -extfile "$W/certs/ext.cnf" >/dev/null 2>&1
chmod 644 "$W/certs/private.key"
minio kr-minio-tls 19443 --certs-dir /certs
sleep 4
T="--s3 --s3-endpoint 127.0.0.1:19443 --s3-bucket kr-bucket --s3-folder tls"
if $KR snapshot save --data "$W/a/server" $T 2>"$W/err"; then echo "FAIL: untrusted CA accepted"; exit 1; fi
$KR snapshot save --data "$W/a/server" $T --s3-endpoint-ca "$W/certs/ca.pem" >/dev/null
$KR snapshot list --data "$W/restored" $T --s3-skip-ssl-verify | grep -q "s3://kr-bucket/tls/" || { echo "FAIL: skip-ssl-verify list"; exit 1; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/o.key" -out "$W/other.pem" -days 1 -subj /CN=other >/dev/null 2>&1
if $KR snapshot list --data "$W/restored" $T --s3-endpoint-ca "$W/other.pem" 2>/dev/null; then echo "FAIL: wrong CA accepted"; exit 1; fi
echo "snapshot-s3: ok"

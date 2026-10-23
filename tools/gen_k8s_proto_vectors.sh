#!/bin/sh
# Regenerates crates/kr-apiserver/tests/vectors/*.{pb.hex,json} with the real Kubernetes
# protobuf and JSON encoders (k8s.io/api v0.31.0) inside a golang container.
# Dev tooling only; needs docker.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/crates/kr-apiserver/tests/vectors"
mkdir -p "$out"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
  -v "$root/tools/k8s_proto_vectors:/src:ro" -v "$out:/out" golang:1.23 sh -ec '
    mkdir -p /tmp/w && cp /src/main.go /tmp/w/ && cd /tmp/w
    go mod init vectors
    go get k8s.io/api@v0.31.0 k8s.io/apimachinery@v0.31.0
    go mod tidy
    go run . /out'

# Plan: `kr` — a single-binary, no_std, zero-dependency Kubernetes distribution in Rust

## Context
The goal is a k3s-like distribution where the node agent idles at a few MB of RSS, not hundreds. It should be one static binary with no libc, no external crates and as little dependence on the host as possible. The directory (`/mnt/extra/projects/k8s-rs`) is empty, so this is a greenfield design.

**Honest constraints, stated up front:**
- "No dependencies" means no crates.io crates. We still depend on the **Linux kernel ABI**: raw syscalls, namespaces, cgroup v2, netlink, seccomp and overlayfs. A container runtime can't exist without these.
- `no_std` + `alloc`: every crate is `#![no_std]`. Only the final binary crate provides `_start`, a panic handler, a global allocator and a syscall layer written in inline asm.
- Building TLS 1.3 and crypto ourselves is the biggest risk. The plan isolates them in one crate (`kr-crypto`) so a vetted implementation can be swapped in later without touching anything else.
- **Scope:** Kubernetes API compatibility is limited to what `kubectl` and common workloads need: core/v1, apps/v1, batch/v1, coordination, discovery and RBAC. We skip in-tree cloud providers, legacy APIs and alpha features. k3s drops the same things.

## Target budgets
| Component | Binary | Idle RSS |
|---|---|---|
| Agent (kubelet + proxy + runtime + CNI) | < 2 MB | < 8 MB |
| Server (apiserver + store + scheduler + controllers) with 100 pods | < 5 MB (same binary) | < 40 MB |

## Architecture: one binary, multicall
`kr server | kr agent | kr kubectl | kr ctr`. The behaviour is chosen from argv[0] or a subcommand.

Workspace crates. All are `no_std` and none use external deps:
1. **kr-sys**: raw syscalls for x86_64 and aarch64 (inline asm), errno, fd RAII, epoll, timerfd, signalfd, clone3, pidfd, mount/pivot_root, setns, unshare, prctl, seccomp, mmap. No libc.
2. **kr-rt**: `_start`, argv/env/auxv parsing, panic=abort, an allocator (mmap-backed size-class slab), and a single-threaded **epoll executor** for async/await built on hand-written `Waker`s. It has no threads by default, with an optional N-worker mode for the server.
3. **kr-fmt**: JSON (streaming parser and serializer), a minimal YAML subset (for manifests), protobuf wire format, base64 and a duration/quantity parser.
4. **kr-net**: TCP/Unix sockets, an HTTP/1.1 server and client, HTTP/2 (needed for kubectl watch performance; HPACK included), WebSocket/SPDY-lite for `exec`/`logs`/`port-forward`, and netlink (rtnetlink, nftables).
5. **kr-crypto**: SHA-256/384, HMAC, HKDF, X25519, Ed25519, ECDSA P-256 (kubectl and client cert compatibility), AES-GCM and ChaCha20-Poly1305 in constant-time code. Also TLS 1.3 server and client, an X.509 DER parser and generator, and a mini CA for cluster bootstrap. It must pass Wycheproof test vectors.
6. **kr-api**: Kubernetes object model. Codegen at build time (`build.rs` reads OpenAPI JSON, so no runtime dependency) produces `no_std` structs plus JSON/proto codecs. It covers only the selected API groups.
7. **kr-store**: an embedded datastore replacing etcd. It is an append-only log with an in-memory B-tree index and MVCC `resourceVersion`, and supports watch fan-out, compaction and fsync batching. HA comes later through Raft (`kr-raft`) over the same log.
8. **kr-apiserver**: REST routing, authn (x509 client certs, bootstrap and SA tokens as signed JWTs with Ed25519/ES256), RBAC authz, admission (defaulting, validation and built-in plugins only), watch, server-side apply (subset), and aggregated discovery.
9. **kr-controllers**: an informer/workqueue library plus Deployment, ReplicaSet, Job, DaemonSet, StatefulSet (basic), Service/EndpointSlice, Node lifecycle, Namespace GC, ServiceAccount/token and garbage-collector controllers.
10. **kr-scheduler**: filter/score covering resources, node selector/affinity, taints/tolerations and topology spread (basic).
11. **kr-runtime**: an OCI-compatible runtime that **replaces containerd + runc**:
    - Image pull: registry v2 client, manifest/index, gzip inflate (our own), tar extraction and a content-addressed store
    - Rootfs: overlayfs, or a copy fallback
    - Process isolation: clone3 with namespaces, cgroup v2 limits, pivot_root, capabilities drop, seccomp default profile, user namespaces (optional)
    - No CRI gRPC: the kubelet calls the runtime in-process. This is the main memory win over k3s.
12. **kr-net-cni**: a built-in bridge+veth network with host-local IPAM. Cross-node traffic goes through either a VXLAN overlay (netlink) or host-gw routes. It needs no CNI plugin binaries.
13. **kr-proxy**: Service VIPs via nftables programmed directly over netlink, with no `nft`/`iptables` binaries. It also provides in-process cluster DNS (a tiny authoritative DNS server for `cluster.local`), replacing CoreDNS.
14. **kr-kubelet**: pod lifecycle, probes, volumes (emptyDir, hostPath, configMap, secret, projected SA token), logs, exec/attach, node status and lease heartbeat.
15. **kr** (bin): multicall entry, config, bootstrap (`kr server --init` generates the CA and tokens; `kr agent --server URL --token T` joins).

Host requirements: Linux ≥ 5.10 with cgroup v2, overlayfs, nf_tables, vxlan and a writable `/var/lib/kr`. Nothing else, so not even `/bin/sh` is required.

## Phases (each ends in a demo-able milestone)
0. **Foundation** (kr-sys, kr-rt, kr-fmt): a static `no_std` hello-world that runs an epoll HTTP/1.1 echo server. CI covers the x86_64 and aarch64 musl-free targets, with `-C panic=abort`, `opt-level=z`, LTO and `strip`.
1. **Runtime alone** (kr-runtime, kr-net-cni): `kr ctr run docker.io/library/nginx` pulls the image and runs it isolated with networking. Compare with `runc` behaviour.
2. **Crypto + TLS**: TLS 1.3 handshake against `openssl s_client` and Go `crypto/tls` (kubectl's stack), with Wycheproof passing.
3. **Single-node control plane** (kr-api, kr-store, kr-apiserver): stock `kubectl get/apply/watch` works against `kr server`.
4. **Scheduling + kubelet + controllers**: `kubectl create deployment nginx --replicas=3` produces running pods on the same binary.
5. **Services + DNS + multi-node**: a Service VIP and pod DNS work across 2 or more agents.
6. **Hardening**: `exec`/`logs`/`port-forward`, RBAC, SA tokens, fuzzing (cargo-fuzz runs in a separate dev-only harness; the dev tooling may use deps, the shipped code may not), and conformance tests.
7. **HA** (later): kr-raft for 3-server clusters.

## Conformance target (definition of done)
"Certified Kubernetes" means passing the CNCF conformance suite (the upstream e2e tests tagged `[Conformance]`, run with Sonobuoy or Hydrophone) for a supported minor version, submitting the results to `cncf/k8s-conformance`, and signing the CNCF participation agreement. This must be redone for each version claimed. The name stays "kr" (trademark rules); "Certified Kubernetes" is used only after passing.

Required beyond phases 0–6:
- **C1 CustomResourceDefinitions:** apiextensions.k8s.io/v1, structural schemas, pruning, status/scale subresources, watch, and conversion (None strategy first).
- **C2 Admission webhooks:** Validating/MutatingWebhookConfiguration called over TLS; failurePolicy, namespaceSelector/objectSelector, timeouts.
- **C3 Protobuf responses:** e2e clients negotiate protobuf. Encode responses with the generated schema table (request decoding already exists).
- **C4 Typed schemas:** generated from the upstream OpenAPI. Covers published `/openapi/v2` and `/openapi/v3`, defaulting, strict field validation and kind-specific validation.
- **C5 Server-side apply with managedFields** and field-ownership conflicts.
- **C6 Pod surface:** ServiceAccount token projection, downward API, exec/logs/attach/port-forward, probes, lifecycle hooks, init containers, resource limits, securityContext, hostPath/emptyDir/configMap/secret/projected volumes.
- **C7 Networking:** Services (ClusterIP/NodePort), EndpointSlices, cluster DNS, pod-to-pod connectivity across at least 2 nodes.
- **C8 Controllers:** GC by ownerReferences, Deployment/ReplicaSet/StatefulSet/DaemonSet/Job/CronJob, namespace lifecycle, ServiceAccount, ResourceQuota/LimitRange admission.
- **C9 RBAC, aggregated discovery, Events, Leases.**

Milestone: once the kubelet runs pods (phase 4), run Sonobuoy in CI and track the pass count.

## Key design rules
- `#![no_std]` + `#![forbid(unsafe_code)]` in every crate except kr-sys, kr-rt and the kr-crypto asm. Unsafe code is audited and kept in those crates.
- No `std`, no libc, no crates.io deps in `Cargo.lock`, enforced by a CI check (`cargo metadata` must show only workspace members).
- Allocation is arena- or slab-based per request. Watch caches store serialized bytes once and share them via refcounting, instead of decoding each object for each watcher.
- Async without tokio: one hand-rolled executor, with timers in a hierarchical wheel.

## Verification
- Unit tests run per crate on host (`cargo test` with a test-only `std` cfg).
- Size and memory gates in CI: `ls -l` of the binary, and RSS measured via `/proc/<pid>/status` after a 5-minute idle; the job fails if the budgets above are exceeded.
- `kubectl` e2e: a kind-free script boots `kr server` and two `kr agent`s in VMs (qemu/firecracker), applies the sample workloads and checks the results.
- Sonobuoy conformance subset in phase 6 (expect partial pass; failures are tracked).
- Crypto: Wycheproof, interop tests against OpenSSL and Go, and a constant-time check (dudect-style) on the key primitives.

## First implementation step (after approval)
Scaffold the Cargo workspace and build phase 0: kr-sys syscalls, the kr-rt allocator and executor, and the static epoll HTTP echo server. Then measure its size and RSS as a baseline.

## Test scripts
- `tools/test/conformance.sh`: Sonobuoy conformance in a throwaway privileged container (`run quick|full`, `wait`, `results`).
- `tools/test/two-node.sh`: server + agent in two containers.
- `tools/test/unit.sh`: every library crate's tests, failing on any crash or abort (use this, not summed `cargo test` output).

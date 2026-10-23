# Architecture Decisions

Short ADR log. Each entry records the decision, the reasoning and its status. Full roadmap: `docs/PLAN.md`.

## ADR-001: Single multicall binary
`kr server | agent | kubectl | ctr`, dispatched by subcommand or argv[0].
**Why:** one artifact to ship, shared code pages, and no inter-process RPC between the components.
**Status:** accepted.

## ADR-002: `no_std` + `alloc`, no libc, no crates.io dependencies
Every crate is `#![no_std]`. The binary links with `-nostdlib -nostartfiles -static`. `Cargo.lock` may contain only workspace members, and CI enforces this.
**Why:** minimal size and RSS, a fully auditable supply chain, and no dependence on the host libc.
**Cost:** we own crypto/TLS, HTTP/2, JSON, gzip and the runtime. Dev-only tooling (fuzzing, benches) may use deps, but it lives outside the shipped graph.
**Status:** accepted.

## ADR-003: Only the Linux kernel ABI is a dependency
Raw syscalls go through inline asm (`kr-sys`) for x86_64 and aarch64. Host requirements: Linux >= 5.10, cgroup v2, overlayfs, nf_tables, vxlan.
**Why:** a container runtime can't exist without these, and no userspace tools are needed (no iptables, no CNI binaries, no /bin/sh).
**Status:** accepted.

## ADR-004: Own `_start`, allocator and mem* intrinsics in `kr-rt`
`kr-rt` provides the entry point, the panic handler (abort and print to stderr), an mmap-backed size-class allocator, and `memcpy/memmove/memset/memcmp/bcmp`.
**Why:** `compiler_builtins` doesn't export mem* on `-gnu` targets when there is no libc.
**Note:** the phase-0 allocator is single-threaded. Threads will need per-thread slabs or a lock, so revisit this when N-worker mode lands.
**Status:** accepted.

## ADR-005: Hand-rolled epoll executor, no tokio
It is single-threaded by default and uses a hierarchical timer wheel.
**Why:** tokio is std-bound and heavy, and an agent's workload is I/O-bound with low concurrency.
**Status:** accepted (implementation pending; phase 0 uses a plain epoll loop).

## ADR-006: Embedded store replaces etcd
An append-only log, an in-memory B-tree index and MVCC resourceVersion. Raft for HA comes later.
**Why:** etcd is the largest share of k3s/k8s memory. A single-node cluster needs no consensus.
**Status:** accepted.

## ADR-007: In-process container runtime, no CRI/gRPC
The kubelet calls `kr-runtime` directly: OCI image pull, overlayfs, clone3 namespaces, cgroup v2 and seccomp.
**Why:** containerd + shims + gRPC are the main memory cost on a k3s node.
**Status:** accepted.

## ADR-008: Networking built in
A bridge+veth CNI with host-local IPAM, a VXLAN or host-gw overlay over netlink, nftables Service VIPs over netlink, and in-process cluster DNS.
**Why:** this removes flannel, kube-proxy, CoreDNS and the iptables binaries.
**Status:** accepted.

## ADR-009: Crypto isolated in `kr-crypto`
TLS 1.3, X.509 and the primitives are kept behind one crate boundary. Wycheproof vectors and OpenSSL/Go interop tests are mandatory.
**Why:** this is the highest-risk code we write ourselves. Isolation keeps it swappable.
**Status:** accepted.

## ADR-010: Reduced API surface
Only core/v1, apps/v1, batch/v1, coordination, discovery and RBAC are supported. Types are code-generated in `build.rs` from OpenAPI.
**Why:** this covers kubectl and common workloads. Legacy, alpha and cloud-provider code is dropped, as k3s does.
**Status:** accepted.

## ADR-011: Process — delegate simple implementation work
Mechanical or well-specified implementation is delegated to cheaper Sonnet subagents. Design, review and security-sensitive code (crypto, runtime isolation) stay with the main model.
**Status:** accepted (user request, 2026-10-23).

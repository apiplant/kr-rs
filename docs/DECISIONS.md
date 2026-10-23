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
**Status:** accepted (implemented in `kr_rt::exec`).

**Implementation notes:**
- Tasks are `Rc<Task>` (boxed future plus a `queued` flag) with hand-written `RawWakerVTable` wakers over the `Rc`. These wakers are `!Send` in practice and must never leave the executor thread.
- The reactor uses one epoll fd. Fds are registered edge-triggered (`EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`) with a slab index as epoll data. Readiness flags are set by events and cleared on `EAGAIN`, so I/O is always read or written until `EAGAIN`.
- Timers use a hierarchical wheel with 4 levels x 64 slots and 1 ms ticks (about 4.6 h). Longer deadlines are clamped and re-armed when they fire early. The epoll timeout is derived from the next non-empty slot, or -1 if none.
- Loop: poll the tasks queued at the start of the round (a self-waking task cannot starve I/O), then `epoll_wait` (timeout 0 if work is queued), then expire timers.
- Single-thread invariant: all executor state lives in one `static` (`UnsafeCell` + `unsafe impl Sync`, like the allocator). No `RefCell` borrow is held across anything that can drop a waker.

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

## ADR-012: `kr-fmt` scope: JSON, a YAML subset, protobuf wire, base64, quantities
`kr-fmt` is a `no_std` + `alloc` crate with no dependencies at all (not even `kr-sys`) and `#![forbid(unsafe_code)]`. It holds JSON (strict RFC 8259 parser, compact serializer and a zero-copy pull tokenizer), a YAML subset, the protobuf wire format, base64, Kubernetes `resource.Quantity` and Go-format durations.
**Why:** these are the formats `kubectl` and manifests actually use. A full YAML 1.2 implementation is large, error-prone and not needed by a Kubernetes distro.

**JSON:**
- Numbers are held exact as `i64`/`u64`, otherwise as `f64`. The original text is kept so that serialization round-trips byte for byte.
- Objects are an ordered `Vec` and duplicate keys are kept (`get` returns the last).
- The parser has a depth limit (default 64) and an input size limit (default 32 MiB). It is iterative, so hostile nesting cannot overflow the stack.
- Lone surrogates, invalid UTF-8, a BOM, comments and trailing data are rejected. Numbers that overflow `f64` are rejected.

**YAML:** the output is always `json::Value`. Supported:
- block maps and sequences, including a sequence at the same indent as its key;
- flow `[]` and `{}`, including across lines;
- plain, single- and double-quoted scalars with YAML folding rules;
- `|` and `>` block scalars with chomping and indentation indicators;
- comments, and multi-document streams (`---`, `...`).

Scalars use the YAML 1.2 core schema: `null/~`, `true/false` (any of three cases), decimal, `0o` and `0x` ints, and floats. `yes/no/on/off` are strings. Object keys are never typed.

**Rejected with a specific error:**
- Anchors, aliases and tags (`&`, `*`, `!`), and therefore the `<<` merge key. Manifests that use them are expanded by tooling before they reach the cluster. Aliases also enable "billion laughs" amplification, and tags make the data model depend on a type registry. A clear error beats silently misparsing.
- Directives (`%YAML`, `%TAG`) and explicit or complex keys (`? `, collection keys).
- Tab indentation, as the YAML spec requires.
- Duplicate mapping keys, in both block and flow maps. The spec says keys must be unique, and silently taking the last one hides manifest mistakes.
- `.inf` and `.nan`, which JSON cannot represent.
- Single-pair mappings inside flow sequences (`[a: b]`).

**Deviations and choices:**
- `parse_all` drops documents that are empty (only comments and whitespace).
- Content after `--- ` on the marker line is supported.
- Integers outside the 64-bit range become inexact floats.
- A YAML-core int such as `0123` or `+5` is normalized to decimal text.
- The k8s Go stack (yaml.v2/YAML 1.1) would read `yes` as a bool. We follow 1.2 on purpose and manifests that need booleans must write `true`.

**Quantities:**
- A quantity is held exactly as an `i128` mantissa times a power of ten. Binary suffixes are folded into the mantissa. Overflow is an error.
- The one deliberate rounding mirrors Kubernetes: precision below 1n is rounded up (away from zero) to 1n.
- Canonical formatting follows the Go rules: decimal forms use exponents that are multiples of 3, binary forms use the largest dividing power of 1024, and small or fractional binary values fall back to decimal.

**Protobuf:** varint, zigzag, fixed32/64 and length-delimited fields only. Groups are rejected. Length prefixes are capped by a configurable limit.

**Status:** accepted.

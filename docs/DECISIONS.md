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
An append-only log, an in-memory B-tree index and MVCC resourceVersion. HA replicates this log with Raft (ADR-026). `Store::image` is also the backup payload and `Store::from_files` rebuilds a store from `snapshot` + `log` bytes (ADR-043).
**Why:** etcd is the largest share of k3s/k8s memory. A single-node cluster needs no consensus.
**Status:** accepted.

## ADR-007: In-process container runtime, no CRI/gRPC
The kubelet calls `kr-runtime` directly: OCI image pull, overlayfs, clone3 namespaces, cgroup v2 and seccomp.
**Why:** containerd + shims + gRPC are the main memory cost on a k3s node.
**Status:** accepted.

## ADR-008: Networking built in
A bridge+veth CNI with host-local IPAM, a VXLAN or host-gw overlay over netlink, a userspace Service proxy (ADR-022) with nftables only for masquerade, and in-process cluster DNS.
**Why:** this removes flannel, kube-proxy, CoreDNS and the iptables binaries.
**Status:** accepted.

## ADR-009: Crypto isolated in `kr-crypto`
TLS 1.3, X.509 and the primitives are kept behind one crate boundary. Wycheproof vectors and OpenSSL/Go interop tests are mandatory.
**Why:** this is the highest-risk code we write ourselves. Isolation keeps it swappable.
**Status:** accepted.

## ADR-010: Reduced API surface
The resource table in `crates/kr-apiserver/src/resources.rs` is the authority on what is served. It started as core/v1, apps/v1, batch/v1, coordination, discovery and RBAC and has grown to what conformance and common operators need (CRDs, admission, aggregation, certificates, networking, policy, storage, autoscaling, flow control, ...). Types are code-generated in `build.rs` from OpenAPI.
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

## ADR-013: Phase 1 layering, with plain-HTTP registries until TLS lands
*(Historical: TLS landed with ADR-020 and pulls from `https` registries work. The layering below still holds.)*
Crates:
- `kr-archive` handles inflate (RFC 1951/1952) and tar. It is pure: no syscalls, `forbid(unsafe)`.
- `kr-net` holds the HTTP/1.1 client and server plus the OCI distribution (registry v2) client.
- `kr-runtime` covers image store, rootfs, and isolation. The main model owns it because it is security-critical.

Until `kr-crypto` ships TLS (phase 2), images are pulled from a local plain-HTTP registry (`registry:2` on localhost). The registry client is written against a `Transport` trait so that TLS can be plugged in without API changes.
**Why:** this unblocks the runtime without rushing the riskiest crate.
**Status:** accepted.

## ADR-014: `kr-archive` streaming design and the whiteout/sanitize contract
- **Push-based, constant memory:** `Inflater::feed`, `GzDecoder::feed` and `TarReader::feed` take input chunks of any size (down to 1 byte) and deliver output through callbacks. Memory is a 32 KiB window plus one 512-byte header (tar metadata records are capped at 1 MiB). A layer is never buffered whole, and the stack composes as `gzip -> tar -> sink`.
- **Decoder:** the bit reader is lazy about partial symbols (a step that lacks bits consumes nothing and resumes on the next feed). Huffman decoding uses a 10-bit primary table plus a canonical fallback for longer codes. Trees are validated strictly (over-subscribed or incomplete trees are rejected, except zlib's single 1-bit code for literal/length and distance trees). `Status::Done{consumed}` returns the unread tail, which is how gzip finds its trailer and the next member.
- **gzip:** CRC32 (slice-by-8) and ISIZE are verified per member. Multi-member input is supported. Bytes after a member that don't start a new member are `TrailingGarbage`. `finish()` is required to detect truncation.
- **tar:** supports ustar/pax/GNU and reports the already-merged `Entry` (precedence pax > GNU long > header) then `Data` chunks then `End`. Non-file entries carry no data. Strings must be UTF-8.
- **Contract with the runtime (`kr-runtime`):**
  1. Always run `tar::sanitize(entry.path)` first. It is lexical only: it rejects absolute paths, NULs and `..` that escape, and normalizes `.`, `//` and trailing `/`. An empty result is the layer root.
  2. The runtime MUST ALSO defend against symlink traversal when extracting. `sanitize` cannot see that an earlier entry made `a -> /etc`. Use an `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` or `O_NOFOLLOW` walk against the rootfs fd. `linkname` of symlinks and hardlinks is reported verbatim and must be validated by the runtime (hardlink targets are layer-relative and must be sanitized too).
  3. Whiteouts: call `tar::whiteout(sanitized_path)`. `Remove(p)` means delete `p` from the lower layers and do NOT create the marker file. `Opaque(dir)` means clear lower-layer content of `dir` (empty string = root) while keeping this layer's own entries. Apply the removal to lower layers only, never to files already extracted by the same layer. `.wh..wh.*` names other than the opaque marker are reserved (`is_reserved_whiteout`) and must be skipped.
**Why:** the layer unpack path is attacker-controlled input, so the parser is total (never panics, covered by mutation tests), and the policy decisions that need a filesystem stay in the runtime.
**Status:** accepted.

## ADR-015: `kr-net` HTTP/1.1 strictness, `Transport`/`Connector` traits, interim sha256
**Strictness rules** (parser: `kr_net::http1::head`, `body`):
- Lines end in CRLF only. A bare LF or a bare CR anywhere in a head or in chunk framing is an error (RFC 9112 2.2 allows recipients to be lenient; we are not, because lenient line splitting is a classic smuggling differential).
- obs-fold (a header line starting with SP/HTAB) is rejected. Whitespace between the field name and the colon is rejected (the name must be a token). Header values may contain only HTAB, SP, VCHAR and obs-text, and must be valid UTF-8; NUL/CTL/DEL are rejected.
- Request line: exactly `method SP target SP HTTP/1.0|1.1`, one space each; the target is visible ASCII only. HTTP/1.1 requests need exactly one `Host`. Status line: `HTTP/1.x SP 3DIGIT [SP reason]` (the SP before an empty reason may be omitted, which is the one tolerated deviation).
- Limits apply to partial input too, so a peer cannot make us buffer without bound: head 16 KiB, line 8 KiB, 100 headers (configurable via `Limits`). Chunk extensions are capped at 1 KiB, trailers at 8 KiB per line and 16 KiB in total; chunk sizes are 1-16 hex digits with overflow checks.
- Framing: `Transfer-Encoding` together with `Content-Length` is an error (for requests AND responses); `Content-Length` must be `1*DIGIT`, and repeated or comma-listed values must all be equal; the only accepted transfer coding is a single, final `chunked` (anything else, including `gzip, chunked`, is an error); `Transfer-Encoding` in an HTTP/1.0 message is an error. Chunk framing is checked byte by byte; trailers are validated and discarded.
- The client keeps a connection for reuse only after the body is fully consumed with no stray bytes left in the buffer. A reused connection that dies before any response byte arrives is retried once, for GET/HEAD only.
- Redirects: at most 5; the scheme may not change; `Authorization`/`Cookie` are dropped when the origin changes; 303 (and 301/302 for POST) become GET.
- Callers cannot set `Host`, `Content-Length`, `Transfer-Encoding` or `Connection`, and header names/values are validated, so request splitting is impossible from the API.

**Traits:** `Transport` (`async read` / `async write_all`) is implemented for `Async<Fd>`; `Connector` creates a `Transport` for a `Url`. `Client<C: Connector>` and `Registry<C>` are generic over it, so a TLS connector from `kr-crypto` can be added without API changes (ADR-013). `TcpConnector` returns `Error::TlsUnsupported` for `https`. Name resolution goes through a `Resolver` trait; only literals + `/etc/hosts` exist.

**Interim sha256:** `kr_net::sha256` is a small FIPS 180-4 implementation (tested against the standard vectors) used only to verify public manifest and blob digests. It is not constant-time and will be replaced by `kr-crypto`.

**Runtime test support:** `kr-rt` has a `host` feature that removes `_start`, `kr_rt_start`, the panic handler, the global allocator and the `mem*` symbols, so the executor can run under the std test harness. `kr-net` enables it only through `[dev-dependencies]`, so release builds of `kr` are unaffected. Since the executor is single-threaded and global, tests serialise `block_on` calls with a mutex. Do not enable `host` in a shipped binary.
**Status:** accepted.

## ADR-016: Rootless-first runtime using kernel isolation; qemu only for privileged paths
*(Update: the server and agent now run rootful by default, with the host user namespace; rootless is opt-in. The isolation primitives below are used in both modes.)*
`kr-runtime` isolates containers with kernel primitives directly: no podman/runc, consistent with ADR-007.
- A **user namespace** is created first, unprivileged. Inside it we are uid 0 and can create mount, pid, net, uts, ipc and cgroup namespaces, mount overlayfs (Linux ≥ 5.11) and call `pivot_root`.
- **cgroup v2** limits go through a delegated subtree: `systemd-run --user --scope -p Delegate=yes` in dev, and the agent's own systemd unit (`Delegate=yes`) in production. The controllers available rootless are cpu, memory and pids. io and cpuset need a root agent.
- **seccomp** (a BPF filter plus `NO_NEW_PRIVS`) and capability dropping need no privileges.
- Tests run rootless on the dev box, so there is no sudo and no VM in the normal loop. A throwaway **qemu VM** is used only for paths that need real root: host-level network setup (bridge, veth to host, nftables), the io/cpuset controllers, and running as a root agent.
**Verified on the dev box (2026-10-23):** user+mount+pid namespaces, overlayfs inside a userns, netns creation, and cgroup delegation via systemd-run all work unprivileged.
**Status:** accepted.

## ADR-017: Flattened per-image rootfs + per-container overlay; safe unpack via openat2
- Each image's layers are applied in order into one flattened directory: `<root>/images/<config-digest>/rootfs`. Whiteouts are applied by deleting. A container gets an overlay with that directory as `lowerdir` and a private `upper`/`work`, mounted with `userxattr` (ADR-016).
  **Why:** whiteout char devices (0:0) and `trusted.*` xattrs are not reliably creatable rootless, so flattening sidesteps both. (Cost: KNOWN_ISSUES #130.)
- Every filesystem operation during unpack goes through `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` relative to the rootfs dirfd, so the kernel itself prevents symlink and `..` escapes. The lexical `sanitize()` from kr-archive is a first filter, not the guard.
- Layers have a decompression-bomb cap: a per-layer uncompressed byte limit and an entry-count limit, configurable with safe defaults.
- Rootless: device nodes in layers are skipped. uid/gid ownership is not preserved (single-uid mapping). Subuid ranges via `newuidmap` come later.
- Store root: `$KR_ROOT`, defaulting to `$XDG_DATA_HOME/kr`, then `$HOME/.local/share/kr` when rootless, or `/var/lib/kr` when root.
**Status:** accepted.

## ADR-018: Container security profile and cgroup supervision
- **Order in the child:**
  1. Make `/` private.
  2. Mount the overlay.
  3. `pivot_root` into it. No image-controlled path is touched before this.
  4. Mount `/proc` while the old root is still visible.
  5. Mount a fresh `/dev` (tmpfs, with host nodes bind-mounted), `/dev/pts` (newinstance), `/dev/shm` and `/sys` read-only.
  6. Detach the old root.
  7. Bring up `lo` and set the hostname.
  8. Drop capabilities.
  9. Set `NO_NEW_PRIVS`.
  10. Install seccomp.
  11. `execve`.
- **Capabilities:** Docker's default set (`0xa80425fb`). The bounding set is reduced, ambient and inheritable are cleared, and effective = permitted = the set.
- **seccomp:**
  - An arch check, plus a kill on the x32 ABI.
  - A deny-list (EPERM) covering io_uring, bpf, userfaultfd, keyrings, perf, kexec/modules, mount APIs, setns/unshare, time setting, and kcmp/process_vm.
  - `clone3` returns ENOSYS, so libc falls back to `clone`, whose flags *are* inspectable. `clone` with namespace flags gets EPERM.
- **Device access (rootful, non-privileged):** a `BPF_PROG_TYPE_CGROUP_DEVICE` program (`kr_runtime::devfilter`) is attached to the container's cgroup before the child enters it. It allows `null`, `zero`, `full`, `random`, `urandom`, `tty`, `console`, `ptmx`, the container's own `pts` (136:*) and the device nodes the container was given (CDI or device-plugin nodes, `hostPath` device nodes; read-only mounts get read only); `mknod` of anything stays allowed because the node it makes cannot be opened. Privileged and rootless containers get no filter. Failing to attach fails the start; `KR_DEVICE_FILTER=off` disables it. Pods that were started before this keep running unfiltered until they are recreated.
- **Setup errors** travel back to the parent over a CLOEXEC pipe as `(step, errno)`. EOF on that pipe means exec succeeded.
- **cgroups:**
  - kr moves the delegated cgroup's processes into `kr-supervisor` and enables `cpu memory pids` on the parent.
  - Each container gets a sibling cgroup and is spawned into it with `CLONE_INTO_CGROUP`, so it is never briefly unlimited.
  - `memory.swap.max=0` is set with `memory.max`.
  - OOM is detected from `memory.events`.
  - CPU millicores map to `cpu.max` over a 100 ms period.
**Status:** accepted.

## ADR-019: User-namespace id ranges and the built-in bridge network
**Context:**
- Rootless kr mapped a single id, so images that chown or switch users (nginx, postgres) failed.
- Containers had loopback-only networking.
- Both features traditionally pull in external helpers: `newuidmap`, CNI plugin binaries, `iptables`/`nft`.

**Decision:**
- **Id mapping:**
  - Real root gets the identity map. Rootless gets `0 → own uid` plus `1.. → the /etc/subuid range`, written by the setuid `newuidmap`/`newgidmap`.
    - These are the only host binaries kr ever runs, and only when a range exists.
    - The kernel requires a privileged writer for multi-id maps, and these helpers are the standard, distro-audited way to get one.
  - Without a range, kr falls back to a single id.
  - Image `USER` is resolved from the image's own passwd/group after `pivot_root`. Then setgroups → setresgid → setresuid, after the capability drop and before NO_NEW_PRIVS and seccomp.
  - Container state owned by subordinate ids is deleted from inside a throwaway userns with the same maps.
- **Network (root only):**
  - Bridge `kr0` with gateway 10.88.0.1/16.
  - IPAM uses O_EXCL lease files under `<root>/ipam`.
  - Each container gets a veth pair; the parent creates the peer directly in the child's netns as `eth0` before releasing the child, and the child configures address, link and default route itself.
  - Outbound traffic goes through nftables masquerade in table `ip kr`.
  - Everything is programmed via netlink (`kr-net::netlink`, `kr-net::nft`). The veth disappears with the netns, and the lease is released by the supervisor.
  - Rootless networking (slirp/pasta-style) is out of scope; rootless containers stay loopback-only (superseded: rootless `kr ctr run` now shares an infra namespace bridge, see KNOWN_ISSUES #50).
- **Supervision:** `start()` returns a `Running` with a `CLONE_PIDFD` pidfd. `wait()` is async on the epoll executor. SIGINT/SIGTERM are forwarded through a signalfd and `pidfd_send_signal`.

**Status:** accepted.

## ADR-020: kr-crypto and TLS 1.3
**Context:** the plan requires TLS and PKI without external crates. Crypto is the riskiest code in the project.

**Decision:**
- **Crate rules:** `kr-crypto` is `no_std`, `#![forbid(unsafe_code)]`, and depends only on `kr-fmt` (for base64/PEM).
- **Primitives:**
  - SHA-256/384/512 and HMAC/HKDF.
  - ChaCha20-Poly1305 (26-bit limbs).
  - AES-128/256-GCM, bitsliced; the S-box is computed as x^254 plus the affine map, with no tables.
  - X25519 (Montgomery ladder over 51-bit limbs).
  - Ed25519, with cofactorless verification that rejects non-canonical S and points.
  - P-256 ECDSA/ECDH: Montgomery-form `U256`, the complete Renes–Costello–Batina formulas, and RFC 6979 deterministic nonces, so signing never depends on an RNG.
- **Constant time:** secret-dependent code avoids branches and table indexing on secrets. Constants are generated by a script, and the tests re-derive them.
- **Verification (dev tooling only):**
  - RFC/FIPS vectors.
  - Differential vectors from pyca/OpenSSL (`tools/gen_crypto_vectors.py`).
  - The relevant Wycheproof suites, converted by `tools/wycheproof_convert.py`; all of them pass.
  - OpenSSL CLI interop for X.509 and TLS, and the real `kubectl` (Go crypto/tls) against the kr TLS server with mTLS.
- **X.509:**
  - Strict DER. v3 only. Unknown critical extensions are rejected. Hostnames are matched against SANs only.
  - Issuance uses P-256 or Ed25519 CAs with SKI/AKI (RFC 7093 key ids), so OpenSSL's `-x509_strict` accepts the result.
  - Keys are stored as PKCS#8.
- **TLS 1.3 design:** a sans-I/O state machine in `kr-crypto::tls`, with socket glue in `kr-net::tls`.
  - **Server preference:** ChaCha20-Poly1305 first, then AES-128-GCM.
  - **Groups:** X25519 and P-256.
  - **Signatures:** ecdsa_secp256r1_sha256 and ed25519.
  - **Features:** mutual TLS, ALPN, KeyUpdate, and middlebox-compatibility CCS.
  - **Deliberately omitted:** TLS 1.2, resumption and 0-RTT. kubectl and Go clients need none of them.
- **CLI:** `kr pki ca|issue` creates the cluster CA and certificates.

**Status:** accepted.

## ADR-021: kr-store and the API server
**Context:** phase 3 needs a datastore and an API server that stock kubectl accepts, while staying within the memory budget.

**Decision:**
- **kr-store (replaces etcd):**
  - An append-only log of CRC-framed records with an in-memory sorted index and global revisions. Revisions are the Kubernetes `resourceVersion`.
  - Compare-and-swap on mod_rev. Watches replay from bounded history and then run live.
  - Snapshot plus log compaction. A torn tail is truncated; a mid-log CRC failure is a hard error.
  - Callers fsync (`sync()`) before acknowledging.
  - Single-threaded, owned by the API server's executor. Handlers never await mid-transaction, so a read-modify-write is atomic.
- **kr-apiserver:** generic JSON objects, with the server validating only the fields it relies on: type, metadata, labels/annotations and names.
  - **Resources:** a static resource table drives discovery, routing, keys (`/registry/<group>/<plural>/[ns/]name`) and the OpenAPI v3 probe surface.
  - **Patches:** merge patch, JSON patch, and strategic merge patch with a built-in merge-key table.
  - **Server-side apply** has its own implementation (`ssa.rs`, ADR-028 for apply configurations).
  - **Status/scale:** status and scale subresources; `generation` bumps when `spec` changes.
  - **Deletes:** finalizer-aware deletes, and synchronous namespace deletion.
  - **Watches:** chunked NDJSON with selector enter/leave semantics, and 410 for compacted revisions.
  - **Server-side Table printing:** `kubectl get`.
- **Lists:** stored JSON is spliced directly into list responses; no decode/encode per item.
- **Authentication:** TLS client certificates against the cluster CA (CN = user, O = groups), bearer tokens and service-account tokens. Authorization is RBAC plus the Node authorizer (ADR-023).
- **Bootstrap:** `kr server` creates the CA, the apiserver and admin certificates, and `admin.kubeconfig` on first start.
- **Protobuf request bodies** (sent by kubectl's typed clients) are decoded with a generated schema table; responses are always JSON.

**Status:** accepted.

## ADR-022: Services, cluster DNS and multi-node
**Context:** phase 5 needs Service VIPs, cluster DNS and nodes joining a server, without iptables/ipvs/CoreDNS binaries and in both root and rootless modes.

**Decision:**
- **Service proxy:** a userspace proxy inside kr. One `local 10.96.0.0/16` route makes every ClusterIP bindable in the node network namespace.
  - kr listens on ClusterIP:port (and 0.0.0.0:nodePort) and splices to ready endpoints (round-robin or ClientIP affinity). UDP gets per-client sessions.
  - Rootless, a socket factory inside the pod-network namespace creates the sockets and passes them over SCM_RIGHTS.
  - Identical behaviour as root and rootless, no packet-rewrite rules, and simple testing. (Costs: KNOWN_ISSUES #133.)
- **Cluster DNS:** kr serves `cluster.local` itself from a 1 s snapshot of Services, Endpoints and Pods, bound on the kube-dns ClusterIP 10.96.0.10:53. Other names are forwarded to the host resolvers.
  - Pods get resolv.conf per `dnsPolicy`, plus Docker-link service environment variables.
- **Multi-node:**
  - **Join token:** `kr server` writes `node-token` = `K10<sha256 of CA cert>::<id>.<secret>` (a bootstrap-token Secret).
  - **CA bootstrap:** `kr agent` fetches `/cacerts` over TLS pinned to that hash (the CA is in the server's chain).
  - **Node certificates:** it exchanges the token at `POST /kr/join` for a client certificate (`system:node:<name>`, `system:nodes`) and a kubelet serving certificate.
  - **Pod subnets:** each Node gets a /24 of 10.88.0.0/16 (`spec.podCIDR`). Root nodes route each other's subnets via their InternalIPs (host-gw).
  - **Pod subresources:** the API server reaches agents' kubelets at `:10250` with mTLS (`kube-apiserver-kubelet-client`). WebSocket upgrades are completed at the API server and replayed to the node with the client's key, then frames are pumped both ways.

**Status:** accepted.

## ADR-023: Conformance baseline (Kubernetes 1.37) and the Node authorizer

**Context:** The first Sonobuoy run against the 1.37 conformance image surfaced gaps that client-go and the e2e framework depend on: SPDY exec (`sonobuoy retrieve`), protobuf DeleteOptions, API defaulting and field selectors. Also, `system:nodes` could read every secret.

**Decision:**
- **Exec over SPDY/3.1:** the kubelet accepts direct `Upgrade: SPDY/3.1` exec (remotecommand v4 only). It waits for the requested streams (`error`/`stdin`/`stdout`/`stderr`, `resize` ignored), then pumps them. With SPDY, query flags are strict: a stream absent from the query is off.
- **Defaulting** (`defaults.rs`): upstream `SetDefaults_*` for the core/apps/batch fields clients observe. It runs on create and on every non-status update and fills only absent fields. Typed validation is still out of scope.
- **Node authorizer** (`node_authz.rs`), ahead of RBAC, for `system:node:<n>` in `system:nodes`:
  - get of secrets/configmaps/PVCs referenced by pods bound to `<n>`: Allow; other reads: defer to RBAC (which no longer grants them to nodes).
  - writes to pods/pods-status not bound to `<n>`, other Nodes, other node Leases, pod creation, secret writes: Deny (NodeRestriction folded in; the created object's name is read from the body for POSTs).
  - serviceaccounts/token: only for service accounts used by the node's pods.
- **Credential lifetimes:**
  - **Join tokens:** `kr token create [--ttl]` creates a bootstrap-token Secret with `expiration`, using the local admin certificate.
  - **Node certificate rotation:** `/kr/join` also accepts a node's own certificate and re-issues for the same name only. The agent renews at 2/3 of the lifetime with fresh keys, replaces the files via rename, and swaps the TLS configs in place (`Remote::set_client_cert`, the kubelet server's `tls_slot`).
  - `KR_NODE_CERT_SECONDS` shortens node certificates for testing.
  - CertificateSigningRequests are approved (kubelet signers, node requestor only) and signed with the cluster CA by the CSR controller (ADR-042); kr's own node join flow still issues certificates directly.

**Status:** accepted.

## ADR-024: Group commit with fsync off the event loop; log compaction

**Context:** In the first full conformance runs the server stalled: kr-store fsynced the log on every write, inside the single-threaded event loop. Under the e2e suite's write load, kr spent most of its time in `D` state (`jbd2_log_wait_commit`), and the API, kubelet and controllers all froze together. Nothing called `Store::compact`, so the log reached 255 MB after 43 minutes, which also made restarts slow.

**Decision:**
- **Writes:** `Store::write_out` writes records to the log, landing in the page cache without blocking on the disk.
- **Acknowledgement:** an API write is acknowledged only after `ApiServer::commit` reports it durable, which keeps etcd's semantics.
- **Where the fsync runs:**
  - It runs in a helper process (`kr_sys::ns::spawn_fsync_helper`). The helper is a fork-style child with `CLONE_FILES`, so it shares kr's fd table.
  - kr sends it the log fd number over a pipe, and it answers with one byte. A death signal makes it exit when kr exits.
  - A process is used instead of a thread because the runtime is single-threaded by design (KNOWN_ISSUES #3).
- **Group commit:** while one fsync is in flight, later writers wait and share the next fsync, so there is one fsync per batch.
- **Fallback:** if the helper can't start or dies, commits fall back to a blocking fsync.
- **In-process writers:** the controllers and the server's own kubelet call the API in-process and don't await durability. A background task flushes their writes every second. (Durability limits: KNOWN_ISSUES #127.)
- **Compaction:** every minute, the log is rewritten into a snapshot once it exceeds 8 MiB and is more than 4× the live data.

**Status:** accepted.

## ADR-025: VXLAN overlay as the default pod network backend

**Context:** host-gw (ADR-022) only works when all nodes share an L2 segment.

**Decision:**
- **Selection:** `KR_NET_BACKEND=vxlan|host-gw` is read by `kr server` and `kr agent`; the default is `vxlan`.
- **Device:** each root node creates `kr.vxlan` over raw netlink (VNI 1, UDP 8472, `nolearning`, local = InternalIP, MTU = uplink - 50) with the node's pod-subnet network address as a /32.
- **VTEP identity:** the MAC is `02:4b:<InternalIP>`; the kubelet publishes it as the Node annotations `kr.io/vtep-mac` and `kr.io/vtep-ip`.
- **Per peer:** route `podCIDR via <peer subnet address> dev kr.vxlan onlink` (`RTPROT_KR`), a permanent ARP entry to the peer's VTEP MAC and an FDB entry MAC -> peer InternalIP. There is no flood, learning or multicast.
- **Reconcile:** the existing 5 s loop diffs wanted against installed routes, ARP entries and FDB entries and removes stale ones.
- **NAT:** the masquerade rule already skips cluster-CIDR destinations, so pod source IPs survive.

**Status:** accepted.

## ADR-026: kr-raft, replicating the kr-store log across servers (HA)

**Context:** kr-store (ADR-021) lives on one server, so losing it stops the control plane. HA needs 3 (or 5) servers that agree on one ordered history of writes, survive the loss of a minority, and give every server identical revisions (`resourceVersion`) and watch streams.

**Decision:**
- **What is replicated:** kr-store's own write-ahead records (op, revision, create revision, key, value), not API requests.
  - The leader's store applies a write as today. The records it produces become the payload of a Raft log entry.
  - Followers apply committed records verbatim, through the same path startup replay uses.
  - Revisions are therefore assigned once, by the leader, and are identical everywhere.
  - Precondition failures (409) produce no record, so they never reach the log.
- **Consensus:** Raft (Ongaro & Ousterhout), in a sans-I/O crate `kr-raft`.
  - Covered: leader election with randomized timeouts and pre-vote, log replication with conflict-index backtracking, a commit rule restricted to current-term entries, snapshots with InstallSnapshot, and single-server membership changes (one at a time, effective on append).
  - It is driven by `tick()`, `step(msg)` and `propose()`, and its output (messages, entries to persist, committed entries, snapshots) is handed back in a `Ready` value. It is tested with a simulated network that drops, reorders, duplicates and partitions messages, while invariants are checked continuously.
- **Durability:**
  - The Raft log and hard state (term, vote) on each server replace the kr-store log file.
  - A write is acknowledged when its entry is committed, meaning a majority has fsynced it. The local fsync still goes through the ADR-024 helper.
  - Snapshots are kr-store snapshots tagged with the Raft index, term and membership.
- **Speculative state on the leader:**
  - The leader's store already holds writes that aren't committed yet.
  - Watch events are released only up to the committed revision.
  - If a leader steps down with uncommitted entries that the new leader then overwrites, it rebuilds its store from the snapshot plus the committed log.
  - Plain reads on a leader can see an uncommitted write during that window. Only failover exposes this, and the writer never received an acknowledgement. This is documented and accepted.
- **Serving:**
  - **Reads and watches** are served locally on every server. They are as fresh as that server's committed state, like etcd's serializable reads.
  - **Writes reaching a follower** are forwarded to the leader. An HTTP request is proxied over TLS with the original user and groups passed as request-header identity, which the leader trusts only from server certificates.
  - **In-process clients** on followers forward the same way.
  - **Controllers and the scheduler** run only on the leader. They start and stop with leadership.
- **Transport:**
  - Server-to-server TLS on port 6444, with mutual authentication.
  - Each server gets a certificate from the cluster CA in the group `system:kr-servers`, and only those certificates are accepted.
  - Messages are length-prefixed binary.
- **Joining:**
  - `kr server --server https://<existing>:6443 --token <server token>` fetches the CA, pinned to the token's hash.
  - It then calls `POST /kr/join-server`, which needs a separate *server* token: agent tokens must never grant membership, because servers hold the CA and service-account signing keys.
  - The response returns the CA and service-account keys plus fresh server certificates.
  - The new server is then added as a voting member and catches up from a snapshot.
- **Single server:** a single-member Raft group. It commits on the local fsync, so existing installs keep working. Their store is imported as the initial snapshot.
- **Amendment (implementation):**
  - HA is opt-in, like k3s: `kr server --cluster-init` founds a cluster; a plain `kr server` keeps the ADR-021 store and its behaviour. Once `raft/` exists the server stays in HA mode.
  - The server token (`server-token`, `K10<ca hash>::server:<secret>`) is created only on HA servers and copied to joiners.
  - Joining is two-phase: `/kr/join-server` (token) returns key material and the current server addresses; the joiner issues its own certificates, starts Raft as a non-member that answers the known servers, then calls `/kr/add-server` with its `system:kr-server:<id>` certificate (the id comes from the certificate, never the body). The voter is added only once the newcomer listens, so a 1→2 change can commit.
  - Forwarded requests carry `Kr-Forwarded-Identity` (base64 JSON user and groups), honoured only from `system:kr-servers` certificates and forwarded at most once; the leader returns `Kr-Revision` and the follower waits to apply it before answering.
  - Converting a single-server install: `--cluster-init` on an existing datastore writes its image as the Raft snapshot at index 1 (term 1, this server the only voter) and renames `db` to `db.imported`.
  - Peer addresses are also saved in `raft/peers` and loaded as seeds at start: the replicated `/kr/servers/` entries are only applied after a quorum is reached, which may need those very peers.
  - Agents keep a list of API servers (from the `kubernetes` endpoints, saved across restarts) and move to the next one on transport errors; no load balancer or virtual IP is needed.
  - Joining servers enter as learners (`EntryKind::AddLearner`, carried in snapshot metadata); `/kr/add-server` promotes them with `AddVoter` once they have the commit index, or answers 503 so the joiner retries.
  - Each server keeps `/kr/servers/<id>` current: on start it reissues certificates whose IP SAN no longer matches, and re-registers through any server; a link whose address changes reconnects at once.
  - Leader-only components run under `Cluster::while_leader` (started when the leader is ready, aborted on step-down).

- Backup and restore (ADR-043): `kr snapshot save` replays the local `raft/` files to a store image; `kr snapshot restore` writes a single-server `db/`, from which `--cluster-init` founds a new one-member cluster. The commit index in `hardstate` is persisted only on term/vote changes, so offline readers treat every local entry as applied unless asked otherwise (`--committed-only`).

**Status:** accepted (implemented; gaps in KNOWN_ISSUES #97).

## ADR-027: opt-in registry mirrors (`KR_REGISTRY_MIRRORS`)
- **What:** `KR_REGISTRY_MIRRORS=registry.k8s.io=http://10.0.0.4:5000,docker.io=https://cache:5000` maps an upstream registry to a mirror. A pull tries the mirror first, anonymously; any failure (unreachable, missing image) falls back to the upstream with the pod's credentials. Like docker's `registry-mirrors`, the mirror is trusted for tag-to-digest resolution only: blobs are still verified against the manifest digests. `http://` mirrors are plain HTTP (the same as the insecure-registry list).
- **Why:** test runs (conformance, multi-node scripts) downloaded the same ~600 MB of images in every throwaway container. `tools/test/registry-cache.sh` runs one `registry:2` pull-through proxy per upstream with blobs in named docker volumes, and the test scripts pass the mirrors automatically when the caches are up. A warm agnhost pull went from 47 s to 1.7 s.
**Update (ADR-044):** mirrors are no longer anonymous: credentials and TLS settings come from `registries.yaml` `configs` per endpoint host, several mirrors per registry are tried in order, and `KR_REGISTRY_MIRRORS` stays and is merged under the file.
**Status:** accepted.

## ADR-028: admission policies in the existing admission pass
- **What:** ValidatingAdmissionPolicy and MutatingAdmissionPolicy are evaluated in `webhook::run`'s admission pass, on the dry-run result: mutating policies, mutating webhooks, validating policies, validating webhooks (upstream's plugin order). Parsed policies and bindings share the webhook configuration cache, keyed by the count and newest revision of all six configuration kinds.
- **CEL:** the existing evaluator (`cel.rs`) was extended rather than replaced: map literals and `Object{...}` construction evaluate to plain JSON, so an apply configuration is just a partial object. Typing is a separate static pass over the same AST (`type_warnings`) that only reports operator overloads whose operand types are both known; everything it cannot type is `dyn`, so it never produces warnings cel-go would not.
- **Type checking is synchronous:** `status.typeChecking` is computed when the policy is written instead of by a controller (upstream sets it shortly after). Clients poll for it, so being early is indistinguishable.
- **Apply configurations** are merged with the strategic-merge code (list keys from the same tables) rather than structured-merge-diff (see KNOWN_ISSUES #146).
**Status:** accepted.

## ADR-029: Pod Security admission built in
- **What:** the upstream PodSecurity admission plugin, in `psa.rs`, evaluated in the API server's create/update path for pods (deny on `enforce`, warning on `warn`) and pod-template workloads (warnings only).
- **Defaults:** unlabelled namespaces are `privileged`, as upstream ships; kr does not change the default so that existing manifests keep working, and clusters opt namespaces in with labels. An invalid level label is evaluated as `restricted` and rejected on namespace writes (fail closed).
- **Scope:** the baseline and restricted checks of `latest` with upstream's wording (clients and e2e tests match on it).
- **Why built in:** hostNetwork, privileged and hostPath pods are otherwise available to anyone who can create pods. kr's user-namespaced sandboxes reduce the blast radius, but namespaces need the same declarative guardrail upstream gives.
**Status:** accepted.

## ADR-030: round 8 design choices (reviews, selectable fields, pod certificates)
- **Review kinds** are a separate static table (`resources::REVIEWS`), advertised in discovery as `create`-only and never stored; the handlers stay where they were. They are not part of `RESOURCES`, so the generic REST paths, OpenAPI and the protobuf table generator do not see them (the generator lists them in `EXTRA_ROOTS`).
- **Impersonation** is part of authentication (`ApiServer::authenticate`): the caller is authorized for `impersonate` on `users`, `serviceaccounts`, `groups`, then the request continues as the impersonated identity, with `system:authenticated` added. UID and extra headers are ignored.
- **CRD selectable fields** are parsed per request (`ApiServer::field_selectors`). When a conversion webhook exists, terms on custom fields are returned apart and evaluated on the converted objects by the transport (`convert.rs`), because the sync handlers only see the stored version. A collection delete with such terms is therefore a list, the filter and per-item deletes there (admission webhooks are not consulted for those items).
- **Pod certificates:** the kubelet owns key generation (the private key never reaches the API), the API server only checks bounds and shape of the request, the signer is whatever updates the request status. Rotation is the kubelet's re-stage after 80% of the lifetime, not `beginRefreshAt`. Only ECDSAP256 (kr-crypto has no RSA key generation, and P-384/P-521 or Ed25519 PKCS#10 signing are not needed by the suite).
- **Pod resize** applies `resources` to the live cgroups in the kubelet's periodic sync and reports them in the status (the `PodResize*` conditions, `Deferred`/`Infeasible` handling and `resizePolicy` came with ADR-033).
- **ControllerRevision data** reproduces the Go rendering instead of the template as stored, because upstream clients compare the bytes; the template hash used for naming is unchanged.

**Status:** accepted.

## ADR-031: rootless pod egress through a TUN device and a userspace NAT

**Context:** rootless pods live in an infra user+net namespace that had no route out. The host namespace cannot be reached by veth without privileges, and nftables masquerade needs root.
**Decision:** the infra namespace gets a TUN device `kr-out` (100.64.255.1/30) as its default route. kr, in the host namespace, receives the descriptor over SCM_RIGHTS and serves it with `kr_net::usernat`, a slirp-style engine (no I/O, unit-tested) that terminates the pod's TCP itself and relays each flow over ordinary host sockets; UDP flows map to host UDP sockets; ICMP echo goes out through an unprivileged ICMP socket (`ping_group_range`). DNS to 100.64.255.2:53 is redirected to the host's first nameserver, which `kr ctr run` writes into resolv.conf. The pod sees the real destination address (transparent), so no rewriting rules exist. Driver: `kr-kubelet/src/egress.rs`.
- Window scaling is offered when the pod's SYN has it (shift 4, 1 MiB); IP fragments are reassembled and generated. No retransmission timers toward the pod (the TUN is lossless); IPv4 only when written, IPv6 followed in ADR-032.
- Service ClusterIPs and pod-to-pod traffic never reach the TUN (local routes in the infra namespace).
- `kr ctr run`: the detached infra supervisor runs the same driver on its own executor (`exec::reset_after_fork` drops the inherited reactor state).

**Status:** accepted.

## ADR-032: dual-stack pod network with derived IPv6 addresses

**Context:** the cluster was IPv4 only. Dual stack touches addressing, the node datapath, Services, EndpointSlices, the proxy, DNS and the rootless NAT.
**Decision:** every node and pod gets an IPv6 twin of its IPv4 address; no second IPAM.
- **Addressing.** The node pod `/24` `10.88.N.0/24` has the `/64` `fd00:88:0:N::/64` (`network::subnet6`); a pod's IPv6 address ends in its IPv4 host octet; the bridge gateway is `::1`. The API server sets `spec.podCIDRs` to both when it hands out the number `N`. Pods get both addresses (`NetConfig::dual`, no DAD) and report `status.podIPs` with IPv4 first.
- **Node datapath.** `net.ipv6.conf.all.forwarding=1`, a second nftables table `ip6 kr` masquerading `fd00:88::/32`, and on VXLAN one on-link route per peer `/64` via `fd00:88:ffff::N` with a static neighbour entry to the peer's VTEP MAC (the FDB entry for IPv4 carries the frames). The host-gw backend stays IPv4.
- **Services.** `spec.ipFamilies`/`ipFamilyPolicy` are honoured: IPv4 ClusterIPs from `10.96.0.0/16`, IPv6 ones from `fd00:96::/112` (from `::b`); a dual-stack Service has both, an IPv6-only one a single IPv6 address. EndpointSlices come per address family (`addressType`), Endpoints carry the primary family.
- **Proxy.** One 16-byte address type (IPv4 as `::ffff:a.b.c.d`) end to end, including the socket-factory protocol of the rootless mode. IPv6 ClusterIPs are a `local fd00:96::/112` route plus IPV6_FREEBIND binds. The proxy picks backends of the family of the ClusterIP.
- **DNS.** AAAA answers from `clusterIPs` and from the pods' second `podIPs`; A answers are unchanged. Resolvers still reach the DNS server on its IPv4 ClusterIP.
- **Rootless.** `usernat` works on 16-byte addresses: IPv6 TCP/UDP, ICMPv6 echo (through an unprivileged ICMPv6 socket) and errors, hop-limit expiry (`traceroute`), with the NAT hop at `fd00:88:ffff:1::2` on a transit `/126` of the TUN. The engine quotes the whole offending packet in errors (busybox `traceroute -6` ignores short quotes).
- **Host side (follow-up).** The API server also listens on `[::]` (`IPV6_V6ONLY`, best effort). `kube-dns` is dual stack (`fd00:96::a`, the DNS server listens on both). The `kubernetes` Service is dual stack only when the host has a global IPv6 address (`api::host_ip6`: source address towards a public IPv6 destination, no link-local): then it gets `fd00:96::1`, an IPv6 EndpointSlice `kubernetes-v6`, and the node reports a second `InternalIP`. NodePort and hostPort get `[::]` listeners (`IPV6_V6ONLY`, hostPort backed by the pod's IPv6 address); `/etc/hosts` and the `status.podIPs` env var list both addresses. The host-gw backend adds the peer's `/64` via its IPv6 `InternalIP` (routes are added, stale ones are not removed until restart).
- **IPv6 underlay (hosts without IPv4).** Node and server addresses are 16 bytes everywhere (IPv4 mapped as `::ffff:a.b.c.d`; `tcp::parse_ip16/fmt_ip16/url_host/ip_bytes16`): the primary address is the IPv4 source towards the internet if there is one, else the global IPv6 source (`ns::route_source_any`; `KR_PREFER_IPV6=1` forces IPv6 on a dual-stack host, which is how the tests run). `kr agent --server https://[fd05::1]:6443` joins over IPv6; Raft, write forwarding, the kubelet endpoint (`:10250`) and the API listener also listen on `[::]` (`IPV6_V6ONLY`); node and server certificates carry the right IP SAN (4 or 16 bytes). VXLAN uses `IFLA_VXLAN_LOCAL6` and IPv6 FDB destinations (the VTEP MAC is a hash of the address); host-gw routes pod IPv6 subnets only on an IPv6 underlay. Pods still get both families (the IPv4 pod network is internal), and the `kubernetes` Service keeps its IPv4 ClusterIP: the proxy lets that one Service use endpoints of either family, so an IPv6-only API server is reached through `10.96.0.1`.

**Status:** accepted.

## ADR-033: API priority and fairness, aggregated watches, resize policies

**Context:** three documented gaps: APF objects were stored but not enforced, watches of aggregated APIs answered 501, and in-place pod resize ignored `resizePolicy` and `PodResizePending`.
**Decision:**
- **APF (`kr-apiserver/src/apf.rs`).** Requests arriving over HTTP are classified by the first matching FlowSchema (lowest `matchingPrecedence`, then name; subjects User/Group/ServiceAccount, resource and non-resource rules) into a priority level. A limited level gets `N * shares / sum(shares)` seats, N being `KR_APF_SEATS` (default 600, read once); a request takes `width` seats (1, but a LIST takes one per 100 stored objects it may return, at most 10); over the limit, requests wait in per-flow queues (flow = schema plus user or namespace per `distinguisherMethod`) served round robin, and are refused with 429 and `Retry-After: 1` when the level rejects, the queues are full (`queues * queueLengthLimit`) or the wait exceeds 15 s. `Exempt` never waits. Watches, exec/attach/port-forward/proxy, followed logs, `/kr/` endpoints and requests forwarded by another HA server are not counted; in-process callers (controllers, the local kubelet) do not go through HTTP and are not throttled. The suggested FlowSchemas and levels (exempt, probes, leader-election, node-high, system, workload-high/low, global-default, catch-all) are created when missing; objects are re-read every second. A level lends `lendablePercent` of its limit while idle and may borrow lent seats up to `borrowingLimitPercent` of its limit (unset: unlimited); seats are never revoked, a borrower gives them back as its requests finish, and a release wakes queued requests of all levels (KNOWN_ISSUES #143 for the rest). Responses carry `X-Kubernetes-PF-FlowSchema-UID` and `X-Kubernetes-PF-PriorityLevel-UID`.
- **Aggregated watches.** A `watch` request is relayed as a stream: the extension's status and `Content-Type` are returned when its head arrives, then its chunked body is copied chunk by chunk by a task (one hour idle limit) until either side closes.
- **Resize.** The kubelet checks a changed `resources` against the node first: over the node's capacity is `Infeasible`, not fitting next to the other pods' requests is `Deferred`; both are reported as the `PodResizePending` condition (reason and message) and retried each sync, nothing is applied meanwhile. When it fits, a container whose changed resource has `resizePolicy: RestartContainer` is stopped (SIGTERM) and restarted at once with the new limits regardless of `restartPolicy` and without backoff (the restart count rises, `PodResizeInProgress` is reported until it is running), the others get their cgroup limits updated live.
**Status:** accepted.

## ADR-034: configurable pod network families (IPv4, IPv6, dual stack)

**Context:** pods always had both families (ADR-032); an IPv6-only cluster was impossible, and so was an IPv4-only one.
**Decision:** the server's `KR_POD_FAMILIES` (`4`, `6` or `4,6`, default `4,6`) is the one switch. Nodes follow from what the API server gives them.
- **Node CIDRs.** `admit_node` hands out the next free pod-network number N and sets `spec.podCIDRs` to `10.88.N.0/24` and/or `fd00:88:0:N::/64` (`podCIDR` is the first). The kubelet derives its subnet and families from them (`PodNet::from_cidrs`); the IPv4 `/24` doubles as the allocator's address space, so an IPv6-only pod gets the IPv6 address derived from its lease slot without a second IPAM, and the IPv4 address is simply never configured.
- **Datapath.** The bridge, forwarding, masquerade tables, VXLAN routes/ARP/neighbours, host-gw routes and the pod's `eth0` addresses and default routes are created per family; an IPv6-only network needs host IPv6 (setup fails otherwise).
- **Pod status.** `status.podIP` is the primary address (IPv4 when the pod has one, else IPv6), `podIPs` lists the pod's addresses; `/etc/hosts`, the downward API and the `KUBERNETES_*` service env (bracketed in URLs) follow. HostPorts, probes with an explicit `host`, `pods/proxy`, `services/proxy`, DNS records (A and AAAA, endpoints without an IPv4 address, SRV additional records) and the endpoint controller handle either family.
- **Services.** A Service defaults to the first available family; `ipFamilies` naming a family the cluster lacks, or `RequireDualStack` on a single-family cluster, is refused; `PreferDualStack` degrades to single stack. `kubernetes` and `kube-dns` get `10.96.0.1`/`.10`, `fd00:96::1`/`::a` or both. The proxy lets the `kubernetes` Service use endpoints of either family, so an IPv6-only pod network can reach an API server that has only an IPv4 host address.
- **DNS and egress.** Pods' `resolv.conf` points at the `kube-dns` address of the pod's primary family (a Default-policy IPv6-only pod gets IPv6 resolvers only; IPv4 ones are replaced by the cluster DNS, or in rootless mode the NAT's `fd00:88:ffff:1::2` forwarder). The rootless forwarder resolves through the host's first nameserver of any family.
- **Changing families.** The server stores an explicit setting (`/kr/pod-families`; a server started without the variable uses it, so HA leaders agree) and, when it starts, rewrites every Node's `podCIDRs` to the setting, keeping each node's pod network number, and recreates the `kubernetes` and `kube-dns` Services when the families changed. Agents and kubelets read their CIDRs at start, so they follow when restarted; a running kubelet logs that it must be restarted. Pods from before the change are lost with the restart, as with any kr restart. Peers are only routed in the families both nodes have, so nodes that disagree for a moment do not break each other.
- **Standalone containers.** `kr ctr run` follows `KR_POD_FAMILIES` too (default dual stack); the rootless bridge is shared, so the first run decides its families.
**Status:** accepted.


## ADR-035: Linearizable follower reads by leader lease (ReadIndex)
**Context:** HA servers served reads from their local applied state, so a client could read stale data right after a write acknowledged elsewhere (kubectl through a load balancer). **Decision:** reads without a `resourceVersion` (and not watches) pass a barrier. The leader answers if `Raft::read_index()` holds: it has committed an entry of its own term and a quorum acknowledged it within `election_ticks / 2`; followers refuse votes for a full election timeout after hearing from a leader, so no other leader can exist in that window. A follower asks the leader (`GET /kr/readindex`, server certificate) for its committed store revision and waits until it has applied it. **Consequences:** one leader round trip per such read on a follower, no log writes; correctness needs bounded clock drift between servers (as any lease). No quorum means a 503 after 3 s rather than a stale answer.

## ADR-036: pods survive a restart or crash of the kubelet process (root and rootless)
**Context:** sandboxes and containers carried `PDEATHSIG=SIGKILL` to the kubelet and the kubelet cleaned everything up at start, so a crash, upgrade or restart of `kr agent` / `kr server` killed every pod on the node. k3s (containerd shims, systemd `KillMode=process`) and upstream keep containers running, with their exit status, terminals and stdin, while the kubelet is away.
**Decision:**
- **Shim per container (`container::start_detached`).** The kubelet forks a detached process (own session, double fork) that runs the ordinary `start()` itself, so it is the container's parent; it reports the container pid back over a pipe, closes every descriptor it does not need, and then `exec`s `kr shim` (a fresh tiny image: no copy of the kubelet's memory and credentials). The shim reaps the container, reads the cgroup's OOM counter, and writes `<pod dir>/<container id>.exit` (`<code> <oom>`, renamed into place). For `tty: true` it also copies the pty output into the container log, so logging does not depend on the kubelet. It keeps the pty master / the kubelet's end of the stdin socket open and serves it on a unix socket `<pod dir>/<container>.io` (mode 0600, one descriptor per connection via `SCM_RIGHTS`), which a restarted kubelet connects to. No ptrace is involved, so this works under any `kernel.yama.ptrace_scope` (including 3) and needs no `CAP_SYS_PTRACE`. The container keeps its death signal, now tied to the shim: killing the shim kills it.
- **Sandboxes** (`kr pause`) clear their death signal before the exec (`set_survive_parent`); `kr ctr run` keeps the old behaviour.
- **Adoption (`kr-kubelet/src/adopt.rs`).** The pod directory keeps `.adopt` (sandbox pid, and per container pid, shim pid, container id, seq, start time, the shim's fd number for stdin/pty), all with `/proc/<pid>/stat` start ticks so a recycled pid is never taken over. It is rewritten when a sandbox or container starts or ends. The first time the kubelet sees a pod it adopts: pidfds for sandbox and containers, the IP lease and pod cgroup are re-claimed, probes restart, restart counts, finished init containers and readiness come from the pod's API status, and the stdin socket / pty master are fetched from the shim's socket. A container that ended meanwhile has its true exit status read from its `.exit` file (255 only if the shim itself was killed). What cannot be adopted is killed and the pod starts afresh. After the first successful sync `sweep_unclaimed` kills cgroups and recorded processes and frees IP leases of pods nobody claimed (deleted while the kubelet was down).
- **Rootless.** The pod network no longer depends on the kubelet: the egress NAT (ADR-031) runs as `kr egress` in a detached helper process that owns the TUN device (`container::spawn_helper`), the infra namespace holder survives, and `<root>/infra.adopt` records both. At start the kubelet adopts them when both live; otherwise it kills the pods recorded as using the old network and builds a new one.
- **Guard rails.** One kubelet per root: `<root>/kubelet.lock` (`flock`, released with the process) makes a second `kr agent`/`kr server` on the same root exit, so two never adopt the same pods. The kubelet checks the kernel at start (`survive_prerequisites`: `pidfd_open`, `clone3`, `close_range`, i.e. Linux 5.9) and, if something is missing, says so and runs containers as its own children as before. A pod without a record has whatever runs in its cgroup killed before it starts, and a lease the pod already holds is reused (a crash between allocating an address and writing the record leaked one). After the first sync the sweep also removes pod and container directories of pods that are gone. When the pod network has no free address a pod stays in `ContainerCreating` and retries; it used to start without any network.
- **Record format** (`.adopt`) is versioned and only ever extended (readers ignore unknown trailing fields and lines), see `docs/UPGRADING.md`. Pods started by a binary older than this ADR carry a death signal inside the container that nothing can clear, so the first upgrade onto this version needs a drain; later ones do not.
**Deployment note:** a service manager must not kill the whole control group on stop (systemd `KillMode=process`, as for k3s), or shims and containers go with the agent.
**Consequences:** a pod keeps its IP, processes, open connections, terminal log and exit status across `kill -9` of the agent or the server; `attach -i` works again after the restart. One shim process per running container (about 1 MB resident each, measured: 200 pods = 250 MB of shims; adopting 200 pods after a `kill -9` takes 9 s). Tested by `tools/test/stress.sh`, `failure.sh` (binary swap with SIGTERM, killed shim, recycled-pid records, crash loop, crash during creation, second agent), `soak.sh` (200 pods, churn with a crash every minute, leak accounting) and `rootless-survive.sh`.
**Status:** accepted.

## ADR-037: node lifecycle controller
**Context:** nothing noticed a node whose kubelet stopped: it stayed `Ready`, got new pods and kept its endpoints. **Decision:** `kr-controllers/src/nodelifecycle.rs` runs every 5 s. A node whose newest sign of life (Lease `renewTime`, Ready `lastHeartbeatTime`, creation) is older than 40 s gets Ready/MemoryPressure/DiskPressure/PIDPressure `Unknown` (`NodeStatusUnknown`) and the `node.kubernetes.io/unreachable` taints (`NoSchedule`, `NoExecute`). Its pods are marked not Ready (so Endpoints drop them) and deleted once their toleration of the `NoExecute` taint ends (`tolerationSeconds`; none for a matching toleration without seconds; 300 s when they have none, which stands in for upstream's DefaultTolerationSeconds admission). Taints are removed when the heartbeat is back; the kubelet restores the conditions (every 30 s) and rewrites pod Ready conditions the API disagrees with. Pods are deleted, not force-deleted: the kubelet finishes them when it returns. Evictions are rate limited per zone and zone aware (ADR-042): the `NoExecute` taint is added through a token bucket (0.1/s, 0.01/s or stopped for disrupted zones); the `NoSchedule` taint, Unknown conditions and NotReady marks are immediate. **Status:** accepted.

## ADR-038: Device Plugin API (v1beta1) in the kubelet
**Context:** GPUs (NVIDIA GPU Operator's device plugin) and other hardware are advertised and handed to pods through the Kubernetes Device Plugin API: plugins dial a kubelet gRPC socket and the kubelet dials back. KNOWN_ISSUES #117.
**Decision:** `kr-kubelet/src/deviceplugin.rs`, over the in-tree gRPC/HTTP2 layer (`kr_net::grpc`, protobuf by `kr_fmt::proto`; no generated code).
- **Directory.** `/var/lib/kubelet/device-plugins` when the kubelet runs as uid 0 (the GPU Operator mounts that hostPath), else `<root>/device-plugins`; `KR_DEVICE_PLUGIN_DIR` overrides. Created 0750; a stale `kubelet.sock` is removed; sockets are 0600 (root only). Nothing is served if the directory or socket cannot be created.
- **Registration.** `Registration/Register` requires version `v1beta1`, a `domain/name` resource that is not in `kubernetes.io`, and an endpoint without `/` or `..`. Each registration spawns a manager task: connect to `<dir>/<endpoint>` (retries for 5 s), `GetDevicePluginOptions` (failure ignored), then `ListAndWatch`; each response replaces the resource's device list. When the stream ends or the connect fails all devices turn unhealthy: capacity stays N, allocatable becomes 0 (as upstream) until the plugin registers again. A new registration for the resource aborts the old manager.
- **Node status.** `status.capacity[r]` = devices, `allocatable[r]` = healthy devices, merged into the node status patch. Every resource ever advertised is remembered (also across kubelet restarts, in the allocations file) and reported as `"0"` when gone, since a merge patch cannot delete. The heartbeat loop ticks every second and patches the status at once when a counter changed, otherwise every 30 s.
- **Allocation.** `spec::build` asks `Plugins::allocate` for each container whose `resources.limits` name a managed resource. Devices come from the healthy ones not held by another (pod uid, container), chosen by the plugin when it supports `GetPreferredAllocation` (asked per container; its answer is used if all ids are free), else on one NUMA node when possible (`topology.nodes` of `ListAndWatch`; smallest node that fits), else the first ones; the same container keeps its devices across restarts (`Allocate` is called again with the same ids). `PreStartContainer` runs when the plugin asked for it. The response is applied: envs (plugin wins over the container env), mounts as bind mounts, `DeviceSpec`s as bind mounts of the host node onto the container path (read-only unless the permissions contain `w`; the mount code creates the target file). Annotations are parsed and dropped. A failure (unregistered resource, not enough healthy free devices, Allocate error, missing CDI spec) is returned as the `build` error, so the container shows `CreateContainerConfigError` with the message and is retried with back-off; it never starts without its devices. A failed fresh reservation is released.
- **State.** The registry lives in the `Plugins` object owned by the kubelet (the crate forbids `unsafe`, so no global). Devices are freed when the pod is cleaned up. `<dir>/kr-allocations.json` (pod uid, container, resource, device ids; plus the resource names) is rewritten on every change and loaded at start; after the first successful pod sync `sweep_unclaimed` drops allocations of pods that are not on the node anymore (the same moment as ADR-036's sweep). Init container allocations are held until the pod ends.
- **CDI.** `cdiDevices` in an `AllocateResponse` are resolved against JSON and YAML (`.yaml`/`.yml`, as the NVIDIA toolkit writes) specs in `/etc/cdi` and `/var/run/cdi` (`kind`, `devices[].name`, top-level and per-device `containerEdits`: `env`, `deviceNodes`, `mounts`). `hooks` run as OCI hooks (ADR-039); a device without a spec fails the container start.
- **Plugin connections.** One connection per plugin socket is cached and reused for `GetPreferredAllocation`, `PreStartContainer` and `Allocate` (a closed one is replaced; an UNAVAILABLE answer drops it and the call is repeated once). `allocate_batch` sends one `Allocate` for several containers of a pod and resource; the kubelet still calls it per container (KNOWN_ISSUES #141).
- **Unhealthy devices.** A container holding a device that a live `ListAndWatch` reports Unhealthy (or no longer lists) fails its pod (phase Failed, reason `Evicted`) from the 10 s eviction loop. A plugin whose stream is gone does not fail pods (unknown, not broken). Grace period and restart handling: KNOWN_ISSUES #167.
- **PodResources.** `kr-kubelet/src/podresources.rs` serves v1 `List`, `GetAllocatableResources` and `Get` on `<kubelet dir>/pod-resources/kubelet.sock`; CPUs and memory are always empty.
- **Scheduling.** No change: the scheduler already fits extended resources from `allocatable` and treats a limit as the request; the API server does not validate extended resources further.
**Consequences:** about the size of the module in the binary (see the commit); plugins written for upstream kubelet work unchanged if they only use v1beta1 Register/ListAndWatch/Allocate.
**Status:** accepted.

## ADR-039: NVIDIA RuntimeClass emulation through CDI; CRD printer columns
**Context:** The GPU Operator's validator pods (and CUDA workloads) use `runtimeClassName: nvidia` with `NVIDIA_VISIBLE_DEVICES`, which upstream container runtimes turn into GPU access through the NVIDIA container runtime or CDI. kr has no such runtime hook, so `nvidia-smi` was not found in the pod and the plugin's init container never got its toolkit-ready marker. Separately, `kubectl get <custom resource>` showed only Name and Age because the server ignored a CRD's `additionalPrinterColumns`.
**Decision:**
- A pod whose `RuntimeClass` object (looked up by the kubelet; a missing class fails the container start) has `handler` `nvidia`, `nvidia-cdi` or `nvidia-legacy` gets CDI devices `nvidia.com/gpu=<x>` for each token of `NVIDIA_VISIBLE_DEVICES` (`all`, an index, or a `GPU-` UUID; `none`/`void`/unset/anything else gives nothing). Pods without that runtime class never get GPUs this way, so the env var alone is not enough. Resolution reuses the CDI code of ADR-038 (host specs in `/etc/cdi`, `/var/run/cdi`).
- CDI hooks are run as OCI hooks (see the addition below); nothing is emulated.
- The API server keeps a CRD version's `additionalPrinterColumns` and uses them (JSONPath subset: `.a.b`, `[n]`, `[*]`, `['k']`, `[?(@.f=="v")]`) in Table output for custom resources; priority >0 columns are wide-only. Built-in kinds keep their fixed printers.
**Consequences:** Host GPU access is granted to any pod that can name the `nvidia` RuntimeClass, as on upstream clusters; restrict `runtimeClassName` with admission policy if that matters. Open GPU items: KNOWN_ISSUES #141, #142, #160, #163-#169. Hooks and device nodes were verified with the host's NVIDIA CDI specs on an RTX 4090 through `kr ctr run --cdi` (`nvidia-smi -L` works in an Ubuntu container).
**Status:** accepted.

**Addition (same ADR, OCI hook lifecycle):** CDI `hooks` (`hookName`, `path`, `args`, `env`, `timeout`) are run by `kr_runtime::hooks`, replacing the `LD_LIBRARY_PATH` and symlink-to-bind-mount emulation. Each hook gets the container state JSON on stdin and exactly its own `env`; the container's directory holds `config.json` (`root.path` = the merged rootfs) and `hooks.log`, which collects hook output (not the container log) and is quoted in the start error. Stages: `createRuntime` (and `prestart`) in the runtime namespace after the container's namespaces exist; `createContainer` after the rootfs, `/dev`, `/proc` and all volumes are mounted and before the read-only remount, with the host root as the hook's root and the container's root recursively bind-mounted at `root.path` (what runc's hooks see; `nvidia-cdi-hook update-ldcache` runs the host `ldconfig` against it), detached afterwards; `startContainer` inside the container right before the exec; `poststart` after the start, failures only logged; `poststop` is saved to `poststop.json` in the container directory at start and run (state `stopped`, pid 0, failures only logged, once) by `Store::delete_container` just before the directory is removed, so it also runs after a kubelet restart. `state.pid` is the container's pid in the runtime's pid namespace (sent to the child with the go byte). A failing hook, or one that exceeds `timeout` (default 120 s), fails the container start. Specs that are not owned by root or are group/world-writable are ignored, since hooks run as root. A hook binary (and every symlink on the way) must also be owned by root, be a regular file and not group/world-writable (`kr_runtime::hooks::trust`, checked when the CDI spec is resolved and again before `poststop` runs), otherwise the container does not start; `KR_CDI_HOOK_DIRS` (colon-separated) optionally limits the symlink-resolved hook paths to those directories. Parent directories are not checked (KNOWN_ISSUES #168). A hook with an unknown stage or a relative path fails the start instead of being skipped. CDI `additionalGids` become supplementary groups of the container (also for `kr ctr run --cdi`); `KR_CDI_DIRS` (colon-separated) replaces `/etc/cdi:/var/run/cdi`. `kr ctr run --cdi <vendor/class=name>` applies CDI devices to a plain container (used to verify with the host's NVIDIA specs: `nvidia-smi -L` works in an Ubuntu container). `NVIDIA_VISIBLE_DEVICES` under the `nvidia*` runtime classes still selects CDI devices in the kubelet, as `nvidia-container-runtime` does in CDI mode.

## ADR-040: Kubernetes compatibility for Longhorn: lenient webhook patches, nulls in custom objects
**Context:** Longhorn's mutating webhook (`mutator.longhorn.io`) made `longhorn-manager` crash-loop: kr rejected its patch with `error applying patch: path not found: finalizers`. Kubernetes applies webhook patches with the JSON-patch library's lenient options, which webhooks rely on.
**Decision:** patches from webhooks use `patch::json_patch_lenient`: `replace` of an absent object member sets it, and `add` creates missing parent objects (an array when the next token is `-`). Client `PATCH` requests keep strict RFC 6902 behaviour. Based on the error text alone; the actual Longhorn op was not captured.
**Status:** accepted.
**Addition (same ADR):** `crd::prune` drops a `null` member whose schema is not `nullable: true` (before defaulting), as Kubernetes does. Longhorn's `Node` status sends `lastPeriodicCheckedAt: null` and the manager died on `Invalid value: "null"` without it.

## ADR-041: CSI node support, attach/detach controller, mount propagation
**Context:** CSI drivers (Longhorn first) need the kubelet to register their plugin, stage and publish volumes through the driver's unix socket, and a controller to create `VolumeAttachment`s for the external-attacher. The driver's node plugin also mounts volumes below `<kubelet root>/pods/...` from inside its own container, which must be visible on the host.
**Decision:**
- **Kubelet (`kr-kubelet/src/csi.rs`).** Root dir `/var/lib/kubelet` (`KR_KUBELET_DIR`), root kubelet only. Every 2 s the sockets in `plugins_registry/` are registered: `Registration/GetInfo`, `NodeGetInfo`, `NodeGetCapabilities`, `NotifyRegistrationStatus`; `CSINode` and the `csi.volume.kubernetes.io/nodeid` node annotation follow the registry. `spec::pvc_source` calls `Csi::mount_pv` for PVs with `spec.csi`: waits for the `VolumeAttachment` when the `CSIDriver` requires attach, `NodeStageVolume` (when the driver has STAGE_UNSTAGE_VOLUME) at `plugins/kubernetes.io/csi/<driver>/<sha256 handle>/globalmount`, `NodePublishVolume` at `pods/<uid>/volumes/kubernetes.io~csi/<pv>/mount`, and bind-mounts that path into the container. Pod cleanup and the unclaimed-dir sweep call `unmount_pod` (Unpublish, then Unstage for the last user; `vol_data.json` stays until both succeed so a failure is retried). Names from API objects are checked (`safe_name`) before they are used in a path, and cleanup only `rmdir`s empty directories.
- **Controller (`kr-controllers/src/attachdetach.rs`).** Every 3 s: a non-terminal scheduled pod using a Bound PVC of a CSI PV whose driver needs attach gets `VolumeAttachment` `csi-<sha256(handle+driver+node)>` (label `kr.io/attach-controller`); labelled ones nobody needs are deleted. Unlabelled attachments are never touched.
- **Mount propagation (`kr-runtime`).** `volumeMounts[].mountPropagation` (`HostToContainer`, `Bidirectional`) is honoured. The volume is cloned with `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` while the new mount namespace still shares the host's peer groups, then attached with `move_mount` after `pivot_root`; the clone stays a peer of the host mount (`HostToContainer` is then made `MS_SLAVE|MS_REC`). Plain binds stay private. `Bidirectional` requires `securityContext.privileged: true` (as upstream), a rootful container and no `subPath`. The host mount holding the volume must be shared (systemd's default for `/`).
- **External provisioners (`kr-controllers/src/pvc.rs`).** A claim whose StorageClass names another provisioner gets `volume.kubernetes.io/storage-provisioner` and the beta annotation (and `volume.kubernetes.io/selected-node` for `WaitForFirstConsumer`, once a pod using the claim is scheduled), which the CSI external-provisioner sidecar acts on; the PV it creates carries a `claimRef` and binds through the existing static path. A PV with another `pv.kubernetes.io/provisioned-by` is only marked `Released` when its claim goes: that provisioner deletes it (kr no longer deletes it, which would leak the backing volume).
**Consequences:** Longhorn is installed with `--set csi.kubeletRootDir=/var/lib/kubelet`. Tested only with fake drivers until run with a real one.
**Status:** accepted.
**Addition (same ADR):** mutating webhooks run before CRD schema validation. The webhook step dry-runs the write to get the object; that dry run used to validate the schema first, so a webhook that fills a required enum (Longhorn's `Volume` mutator) was never reached (`Unsupported value: ""`). While the dry run feeds mutating webhooks, `ApiServer::defer_schema` skips the schema check; the real write validates the mutated object.
**Addition (same ADR, 2026-11-12):** the kubelet's CSI watcher (2 s tick) reports `node.status.volumesInUse` (`kubernetes.io/csi/<driver>^<handle>` of every volume recorded under `pods/*/volumes/kubernetes.io~csi`, read from disk so it survives a restart; patched only on change). Every 10 s it expands filesystems: a mounted volume whose claim has `FileSystemResizePending`, with a PV at least as large as the request and a larger request than `status.capacity`, gets `NodeExpandVolume` (needs EXPAND_VOLUME; the staging path, or the publish path without staging), then the claim's `status.capacity` is set and the condition removed. `NodeGetInfo.max_volumes_per_node` becomes `CSINode.spec.drivers[].allocatable.count`. `Csi::volume_stats()` returns per (pod uid, PV) usage via `NodeGetVolumeStats` (GET_VOLUME_STATS) or `statfs` (`kr_sys::ns::statfs`); no endpoint serves it yet. The attach/detach controller keeps an unwanted attachment while its node still lists the volume in `status.volumesInUse` and deletes it when the node stops reporting it, or after 6 minutes of waiting (`MAX_WAIT_MS`, in-memory timer). Still open: KNOWN_ISSUES #135-#137, #170, #171.
**Addition (propagation details, same ADR):** the clone is attached with `move_mount(tree, "", target_fd, "", F_EMPTY_PATH|T_EMPTY_PATH)`; passing `/proc/self/fd/N` as a path fails with EINVAL because `move_mount` does not follow a final symlink. A volume that asks for propagation and cannot be cloned or attached now fails the container start (`clone propagating volume`, `volume mount`) instead of silently becoming a private bind. Verified: `HostToContainer` shows `master:` in the container's mountinfo and a mount made on the host after the container started (a loop-mounted ext4) is visible; `Bidirectional` works for Longhorn's CSI plugin.

## ADR-042: ServiceLB, CSR approval/signing, eviction rate limiting
**Context:** KNOWN_ISSUES #145, #147 and #150: `type: LoadBalancer` Services stayed pending, CSRs were never approved or signed, and a partitioned control plane evicted every pod at once.
**Decision:**
- **ServiceLB** (`servicelb.rs`). One key `*` reconciles all Services after any Service, Node or EndpointSlice event (and at every resync). Handled: Services with no `loadBalancerClass` or `kr.io/servicelb`. `status.loadBalancer.ingress` = sorted InternalIPs of the Ready, non-deleting nodes (`Cluster`), restricted to nodes with a ready endpoint in the Service's EndpointSlices (`Local`). Ingress is removed when the type is no longer LoadBalancer. Foreign classes are never read or written. The status is written only when it changed.
- **CSR** (`csr.rs`). `CaSigner { name, key, rng }` is passed to `run_all_with_ca`; without it the controller does not run. The request is parsed with kr-crypto's DER reader (CN, O, DNS and IP SANs; the self-signature is verified; P-256 and Ed25519 only) and issued with `x509::issue`. Auto approval: only `kubelet-serving` and `kube-apiserver-client-kubelet`, only when `username` is `system:node:<n>`, groups contain `system:nodes`, CN equals the username, `O=system:nodes`, usages are within the signer's set; serving SANs must be the Node's name, Hostname/InternalDNS/ExternalDNS or InternalIP/ExternalIP addresses; client requests carry no SANs. Signing: approved requests of the four built-in signers; the two kubelet signers re-check subject and SANs even after a human approval. The certificate is the base64 PEM in `status.certificate`; lifetime is `expirationSeconds` clamped to 10 minutes..1 year (default 1 year).
- **Eviction rate limiting** (`nodelifecycle.rs`). Per zone token bucket (burst 1, thousandths of a token per second) gating the `NoExecute` taint. Zone state from healthy/unhealthy counts as upstream's `ComputeZoneState`: Full when no node is healthy, Partial when at least 3 nodes and 55% are unhealthy, else Normal. Rates: Normal 0.1/s; Partial 0.01/s above 50 nodes, else 0; Full 0, except when all zones are Full (the control plane is the likely problem) where 0.1/s applies. Everything else of ADR-037 (NoSchedule, Unknown conditions, NotReady marks, toleration-based deletion) is unchanged.
**Consequences:** small code (three modules, no dependency); the server loads the CA key a second time for the signer. Open points: KNOWN_ISSUES #172-#174.
**Status:** accepted.

## ADR-043: Backup and restore, certificate rotation, manifest auto-deploy

**Context:** Operating a cluster needs a way to get its state back (ADR-006 store, ADR-026 Raft), renew certificates before the 365-day lifetime ends, apply manifests at start like k3s's `server/manifests`, and upgrade nodes in order (ADR-036). All of it must stay inside the single binary with no new dependencies (ADR-002).

**Decision:**
* **Snapshots reuse the store format.** The archive is a ustar tarball (`kr_store::bundle`, regular files only, names checked on read) with `kr-snapshot/store` = `Store::image()` (`KRSNAP1`, the format ADR-006 compaction and ADR-026 Raft snapshots use), `META` (mode, revision, time) and the secrets a restore on another machine needs (`pki/ca.*`, `pki/sa.key`, `node-token`, `server-token`; leaf certificates and `admin.kubeconfig` are issued again by the next start). `Store::from_files` rebuilds a store from the bytes of `snapshot` + `log` without opening the directory (no truncation of the live log, no lock); the snapshot file is read twice around the log and the read repeated if a compaction replaced it. HA: the Raft `snapshot`, `log` and `hardstate` are copied into a scratch directory, `kr_raft::storage::Storage` loads them (cutting a torn tail there, not in the live directory) and the entries are applied to a replicated-mode store.
* **Restore is offline and always single-server.** It validates the archive, refuses a non-empty data dir without `--force` (state is then moved to `pre-restore-<time>/`, never deleted), refuses while the kubelet lock of the root is held, writes `db/snapshot` and an empty `db/log` plus the keys. `kr server --cluster-init` then imports `db/` as the Raft snapshot (ADR-026). Procedure for HA: stop all servers, `kr snapshot restore` on one machine, `kr server --cluster-init`, then re-join the others with `--server` and the new `server-token` (their old `raft/` and `server-id` removed first).
* **Scheduled snapshots** are `kr server --snapshot-interval` (seconds or `30s/15m/6h/1d`) and `--snapshot-keep N` (default 5), written to `<data dir>/snapshots`, atomically (tmp + fsync + rename), mode 0600, from the server's own files like the CLI.
* **Rotation** is `kr pki rotate`: move the leaf certificates and keys and `admin.kubeconfig` to `pki/rotated-<time>/` and let the ordinary start-up bootstrap issue them again, so SANs and names cannot drift from first start. The CA and `sa.key` stay unless asked. CA rotation is not done (KNOWN_ISSUES 156).
* **Manifests** (`crates/kr/src/manifests.rs`): every 20 s, in name order, via the in-process client; kind to resource via the group's discovery document (so CRDs work once established); server-side apply with field manager `kr-manifests` and `force=true`; annotation `kr.io/manifest-file`. No deletion. In HA it runs under `while_leader`.
* **Upgrades:** `tools/upgrade/kr-upgrade.sh` (see docs/UPGRADING.md), one node at a time.

**Consequences:** Backups need no cooperation from the server and cannot corrupt it; the price is a stale commit index in HA and an event-loop stall for scheduled snapshots of huge stores. Archives contain private keys and are unencrypted.
**Status:** accepted.

## ADR-044: `registries.yaml` and air-gap image import
- **What:** `kr_runtime::registries` parses k3s-format `registries.yaml` with kr-fmt's YAML (`mirrors` with ordered `endpoint`s and regex `rewrite`s, `configs` with `auth` and `tls`) and merges `KR_REGISTRY_MIRRORS` under it. `pull` builds a plan (`Registries::attempts`): mirror endpoints in order (rewritten repository, the endpoint host's own credentials, never the pod's), then the upstream. The first endpoint whose manifest resolves is used for the blobs; the upstream's error is the one reported. Digests are verified as before, so a mirror is trusted for tag resolution only.
- **TLS:** `kr_net::registry::RegConnector` wraps kr-crypto's existing `ClientConfig` (extra roots, client certificate) and `TlsStream::connect_insecure` (`insecure_skip_verify`); one `Registry` is built per endpoint so each host gets its own config. kr-crypto and `tls.rs` are unchanged. `Credential` gained `token` (static bearer).
- **Regex:** kr has no regex crate and the API server's one is private, so `registries.rs` has a ~150-line backtracking matcher (fuel-limited) for the documented subset.
- **Import:** `kr_runtime::import` extracts a docker-archive or OCI-layout tar (optionally gzip) to a temp directory in the store, verifies/copies layers into the blob store, synthesises an OCI manifest for docker archives and reuses the pull path (`install_image`) to unpack. `kr ctr import` and node start (`<KR_ROOT>/agent/images`, once per path+mtime+size in `<store>/imported.txt`; failures are retried and logged, never fatal) use it.
- **Why:** air-gapped and private-registry installs (k3s parity, #148/#155) without a local registry.
**Status:** accepted.

## ADR-045: What kr does not bundle, and plans for the big open items
**Context:** k3s ships Traefik, a snapshot controller and several large subsystems; kr aims at a small single binary (ADR-001, ADR-002) and has issues that need design before code.
**Decision:**
- **Not bundled by design:** an Ingress controller (KNOWN_ISSUES #151) and the VolumeSnapshot CRDs and snapshot controller (#153). Install them as ordinary workloads (Traefik, ingress-nginx; the external snapshot-controller) through the manifests directory (ADR-043) or Helm; ServiceLB (ADR-042) gives them a LoadBalancer address. kr's job is to run them correctly.
- **Planned, not started** (design in the issues): multi-threading the control plane (#126: first split the fsync-like blocking work and TLS handshakes into helper processes, then shard API serving by listener process sharing the store through Raft locally), the layered image store (#130: content-addressed layer directories used as overlay lowerdirs when rootful), the nftables Service datapath (#133, which also fixes the NetworkPolicy bypass #165: DNAT keeps the client source address), configurable pod and Service CIDRs (#132).
**Status:** accepted.

## ADR-046: Audit log and Pod Security configuration
- **What:** `audit.rs` implements the audit backend (log only) and `psa.rs` gained configuration, versions, exemptions and the audit mode (ADR-029).
- **Hook:** `server::handle` calls `audit::begin` before and `audit::finish` after `handle_inner`; the policy is evaluated from the request line (path parsing is generic, not tied to the resource table). If the policy has no user/group rules a None level costs nothing. The transport is used, not `ApiServer::handle`, so the event has the real status, headers, source IP and the encoded response (decoded back from JSON/protobuf).
- **Writes:** events are appended to a buffer; the buffer is written when it reaches 64 KiB and by a 1 s timer (one `write(2)` to the page cache, no fsync). A failing write drops events and logs once. Rotation happens before a flush that would exceed the limit; backups are `audit-<time>.log` and are pruned by name order.
- **Secrets:** bodies of Secrets, TokenReviews and ServiceAccount tokens are capped at Metadata whatever the policy says (resource-based and body-kind-based), and `managedFields` are stripped when `omitManagedFields`.
- **PSA audit:** violations are computed in `audit::finish` from the request body, not in admission, so no state is shared between interleaved requests (admission is synchronous, the transport is not).
- **Defaults:** auditing is on with the built-in policy; `--audit-log-path off` disables it. The built-in policy omits RequestReceived. PSA behaviour without `--pod-security-config` is unchanged (privileged defaults, no exemptions).
- ADR-029 edits: replace "Scope" bullet's end with "...of `latest`, or of the `<mode>-version` label (partial pinning, ADR-046)" and add "**Update (ADR-046):** `--pod-security-config` (defaults, exemptions), `-version` labels and the `audit` mode annotations."
**Status:** accepted.
(Usage: `--audit-policy-file`, `--audit-log-path`, `--audit-log-maxsize`, `--audit-log-maxbackup`, `--pod-security-config`; examples in `tools/test/audit.sh`.)

## ADR-047: Secrets encryption at rest

**Context:** #157. etcd-style encryption of Secrets (EncryptionConfiguration, k3s `secrets-encrypt`) with the AES-GCM already in kr-crypto.

**Decision:**
- The hook is kr-store, at the persistence boundary: `trait Codec { encode, decode }` (`Store::open_with`, `set_codec`). Values are encoded when appended to the log, written to a snapshot image or captured as Raft records; decoded when the log, a snapshot or replicated records load. The in-memory map, watch events and API responses hold plaintext (as kube-apiserver's watch cache does), so reads and lists cost nothing and no call site in api.rs changed. Only keys under configured resource prefixes (`/registry/<group|core>/<plural>/`) are touched: one prefix check for everything else.
- Format: `k8s:enc:aesgcm:v1:<keyname>:` + nonce(12) + ciphertext + tag(16), AAD = the store key (a value cannot be moved to another object). Random 96-bit nonces from the kr RNG; limit 2^32 encryptions per key, rotate by name. A value without `k8s:enc:` is plaintext (identity fallback), so clusters upgrade in place and `disable` works. A value with an unknown key name, a bad tag or truncated bytes makes load/apply fail (`Corrupt`), closed.
- Config `<data>/encryption-config.json` (0600): `{"resources":["secrets"],"keys":[{"name","secret":base64(32)}...],"identityFirst":false}`. The first key encrypts, all keys decrypt. Created at first start (random key) unless `--secrets-encryption off`; a joining server never creates one.
- HA: all servers need the same keys. The key is NOT stored in the replicated store (it would sit next to the data). The join response carries the file (`join_secrets`/`join_cluster`, over the CA-pinned TLS and the server token). Raft log and snapshots then hold ciphertext on every server. `store_digest` hashes the plaintext image because nonces differ.
- CLI: `kr secrets-encrypt status` (read only), `rotate-key` (new first key, old kept), `reencrypt` (offline: opens the store with the config and `rewrite_log`, which writes every value with the first key and empties the log, so it also removes old ciphertext from the log), `disable` (identityFirst then reencrypt). The first design (no-op update through the API) was dropped: an unchanged update can be elided, and it would not clean the log.
- Rejected: per-read decryption (101 call sites, watch events), storing keys in the store, hand-written crypto.

**Consequences:** see KNOWN_ISSUES NEW-1 to NEW-8.

## ADR-048: Metrics API and kubelet resource metrics
**Context:** k3s ships metrics-server, so `kubectl top` and HPA resource metrics work; kr must not depend on an extra Deployment, and a metrics-server needs an aggregated API plus kubelet scrapes anyway (ADR-033 aggregation, ADR-023 kubelet authentication).
**Decision:**
- **Kubelet:** `kr_kubelet::stats` measures the node (`/proc/stat` busy seconds, `MemTotal - MemAvailable`) and every running container with a cgroup (`cpu.stat` `usage_usec`, `memory.current` - `inactive_file`) on demand, no background sampling. It serves `GET /metrics/resource` (the upstream metric names and labels, per-line millisecond timestamps) and a subset of `GET /stats/summary` on the existing :10250 server, behind the existing `kube-apiserver-kubelet-client` check. The handlers are reached through `NodeProxy::pod_subresource("metrics", "resource"|"summary", ...)` so the trait did not change.
- **API server:** `kr_apiserver::metrics` is built in (ADR-007 style: no separate process, no APIService). `NodeMetrics`/`PodMetrics` sit in the resource table (discovery, authorization attributes `metrics.k8s.io` / `nodes|pods` come for free; discovery verbs are `get`, `list`) but `route()` hands the group to `metrics::serve`, which answers from an in-memory `Cache` held by `ApiServer`. A task spawned at server start scrapes each Node (InternalIP, in-process for the local node) through the `Scraper` trait, implemented for the kubelet `Router` (crate layering: `kr-kubelet` depends on `kr-apiserver`), every 15 s with a 10 s timeout.
- **Rates:** CPU usage is `(cpu_now - cpu_prev) / (t_now - t_prev)` in nanocores from the kubelet's own timestamps; a counter that goes backwards or time that does not advance yields no value, and an item without a value is not served (like metrics-server). `window` is the interval between the two samples. Memory is reported in `Ki`. Labels come from the stored Node/Pod objects, so label selectors work and deleted pods vanish.
- **Alternatives rejected:** running upstream metrics-server (an image, a Deployment, TLS to the kubelet with its own trust setup); sampling in the kubelet on a timer (needs state and gives no more than scraping on demand).
**Consequences:** see KNOWN_ISSUES (no HPA controller, cgroup-only pod stats, per-server caches, no cadvisor endpoint).
**Status:** accepted.

## ADR-049: NetworkPolicy enforcement
**Status:** accepted. **Context:** k3s ships kube-router's policy controller; kr stored `NetworkPolicy` objects without enforcing them (#152). Calico (external CNI) enforces them itself. **Decision:** a controller in the kubelet (`kr-kubelet/src/netpol.rs`, root + built-in bridge, ADR-019/ADR-032/ADR-034) computes, as a pure function of the pod, namespace and policy lists, one allow-list chain per selected local pod IP and direction, and `kr-net::nft` (netlink, no `nft` binary, ADR-008/ADR-002) replaces tables `inet kr-netpol` (routed/forward) and `bridge kr-netpol` (same-node bridged traffic) atomically (create, delete, create in one batch) only when the computed result changed. Matching is on pod IPs (peers resolved from the pod list, ipBlock `except` by CIDR subtraction, named ports resolved against the selected pod for ingress and the peer pod for egress); allowed packets `return` from the pod chain so ingress and egress of the same packet both apply, the chain ends in `drop`; established/related and ICMPv6 neighbour discovery are accepted first. It is off with `KR_NETWORK_POLICY=off` and with `KR_CNI_CONF_DIR` set (the external CNI enforces), and a no-op rootless. **Consequences:** only forwarded traffic is filtered: traffic to/from the node (probes, DNS/Service ClusterIPs, the userspace Service proxy of ADR-022) is not, so #165 stays open until the DNAT datapath of ADR-045; rules are per peer IP and the controller polls every 3 s (NEW-2, NEW-3). The proxy was deliberately not changed.

**Addition (ADR-023, 2026-11-12):** node authorizer: `persistentvolumeclaims/status` get/patch/update only for claims of pods bound to the node, CSINode writes only for the node's own object; `system:node` also holds the CSI/volume reads of ADR-041, RuntimeClass reads and CSR create/get/list/watch. CSR approval is validated in `update_ex` (`rbac::csr_update_check`, ADR-042): only Approved/Denied/Failed through `approval`, frozen once issued, `approve` on `signers` required, `system:masters` in a client request needs a `system:masters` approver.
**Addition (ADR-028, 2026-11-12):** apply ownership and merging use list/map types: CRD schema markers or, for built-in types, the upstream marker table in `ssa::builtin_lists`; a keyed item is removed only if no other manager owns part of it (KNOWN_ISSUES #146).
**Addition (ADR-029, 2026-11-12):** `--pod-security-config` (defaults, exemptions), `-version` labels (partial pinning) and the `audit` mode annotations: ADR-046.
**Addition (ADR-043/047, 2026-11-12):** `kr snapshot` archives now include `encryption-config.json` when present.

## ADR-050: Offload CPU-bound work from the event loop before going multithreaded

**Status:** proposed (plan; not implemented). **Context:** the control plane is single-threaded (ADR-004, ADR-005, #126). Measured and expected stalls come from CPU-bound steps on that thread: TLS handshakes (#209), large JSON serialisation/parsing including audit bodies (#210, #187), image pull and unpack (#211), hashing, snapshots and the encryption codec (#212), and Raft sharing the loop with API serving (#213). Going fully multithreaded needs a thread-safe allocator and `Send` data structures through the whole code base (#126), a large change. **Decision:** keep one event-loop thread and move specific blocking work to helpers, in this order: (1) a stall watchdog and Raft heartbeat priority, with configurable election timeouts (#213), so the problem is measured; (2) chunked/yielding list serialisation and cached OpenAPI/discovery documents (#210), which need no helper; (3) a bounded offload facility in `kr-rt` (#208), preferring worker processes over a socketpair as the fsync helper of ADR-024 (byte-in/byte-out, no shared allocator), with inline fallback when it cannot start; (4) users of it in this order of payoff: image pull and unpack (#211), TLS asymmetric operations (#209), snapshot images via fork (#212). **Consequences:** latency of the loop is bounded by the longest inline step, not by the largest object or image; memory is copied across the helper boundary; helpers add processes to supervise; `kr-crypto` and TLS internals stay untouched (the offload wraps their API). Full multithreading (#126) remains the long-term plan for throughput, not for latency.

## ADR-051: TLS 1.3 session resumption (PSK with ECDHE, stateless tickets)

**Status:** accepted and implemented (supersedes the "no resumption" note of ADR-020 for TLS 1.3). **Context:** every reconnect of a kubelet, controller or client did a full handshake, about 1.2 ms of CPU on the single event loop (ECDHE, the server signature, and for mutual TLS the client chain verification and signature check, #209/#220). A restart makes hundreds of clients reconnect at once. **Decision:** RFC 8446 section 2.2 resumption with `psk_dhe_ke` only, no 0-RTT/early data (so no replay window and forward secrecy is kept: a resumed handshake still does one ECDHE and the traffic keys depend on it).
* **Server tickets are stateless.** After the client Finished the server sends one `NewSessionTicket`. The ticket is `key_id(8) | nonce(12) | ChaCha20-Poly1305(key, nonce, aad = key_id, plaintext) | tag` under a random 32-byte ticket key kept in memory only, rotated every hour with the previous key still accepted (a ticket lives at most one hour). The plaintext holds: format version, the PSK (`HKDF-Expand-Label(resumption_master_secret, "resumption", nonce)`), cipher suite, the valid-until time, a hard limit, the ALPN protocol that was negotiated, a config binding, and the client's certificate chain (DER) when mutual TLS authenticated one.
* **Identity survives resumption.** kr authenticates API clients by their certificate (`peer_certificates()`), and a resumed handshake carries no Certificate message, so the verified chain is stored in the ticket and restored on resumption. The ticket's validity is capped at the earliest `notAfter` of that chain, so a resumed session never outlives the certificate that authenticated it. A ticket without a chain is refused when the config requires client certificates.
* **Config binding.** The ticket carries SHA-256 over the server leaf certificate, the client-auth mode and the client trust roots; a ticket from another configuration (or after the CA or server certificate changed) is ignored and the handshake falls back to a full one. Ticket keys are per process and not persisted, so a restart invalidates all tickets, and tickets do not work across HA servers: both fall back to full handshakes, which is always safe.
* **Chains are bounded.** A resumed connection issues a fresh ticket, but with the original hard limit (24 hours from the first full handshake) and certificate cap, so a client cannot keep a session alive indefinitely by resuming.
* **Client.** A cache keyed by a fingerprint of the `ClientConfig` (roots, pin, client certificate, ALPN) plus the server name holds one ticket per key, used once (taken from the cache when offered) and replaced by the ticket of the new connection. The `pre_shared_key` extension is last in the ClientHello with a binder over the transcript up to the binders (also after a HelloRetryRequest); the server's `selected_identity` must be 0, and a ServerHello without it means a normal full handshake. `client_insecure` connections neither store nor offer tickets. The server certificate chain of the original handshake is kept with the ticket so `peer_certificates()` stays populated.
* **Wiring.** `kr-crypto` stays free of global state and `unsafe`: `Connection::server_with_tickets` and `Connection::client_with_sessions` take plain function pointers (`TicketHooks`, `SessionHooks`); `kr-net` owns the process-wide `TicketKeys` and `SessionCache` behind a small spin lock and passes the hooks from `TlsStream::accept`/`connect`.
* **Not done:** TLS 1.2 resumption, sharing ticket keys between HA servers, 0-RTT, ticket revocation (lifetime is the control), `psk_ke` without ECDHE.
**Consequences:** a resumed handshake does one ECDHE and two HMACs instead of a certificate exchange and two signature operations (about 0.2 ms against 1.2 ms for mutual TLS); tickets are bearer credentials for the session's identity for up to an hour, protected only by the in-memory ticket key (a process memory dump exposes both, as it exposes the server key); a client certificate that is revoked by replacing the CA stays usable by tickets until they expire or the server restarts.
**Addendum (shared ticket keys):** `kr server` derives the ticket keys of an hour from the service-account key (`HKDF`, purpose-labelled), so HA servers open each other's tickets and a restart keeps them (hour `h`, accepted for `h-1..h+1`); agents and servers without a shared secret keep random per-process keys. The ticket's config binding still keeps tickets of servers with different certificates apart. The consequence to remember: `sa.key` now also protects against forged client identities in tickets; the ticket plaintext holds the verified client chain, so a forger would choose it.

## ADR-052: Offload workers for CPU-bound work

**Status:** accepted and implemented (first step of ADR-050). **Context:** big list renderings (Table, metadata-only, CRDs with defaults) and RequestResponse audit bodies ran as one poll of the event loop (52 ms for a 3000-pod Table, longer for bigger objects). **Decision:** `kr_rt::offload`: a pool of worker *processes* (default 2, `KR_OFFLOAD_WORKERS`, 0 = off), forked by `kr server` at the start of `main` so they inherit a small address space and none of the listeners (they close every descriptor but their socketpair, and die with the server by `PDEATHSIG`). A worker runs one registered function `handler(kind, request bytes) -> response bytes`; it sees only what it is sent (the allocator and `Rc` state are not shared, which is why threads were not used). The loop talks to a worker over its socketpair with the executor's asynchronous I/O, so it keeps serving while a worker parses and renders. `call` returns `None` when no worker can take the job (none, all busy with 16 callers already queued, the worker died or was killed by a cancelled call); the caller then runs the same handler inline, so a job is always done and gives the same bytes. A dropped call kills its worker (the pending reply would be mixed up with the next job) and the pool replaces it on demand. **Users:** (1) *Lists.* While the transport is in a `GET`, `ApiServer::list` may leave a `ListJob` (kind, payload, finish) instead of rendering inline, when the items total at least 256 KB and the kind has no conversion webhook: Table rows (`KIND_TABLE_ROWS`), metadata-only lists and CRD lists with schema defaults (`KIND_ITEMS`). The items travel as their stored JSON, the worker parses and renders, the loop splices the answer into the response head. (2) *Audit bodies* (`KIND_AUDIT_BODY`): for a request or response body of 256 KB or more at level Request/RequestResponse the event is built without the bodies on the loop, and a spawned task has the worker decode, strip `managedFields` and serialise them; it appends `requestObject`/`responseObject` and writes the event when done, after the response has gone out. **Consequences:** a large list or audit body costs the loop the copy of the bytes through the socket (about 4 MB in 3 ms) instead of the parse and render (the longest gap of the event loop during a 3000-pod Table list: 52 ms inline, 3.8 ms offloaded); a worker is a process per slot (RSS of the fork, shared copy-on-write at the start); audit events with big bodies may appear in the file after later events (their timestamps are those of the request); the first request after a worker dies is rendered inline. Not done: moving image pull/unpack (#211), snapshot images (#212), file writes (#223) and TLS handshakes (#209) onto the facility; they can use it by registering another job kind.
**Addendum (image pulls, #211):** a second pool class, `SLOW` (`KR_OFFLOAD_SLOW_WORKERS`, default 2, started by `kr server` and `kr agent`), runs jobs that take seconds so they never queue the short list jobs: `KIND_INSTALL_IMAGE` (`pull::install_image`: gunzip, SHA-256 and tar extraction of every layer into the rootfs), `KIND_VERIFY_BLOB` (`Store::verify_blob` of a blob already in the store) and `KIND_FSYNC_FILE` (the fsync of a downloaded blob before it is renamed into place). These touch only files of the store, so the job is the store root and digests, and a failure comes back as text (`Error::Remote`). The download itself stays on the loop but no longer starves it: `pull_blob` yields after 5 ms of continuous work (on a fast link every read is ready at once) and the stream is hashed once, by the blob writer, instead of twice. Without workers (`kr ctr pull`, a worker class set to 0) the same functions run inline.


## ADR-053: Configurable IPv4 pod and Service networks

**Status:** accepted and implemented. **Context:** the pod network (`10.88.0.0/16`) and Service network (`10.96.0.0/16`) were constants, so a site that already used those ranges could not install kr (k3s: `--cluster-cidr`, `--service-cidr`). **Decision:** `KR_POD_CIDR` and `KR_SERVICE_CIDR`, each an `A.B.0.0/16` (not equal, not loopback/multicast), read once at start-up by `server`, `agent` and `ctr` into `kr_net::cidr`; every place that had the literals asks it (node `podCIDR` `A.B.N.0/24`, the ServiceCIDR object, `kubernetes` at `.0.1` and `kube-dns` at `.0.10`, ClusterIP validation and allocation, the Service proxy's local route, masquerade, the pod DNS address, the API server certificate's SAN, the DNS server's cluster-address test). A /16 keeps the node-subnet arithmetic (a /24 per node, 256 nodes, host octet in the IPv6 twin) unchanged; other prefix lengths are refused. The IPv6 networks (`fd00:88::/32`, `fd00:96::/112`) stay fixed: they are ULA ranges nobody else uses. **Consequences:** the value must be set before the cluster's first start and be identical on the server and every agent (an agent does not learn it from the server; the join does not check it); changing it on an existing cluster is unsupported, as in k3s (existing Services and pods keep their addresses). The bootstrap ServiceCIDR object follows the setting (ADR `kr.io/autoupdate`). Test: `tools/test/cidrs.sh`.

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

## ADR-013: Phase 1 layering, with plain-HTTP registries until TLS lands
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
`kr-runtime` isolates containers with kernel primitives directly: no podman/runc, consistent with ADR-007.
- A **user namespace** is created first, unprivileged. Inside it we are uid 0 and can create mount, pid, net, uts, ipc and cgroup namespaces, mount overlayfs (Linux ≥ 5.11) and call `pivot_root`.
- **cgroup v2** limits go through a delegated subtree: `systemd-run --user --scope -p Delegate=yes` in dev, and the agent's own systemd unit (`Delegate=yes`) in production. The controllers available rootless are cpu, memory and pids. io and cpuset need a root agent.
- **seccomp** (a BPF filter plus `NO_NEW_PRIVS`) and capability dropping need no privileges.
- Tests run rootless on the dev box, so there is no sudo and no VM in the normal loop. A throwaway **qemu VM** is used only for paths that need real root: host-level network setup (bridge, veth to host, nftables), the io/cpuset controllers, and running as a root agent.
**Verified on the dev box (2026-10-23):** user+mount+pid namespaces, overlayfs inside a userns, netns creation, and cgroup delegation via systemd-run all work unprivileged.
**Status:** accepted.

## ADR-017: Flattened per-image rootfs + per-container overlay; safe unpack via openat2
- Each image's layers are applied in order into one flattened directory: `<root>/images/<config-digest>/rootfs`. Whiteouts are applied by deleting. A container gets an overlay with that directory as `lowerdir` and a private `upper`/`work`, mounted with `userxattr` (ADR-016).
  **Why:** whiteout char devices (0:0) and `trusted.*` xattrs are not reliably creatable rootless, so flattening sidesteps both. **Cost:** disk space is not shared between images that share base layers (*revisit:* layer-level lowerdirs once running as root).
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
  - Rootless networking (slirp/pasta-style) is out of scope; rootless containers stay loopback-only.
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
  - **Server-side apply** is approximated as create-or-strategic-merge.
  - **Status/scale:** status and scale subresources; `generation` bumps when `spec` changes.
  - **Deletes:** finalizer-aware deletes, and synchronous namespace deletion.
  - **Watches:** chunked NDJSON with selector enter/leave semantics, and 410 for compacted revisions.
  - **Server-side Table printing:** `kubectl get`.
- **Lists:** stored JSON is spliced directly into list responses; no decode/encode per item.
- **Authentication:** TLS client certificates against the cluster CA (CN = user, O = groups). Until RBAC lands, only `system:masters` is authorized.
- **Bootstrap:** `kr server` creates the CA, the apiserver and admin certificates, and `admin.kubeconfig` on first start.
- **Protobuf request bodies** (sent by kubectl's typed clients) are decoded with a generated schema table; responses are always JSON.

**Status:** accepted.

## ADR-022: Services, cluster DNS and multi-node
**Context:** phase 5 needs Service VIPs, cluster DNS and nodes joining a server, without iptables/ipvs/CoreDNS binaries and in both root and rootless modes.

**Decision:**
- **Service proxy:** a userspace proxy inside kr. One `local 10.96.0.0/16` route makes every ClusterIP bindable in the node network namespace.
  - kr listens on ClusterIP:port (and 0.0.0.0:nodePort) and splices to ready endpoints (round-robin or ClientIP affinity). UDP gets per-client sessions.
  - Rootless, a socket factory inside the pod-network namespace creates the sockets and passes them over SCM_RIGHTS.
  - Trade-off: lower throughput than a kernel datapath, but identical behaviour as root and rootless, no packet-rewrite rules, and simple testing. An nftables DNAT datapath can replace it later behind the same reconcile loop.
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
  - **Node certificate rotation:** `/kr/join` also accepts a node's own certificate and re-issues for the same name only. The agent renews at 2/3 of the lifetime with fresh keys, replaces the files via rename, and swaps the TLS configs in place (`Remote::set_client_cert`, the kubelet server's `tls_slot`). There's no CSR API, because kr issues directly.
  - `KR_NODE_CERT_SECONDS` shortens node certificates for testing.

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
- **In-process writers:** the controllers and the server's own kubelet call the API in-process and don't await durability. A background task flushes their writes every second, so a crash can lose up to about one second of them. These components re-derive their state from the API, so that's acceptable.
- **Watch delivery:** watch events are delivered when written, not when durable. This is a deliberate small deviation from etcd.
- **Compaction:** every minute, the log is rewritten into a snapshot once it exceeds 8 MiB and is more than 4× the live data.

**Status:** accepted.

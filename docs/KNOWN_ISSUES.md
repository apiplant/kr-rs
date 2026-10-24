# Known Issues & Potential Problems

Living list, grouped by what still needs doing. Each item: **status**, impact, plan. Numbers are stable (other docs cite them); new items get the next number. When an item is resolved, mark it *fixed* with the commit and run `python3 -I tools/sort_known_issues.py`.

# Needs work (open or partial)

## Runtime (kr-rt)
4. **Allocator never returns small blocks to the OS** — *open*
   RSS grows to peak usage and stays there. Fine for the agent, but it could matter for a long-running server. Plan: return a chunk with `madvise(MADV_DONTNEED)` once it is fully empty.
6. **Large allocations with alignment above 4096 are not honoured** — *open*
   They go through mmap, which only guarantees page alignment. Plan: over-allocate and trim.
10. **mem\* are byte-by-byte on non-x86_64, and memcmp/bcmp everywhere** — *open (perf)*
    Plan: word-at-a-time versions once there are benchmarks.

## kr-sys
11. **aarch64 path is untested** — *open*
    It compiles under cfg but has never run. Plan: a qemu-user CI job.

## kr-net
30. **Keep-alive pool has no idle timeout** — *open*
    Stale connections are detected only when reused (one retry for GET/HEAD). Add a timer-based eviction if long-lived clients appear.
31. **Registry auth supports anonymous Bearer tokens only** — *open*
    No Basic auth, no credentials (`~/.docker/config.json`), no token refresh by expiry (a token is retried once after a 401), and `scope` is taken from the challenge or defaults to `repository:<repo>:pull`.

## kr-sys (cont.)
35. **`syscall0..6` lack `# Safety` docs (clippy `missing_safety_doc`)** — *open (cleanup)*

## kr-runtime: isolation (container.rs, security.rs, cgroup.rs)
50. **Container networking gaps** — *partly fixed* (ADR-019, ADR-022)
    Pods get a bridge network as root and rootless (an infra user+net namespace holds the bridge), and ports are published through hostPort/NodePort (userspace proxy).
    Remaining:
    - IP leases leak if kr is SIGKILLed; a GC pass at startup is needed.
    - IPv4 only.
    - Standalone `kr ctr run` containers are still loopback-only when rootless.

## Build (cont.)
53. **Binary size** — *watch*
    The binary is 395 KB with TLS, X.509 and the crypto suite included. That is still far under the 2 MB agent budget. Avoid `{:?}` on hot or large types.

## kr-crypto / TLS (ADR-020)
58. **Constant-time behaviour is by construction, not yet measured** — *open*
    The plan's dudect-style timing checks on x25519, P-256 signing, Ed25519 signing and the AEADs are still to do (phase 6 fuzz/timing harness).
60. **P-256 scalar multiplication is a plain ladder (~0.8 ms sign, ~1.5 ms verify)** — *watch*
    That is fine per handshake. Fixed-base tables would speed up the apiserver when there are many clients.
61. **No TLS 1.2 client** — *open*
    Some CDNs only speak TLS 1.2: `production.cloudflare.docker.com` answers TLS 1.3 with `protocol_version`. Docker Hub currently redirects blobs here to CloudFront (TLS 1.3), but registries or regions that land on such a CDN will fail.
    Plan: a client-only TLS 1.2 with ECDHE plus AEAD suites, Extended Master Secret required, and no renegotiation or resumption.

## Control plane (ADR-021)
63. **No typed schemas or defaulting** — *partly fixed*
    - Defaulting for core/apps/batch is in (`defaults.rs`, see #86).
    - kr still accepts unknown fields even with `fieldValidation=Strict`, and per-kind validation is minimal.
    - Plan: generate schemas from the upstream OpenAPI, as the protobuf table does.
65. **Server-side apply is approximate** — *open*
    `application/apply-patch+yaml` is treated as create-or-strategic-merge: there are no managedFields, no field ownership and no conflict detection. Client-side `kubectl apply` is fully supported.
70. **Conformance gaps** — *open; tracked as C1–C9 in PLAN.md*
    Done since: CRDs (#87), admission webhooks (#88), aggregated discovery, ResourceQuota, hostPort, lifecycle hooks, ephemeral containers.
    Remaining: protobuf responses, typed schemas (#63), SSA managedFields (#65), and whatever the current Sonobuoy run reports (`tools/test/conformance.sh results`).

## Node agent and controllers (phase 4)
73. **Volume and token gaps** — *mostly fixed*
    - projected, downwardAPI (fieldRef and resourceFieldRef), configMap and secret volumes work, with per-item modes.
    - They are republished every 20 s through an atomic `..data` symlink swap; the SA token is renewed at 80% of its lifetime.
    - subPath is resolved with RESOLVE_IN_ROOT inside the container mount namespace.
    - Remaining: PVCs (no storage provisioner).
75. **Resource requests are not enforced** — *partly fixed*
    CPU requests become `cpu.weight` (upstream formula). Remaining: memory requests (memory.min/low), QoS classes and eviction.
76. **Controllers are basic** — *mostly fixed*
    StatefulSet, DaemonSet, Job, CronJob and Endpoints/EndpointSlice controllers exist (49 tests), and Job admission defaulting is in.
    Remaining:
    - Deployment pause/progress deadline/minReadySeconds;
    - Job backoff delay;
    - the namespace controller (deletion is still synchronous).

## Services, DNS, multi-node (phase 5, ADR-022)
80. **host-gw networking only** — *open*
    - Nodes must share an L2 segment; VXLAN is planned.
    - Rootless agents have no cross-node pod networking.
    - Cross-node pod traffic is masqueraded (the source pod IP is hidden); the nft rule should exclude the cluster CIDR.
    - Routes of removed nodes are not deleted.
86. **Defaulting is a subset** — *open*
    Defaults cover core/apps/batch fields seen by clients; other groups (networking, policy, storage) store what was sent.
87. **CustomResourceDefinitions are a subset** — *open*
    Served CRD versions become resources at runtime (JSON only; protobuf gets 415). Enforced schema subset: type, nullable, int-or-string, required, properties, additionalProperties, items, enum, minimum/maximum, min/maxLength, min/maxItems, `default`, and pruning (unless `x-kubernetes-preserve-unknown-fields`). Not enforced: pattern, format, allOf/anyOf/oneOf/not, uniqueItems, CEL `x-kubernetes-validations`, list-type semantics, embedded-resource checks, and CRD schema structural validation. Only `conversion.strategy: None` works (apiVersion is rewritten on get/list; watch events keep the stored apiVersion); Webhook conversion is not implemented. Deleting a CRD removes its objects synchronously (no finalizer); there is no aggregated discovery, and removed CRDs leak their small registration strings until restart. Namespaced CR creation is not blocked by `Terminating` CRDs, and CRD storage-version migration is not performed (storedVersions only grows).
88. **Admission webhooks are a subset** — *open*
    Mutating then validating webhooks (admission.k8s.io/v1) run for CREATE/UPDATE/DELETE of resources and `/status` (not other subresources, not DELETE collection, no CONNECT). The write path stays synchronous: the request is dry-run through the built-in handler, the webhooks run (the only awaits) on that result, then the real request executes (with the mutated object as the body if patched), so built-in admission runs twice, webhooks see the object after built-in admission, and the dry-run and the write are not atomic. Webhooks run sequentially; `reinvocationPolicy` and `matchPolicy: Equivalent` are ignored, response `warnings` are dropped, only `JSONPatch` patches are supported, `caBundle` is required (no system roots), and configurations are read from the store per request (no cache). matchConditions use a small CEL subset: `== != < <= > >= ! && || in +`, field/index access, `has()`, `size()`, string `startsWith/endsWith/contains`, literals and lists; any other expression is an evaluation error handled by `failurePolicy`. admissionregistration.k8s.io objects are never sent to webhooks.
90. **Pod sandbox holder costs ~0.6–0.9 MB PSS per pod** — *open*
    The holder is a fork of kr and keeps ~570 kB of private copy-on-write memory. Plan: after setup, execveat the kr binary as `kr pause` (fresh tiny address space, empty environment, fds closed).

# Accepted limitations (by design, or not planned for now)

## Runtime (kr-rt)
3. **Allocator is single-threaded** — *accepted (phase 0)*
   UB if threads are ever added. It must get per-thread slabs or a lock before N-worker mode lands.
5. **Chunk tail waste** — *accepted*
   Up to 2 KiB is lost per 64 KiB chunk when a class is refilled.
7. **Wakers are `Send + Sync` by type but not thread-safe** — *accepted*
   They wrap a non-atomic `Rc`. Sending one to another thread is UB. Must be revisited together with #3.
8. **Stale epoll events after a slot is reused** — *accepted*
   A stale event only sets a readiness flag spuriously, and EAGAIN handling absorbs it. Plan: add generation tags if this ever causes trouble.
9. **`block_on` panics with "deadlock" when there is no work** — *accepted*
   This is intended, but it is a panic rather than an error.

## kr-net
28. **HTTP/1.1 client limits** — *accepted*
    No request body streaming (the body is a `&[u8]`; `body::encode_chunk` exists but the client does not send chunked requests), no proxies, no `Expect: 100-continue`, no response decompression (`Accept-Encoding: identity` is sent), no HTTP/1.0 keep-alive negotiation beyond `Connection: keep-alive`. Responses with `Transfer-Encoding` AND `Content-Length` are rejected rather than handled per the RFC's "TE wins" rule.
29. **Bare LF line endings are rejected, even though RFC 9112 allows recipients to accept them** — *accepted*
    Deliberate (ADR-015). A buggy server that sends LF-only heads will fail with `Parse("bare LF")`.
32. **Registry client is pull-only** — *accepted*
    No push, no tags/catalog listing, no referrers, no resumable or range blob download. Schema-1 manifests are rejected. A sink that has already received data from a blob with a digest mismatch must be discarded by the caller (the mismatch is only known at the end).
33. **`kr-rt` `host` feature for host tests** — *accepted*
    It removes `_start`/panic handler/allocator/`mem*` so `cargo test` works for crates that use the executor. It is enabled only via `kr-net` dev-dependencies, but cargo feature unification means `cargo test --workspace` would enable it for `kr` too; run tests per package. `Async::wait_writable` was added to `kr-rt` for non-blocking connect.
34. **Integration test with a real registry is `#[ignore]`d** — *accepted*
    `cargo test -p kr-net -- --ignored` runs `registry:2` under docker/podman on 127.0.0.1:5000, pushes busybox (needs network for the first pull) and pulls it through the client; it skips when offline or port 5000 is busy and falls back to the std fake registry when no container tool exists. The always-on tests use that std fake server.

## kr-runtime store / unpack / pull
36. **Store root env is read from `/proc/self/environ`** — *accepted*
    `kr-rt` has no environment accessor, so `store::env_var` parses `/proc/self/environ` (the startup environment; later `setenv` calls are not seen). Without procfs, only the explicit `Store::open(Some(root))` works.
37. **Rootless unpack normalises ownership, setuid/setgid and directory permissions** — *accepted*
    Ownership is not preserved (chown failures with EPERM/EINVAL are ignored), setuid/setgid bits are stripped, and directories get `|0700` so later layers, whiteouts and `rm -rf` of the store keep working (a `0555` dir becomes `0755`). As real root, modes are exact. Revisit with subuid ranges.
38. **Unpack uses O(depth) kernel path walks per entry and a recursion depth limit of 512 for removals** — *accepted*
    Each entry resolves its parent with `openat2` (no fd cache). `fs::remove_all` holds one fd per level and fails with ELOOP past depth 512. A directory with mode `000` that was not created by us cannot be emptied rootless (no `/proc/self/fd` chmod fallback).
40. **Whiteout/created-path tracking uses 64-bit FNV hashes** — *accepted*
    The per-layer set of created paths (so a layer's own entries survive its own whiteouts/opaque markers) stores hashes, not strings, to bound memory at ~8 MiB per million entries. A crafted collision can only make a layer keep a lower-layer path it meant to delete; it cannot escape the root.
41. **Pull/unpack are blocking inside the async executor** — *accepted*
    Layer unpack is synchronous file I/O and CPU (inflate) on the single-threaded executor, so other tasks stall while a layer extracts. Concurrent pulls of one image race on `rootfs.tmp` (the loser is cleaned up, but there is no lock).
42. **FIFOs are created, devices are skipped, tar xattrs on symlinks are dropped** — *accepted*
    `trusted.overlay.*` / `user.overlay.*` xattrs from layers are always ignored so an image cannot forge overlayfs markers.

## kr-runtime: isolation (container.rs, security.rs, cgroup.rs)
45. **The seccomp profile is a deny-list, not Docker's allow-list** — *accepted for now*
    It is defence in depth on top of the reduced capabilities. Only the summary state has been checked: `Seccomp: 2`, and unshare/mount are refused. Plan: per-syscall tests, then consider an allow-list.
46. **Fail-closed startup on hostile image layouts** — *accepted*
    Startup aborts with ENOENT if `/.oldroot`, `/proc` or `/dev` is a symlink in the image. This is safe (nothing escapes; verified), but such an image cannot run.
49. **The overlay mount line in `/proc/mounts` reveals host store paths** — *accepted*
    This is an information leak only.
51. **cgroup supervisor moves every process in the delegated cgroup into `kr-supervisor`** — *accepted*
    This is intended for a dedicated scope or unit. Running kr inside a shared cgroup with `Delegate=yes` would also move its neighbours.

## Build (cont.)
52. **`_Unwind_Resume` and `rust_eh_personality` are stubbed** — *accepted*
    The precompiled `core`/`alloc` contain landing pads, and with panic=abort they are never reached. Proper fix: `-Zbuild-std=core,alloc` with `panic_immediate_abort`, which also shrinks the binary.

## kr-crypto / TLS (ADR-020)
57. **TLS feature gaps** — *accepted*
    - As a server, no HelloRetryRequest: clients must offer an X25519 or P-256 key share up front. Go, OpenSSL and curl all do.
    - No TLS 1.2, no PSK/resumption, no 0-RTT, and no NewSessionTicket sent.
    - Only the SHA-256 suites (AES-128-GCM, ChaCha20-Poly1305).
    - As a client, HRR to P-256 is supported but cookies are not.
59. **Secret wiping is best-effort** — *accepted*
    `wipe` plus `black_box` zeroes keys on drop, but copies made by moves and by register spills are not tracked (no `unsafe`/volatile).
62. **Pull speed is network-bound** — *note*
    kr's HTTPS download matches curl on the same file (2.5 s vs 2.2 s for 3.5 MB on this link). Layers are fetched sequentially; parallel layer downloads would help on high-latency links.

## Control plane (ADR-021)
66. **Watch history is not persisted** — *accepted*
    After a restart, watching from an older resourceVersion returns 410 and clients relist, which is standard Kubernetes recovery.
67. **No aggregated discovery, no HTTP/2, no OpenAPI schemas** — *accepted for now*
    kubectl falls back to legacy discovery and HTTP/1.1. `kubectl explain` does not work.
68. **Namespace deletion is synchronous** — *accepted*
    Contents are deleted inline rather than by a namespace controller, and finalizers inside the namespace are not honoured during this cascade.

## Node agent and controllers (phase 4)
78. **exec/probe processes join the container cgroup slightly late** — *accepted*
    The kernel refuses CLONE_INTO_CGROUP after joining the container's cgroup namespace. kr moves the process via cgroup.procs right after the clone, so there is a brief window outside the container's limits.

## Services, DNS, multi-node (phase 5, ADR-022)
79. **Userspace service proxy** — *accepted for now*
    Throughput is limited by kr's copy loop, and source IPs are not preserved to backends. Not supported: SCTP, externalTrafficPolicy, topology hints, and LoadBalancer status (a LoadBalancer gets a NodePort only).
83. **Node-proxied logs report 200 before contacting the node** — *accepted*
    Errors arrive in the body. A direct `Upgrade: SPDY/3.1` (port-forward, or exec from client-go/sonobuoy) to *remote* nodes is not proxied; it works for pods on the server node, and kubectl's default WebSocket path works everywhere.
84. **DNS: no negative caching or prefetch** — *accepted*
    The zone snapshot is rebuilt every second from full lists, which is fine for small clusters.
85. **SPDY exec: no TTY resize, v4 only** — *accepted*
    The `resize` stream is accepted and ignored; clients offering only v1–v3 are refused.

## kr-archive
19. **Tar: no sparse files, unknown type flags are errors, strings must be UTF-8** — *accepted*
    GNU sparse (`S`, pax `GNU.sparse.*`) and any non-standard typeflag fail with `UnsupportedType`. Non-UTF-8 names, link targets or pax values fail with `InvalidUtf8`. Container image layers do not use these. Revisit if a real layer hits them.
20. **pax `mtime` fractions are truncated; global (`g`) pax `path`/`linkpath`/`size` are ignored; `LIBARCHIVE.xattr.*` is not parsed (only `SCHILY.xattr.*`)** — *accepted*
22. **gzip: any non-gzip trailing bytes after the last member are an error** — *accepted*
    Unlike `gzip -d`, which tolerates zero padding. Also, a stream that ends cleanly without ever feeding a byte is `Truncated`. Only DEFLATE with CM=8 is supported (no zlib/raw-deflate wrapper API beyond `Inflater`).
23. **Inflate throughput depends on the profile** — *accepted*
    The workspace release profile uses `opt-level = "z"`. The 50 MB benchmark (`cargo test --release -p kr-archive --test gzip -- --ignored --nocapture`) measures about 800 MB/s on this machine, well above the 150 MB/s target, but re-check if the profile or target changes.

## Build
13. **Linker passes `-pie` alongside `-static`** — *accepted*
    The output is `ET_EXEC` with no relocations, which was verified. Re-check after toolchain bumps, since a static-pie would need self-relocation in `_start`.

## kr-fmt
15. **YAML subset gaps** — *accepted*
    These are rejected or approximate:
    - `[a: b]` single-pair mappings inside flow sequences;
    - multi-line quoted keys;
    - some blank-line edge cases in block scalars;
    - ints wider than 64 bits, which degrade to f64.
    Revisit if real manifests hit them.
16. **JSON duplicate keys are kept (last one wins on `get`); YAML duplicate keys are an error** — *accepted*
    The behaviour is inconsistent, but each matches its consumer: the apiserver can enforce strictness at a higher layer.
17. **Quantity mantissa is i128** — *accepted*
    `1e40` is OutOfRange. k8s has the same practical bounds.

# Resolved

## Runtime (kr-rt)
1. **Pending task + Async forms an Rc cycle** — *fixed* (commit: 68940ad)
   The task owns the future, the future owns the `Async`, the `Async`'s I/O slot owns a waker, and the waker owns the task. A task that never completes is never freed.
   Plan: add `JoinHandle::abort()` to drop the future and break the cycle, and add a live-task counter for leak detection. Rule: every network wait must have a deadline.
   Fix: `JoinHandle::abort()` drops the future immediately, and the handle then resolves to `Err(Aborted)` (the output is now `Result<T, Aborted>`, and there is also `is_finished()`). `exec::live_tasks()` counts tasks until their `Task` is freed, and `kr sleep-test` asserts on it (`live_tasks_ok`). A task that never completes and has no deadline or abort is still a leak hazard by design.
2. **`sleep` can fire up to 1 ms early** — *fixed* (commit: 68940ad)
   The millisecond clock is truncated. Plan: round deadlines up, so a sleep never fires before it was asked to.
   Fix: deadlines are computed in ns (`now_ns`), `Sleep` completes only when `now_ns >= deadline`, and the wheel entry uses `ceil(deadline_ns / 1e6)`. `kr sleep-test` verifies every elapsed time is >= the requested one.

## kr-net
25. **No DNS: only IP literals, `/etc/hosts` and a built-in `localhost`** — *fixed*
    kr-net has a UDP/TCP stub resolver (`dns.rs`, `SystemResolver`: /etc/hosts then resolv.conf nameservers). IPv6 zone ids are still not parsed.
26. **TLS is not implemented; `https` URLs fail with `Error::TlsUnsupported`** — *fixed (ADR-020)*
    `kr-net::tls::TlsConnector` serves `https`, and image pulls use it. Trust anchors come from `KR_CA_BUNDLE` or the system bundle.
27. **Interim SHA-256 in `kr-net/src/sha256.rs`** — *fixed*
    It now re-exports `kr_crypto::sha2`.

## kr-runtime store / unpack / pull
39. **Layer diff_ids are verified** — *fixed* (commit: 38ed253)
    The pull hashes each uncompressed layer tar while inflating and compares it with `rootfs.diff_ids[i]`, failing on mismatch. Still open: zstd layers (`+zstd`) are rejected with `Error::Image`. Pulled-image refs are never refreshed (a moved `:latest` is not re-fetched once present).

## kr-runtime: isolation (container.rs, security.rs, cgroup.rs)
43. **Rootless maps a single uid/gid** — *fixed*
    kr maps a subordinate range from `/etc/subuid`/`/etc/subgid` through `newuidmap`/`newgidmap`, and the identity range as root. Image `USER` (and `--user`) resolves against the image's own passwd/group after pivot_root.
    Verified in a throwaway privileged container: nginx serves its page, `adduser`+`su` works, and subuid-owned files with mode 700 are deleted on cleanup (done from a userns, `IdMaps::run_as_root`).
    Remaining limits:
    - Without a range, only root is mapped and a non-root USER fails with a hint.
    - Rootless unpack drops image file ownership, so everything is owned by container root.
    - `newuidmap` is the only host binary used.
44. **`/proc` is not masked** — *fixed*
    Docker's masked paths (`kcore`, `keys`, `timer_list`, `sched_debug`, ...) get `/dev/null` or an empty read-only tmpfs. `/proc/sys`, `bus`, `fs`, `irq` and `sysrq-trigger` are bind-remounted read-only (keeping the userns-locked flags). Verified: `/proc/kcore` reads 0 bytes and writes to `/proc/sys` give EROFS.
47. **No signal forwarding** — *fixed*
    `kr ctr` blocks SIGINT/SIGTERM, reads them from a signalfd and forwards them via `pidfd_send_signal`. A second SIGINT sends SIGKILL, since pid 1 without a handler ignores the first. The child resets its signal mask before exec. Verified: a trap in sh sees TERM, and double Ctrl-C on `sleep` exits 137.
48. **`container::run` blocks on `wait4`** — *fixed*
    `container::start` returns a `Running`. `Running::wait()` is async: a `CLONE_PIDFD` pidfd on the epoll executor plus `waitid(P_PIDFD, WNOHANG)`. `Signaller` clones the pidfd so another task can signal. The blocking `run()` remains for simple callers.

## kr-crypto / TLS (ADR-020)
54. **Constant-time AES-GCM is slow** — *fixed: 3.5 → 51 MB/s*
    - **AES:** 4 counter blocks per bitsliced pass (`u64` planes) and the Boyar–Peralta S-box circuit, exhaustively checked.
    - **GHASH:** BearSSL's ctmul64 carry-less multiply, cross-checked against the bit-serial reference.
    - **Why it matters:** AWS ELB (registry-1.docker.io) picks AES-128-GCM regardless of client preference.
55. **No RSA signature verification** — *fixed*
    - **RSA:** PKCS#1 v1.5 and PSS (SHA-256/384/512), 2048–8192-bit keys. Wycheproof 1275/1275.
    - **P-384:** ECDSA verification (generic `ecc` module shared with P-256). Wycheproof P-384/SHA-384/512 and P-256/SHA-512 suites all pass.
    - **TLS:** rsa_pss_rsae_* and ecdsa_secp384r1_sha384 for CertificateVerify; PKCS#1 schemes are advertised for certificate signatures only.
    - **Verified:** `kr ctr pull docker.io/library/alpine:3.20` (Let's Encrypt P-384 chain for auth, Amazon RSA chain for the registry, CloudFront blobs) and an OpenSSL RSA-chain server.
56. **No DNS resolver** — *fixed*
    - `dns::SystemResolver`: `/etc/hosts`, then A/AAAA over UDP with TCP fallback on truncation.
    - Honours resolv.conf `nameserver`, `search`, `ndots`, `timeout` and `attempts`.
    - Spoofing defences: random ids, connected sockets and question echo checks. Name decompression is strict, with backward-only pointers.
    - No caching yet.

## Control plane (ADR-021)
64. **RBAC not implemented** — *fixed*
    - Roles, ClusterRoles and bindings are enforced.
    - Bootstrap policy: cluster-admin, admin/edit/view, system:discovery, public-info, basic-user, issuer discovery.
    - ServiceAccount tokens: ES256 JWTs via TokenRequest, optionally pod-bound; revoked when the SA or pod is deleted.
    - Bearer authentication; `kubectl auth can-i` works via SelfSubjectAccessReview.
    - Remaining: aggregated ClusterRoles (aggregationRule), bootstrap tokens for joining nodes, and the TokenReview/SubjectAccessReview APIs.
69. **No garbage collection by ownerReferences** — *fixed*
    `kr-controllers/src/gc.rs` deletes dependents whose owners are gone (background propagation) and honours orphan/foreground deletion.

## Node agent and controllers (phase 4)
71. **No probes** — *fixed*
    exec, tcpSocket and httpGet as startup, liveness and readiness probes, with upstream thresholds. Network probes run inside the pod network namespace (they work rootless). HTTPS httpGet probes are treated as TCP probes.
72. **No `kubectl logs/exec/attach/port-forward`** — *fixed*
    - logs (`--tail`, `-f`), exec (WebSocket v4/v5, stdin, exit codes) and attach work.
    - port-forward works over SPDY/3.1, both tunneled in WebSocket and as a direct upgrade, verified with kubectl 1.37.
    - Remaining: no TTY (`exec -t` runs without a terminal); attach is output-only; `logs --previous` returns the current file.
    - Port-forward does not enforce SPDY flow control, because kubectl ignores it; backpressure comes from the transport instead.
74. **Rootless pods have no pod IP** — *fixed*
    An infra user+net namespace holds the bridge, and pod sandboxes are nested in it. Pods get IPs and reach each other (verified).
    Remaining limits:
    - The host cannot reach pod IPs directly (use port-forward).
    - Pods have no outbound internet rootless; that needs a user-mode network stack (slirp/pasta-like).
77. **Image pulls block the kubelet sync loop** — *fixed*
    Pulls run as background tasks; failures back off and are reported as `ImagePullBackOff`.

## Services, DNS, multi-node (phase 5, ADR-022)
81. **No Node authorizer** — *fixed* (ADR-023)
    Nodes read only the secrets/configmaps/PVCs of their own pods and write only their own Node, Lease and pods. Pods themselves remain readable cluster-wide (as upstream). Token requests are checked by service account, not by `boundObjectRef`.
82. **Bootstrap token never expires** — *fixed* (ADR-023)
    `kr token create --ttl 24h` mints expiring join tokens; the server's initial `node-token` stays permanent (k3s-style), so delete its Secret (`kube-system/bootstrap-token-<id>`) to retire it. Agents rotate their client and serving certificates at 2/3 of their lifetime and hot-swap them, with no restart. Remaining gaps: expired token Secrets are not garbage-collected, and the server's own certificates (apiserver, admin, kubelet-client; 1 year) are not rotated.
89. **Agent join token visible in the process list** — *fixed* (commit: b37c07d)
    `kr agent --token VALUE` exposed the token in /proc/<pid>/cmdline. Use `--token-file` (must be mode 600) or `KR_TOKEN`; `--token` still works but warns.

## kr-archive
21. **Hardlink/symlink targets and the symlink-traversal check** — *fixed* (commit: 38ed253)
    Every path (and hardlink target) resolves via `openat2(RESOLVE_IN_ROOT)` against the rootfs fd and entries are created with `*at` calls that never follow the final component; regression tests cover absolute/`..` symlinks, earlier-layer symlink parents, outside hardlinks and `..` paths.
24. **Decompression-bomb limits** — *fixed* (commit: 38ed253)
    `Limits` caps uncompressed bytes per layer and per image (8 GiB each, spent down across layers by the pull), entry count and path length; failure removes `rootfs.tmp`.

## kr-fmt
18. **14 clippy style lints in kr-fmt** — *fixed* (commit: )

## Echo server (demo only)
12. **The 431 path closes with unread data, so the client may see a TCP RST** — *fixed* (commit: 68940ad)
    Plan: lingering close. Send the response, `shutdown(SHUT_WR)`, then drain the input for up to 1 s and close.
    Fix: `linger_close` runs after every response (not only the 431) using the new `kr_sys::shutdown`. Note that a request whose headers are complete is answered 200 even if a large body follows, and the lingering close drains that body without a reset.

## Echo server (cont.)
14. **The lingering close holds each connection for up to 1 s after the response** — *fixed* (commit: )
    Under heavy load this raises the number of concurrent connections. Plan: skip the drain when the request was fully read, and cap total lingering connections.

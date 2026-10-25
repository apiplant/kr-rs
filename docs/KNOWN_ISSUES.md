# Known Issues & Potential Problems

Living list, grouped by what still needs doing. Each item: **status**, impact, plan. Numbers are stable (other docs cite them); new items get the next number. When an item is resolved, mark it *fixed* with the commit and run `python3 -I tools/sort_known_issues.py`.

# Needs work (open or partial)

## kr-sys
11. **aarch64 path is only partly exercised** — *mostly fixed*
    `tools/test/aarch64.sh` exits 0 (verified 2026-10-24): cross-builds `kr` (aarch64-unknown-linux-gnu, rust-lld shim, no cross gcc) and runs under `qemu-aarch64`: `version`, `sleep-test` and the HTTP `echo` server pass; unit tests of kr-sys, kr-rt, kr-fmt, kr-crypto, kr-archive, kr-store and kr-net pass (aarch64 musl, self-contained): 281 passed, 4 ignored (Wycheproof P-256-sign, RSA-8k, gzip bench, tar sparse), 0 failed. Fixed: missing `getauxval` (compiler_builtins outline atomics) broke linking.
    Remaining: `kr ctr`/kubelet/apiserver paths (namespaces, cgroups, clone3, mounts) are not run under qemu-user and need a real aarch64 host; no CI job yet.

## kr-runtime: isolation (container.rs, security.rs, cgroup.rs)
50. **Container networking gaps** — *partly fixed* (ADR-019, ADR-022)
    Pods get a bridge network as root and rootless (an infra user+net namespace holds the bridge), and ports are published through hostPort/NodePort (userspace proxy).
    Remaining:
    - Kubelet pod leases are garbage-collected at startup (`network::gc`; leases owned by pod uids are stale after a kr crash). Fixed: leases of standalone `kr ctr run` containers record the owning process (pid + start time, so reused pids don't count; zombies count as dead) and are collected by the next `kr ctr run` or kubelet start once that process is gone (verified with SIGKILL in a container).
    - IPv4 only.
    - Fixed: rootless `kr ctr run` containers get a bridge address: concurrent runs share one infra user+net namespace (a detached supervisor holds it, published in `<root>/ctr-net`, gone 5 s after the last run) and lease from the same ipam dir as pods. Verified as a non-root user: two containers ping and wget each other, a SIGKILLed run's lease is reclaimed. Like rootless pods they have no egress (the infra namespace has no route out) and no published ports. Also fixed: the nested rootless uid map was written as one extent (`0 0 1+N`) and failed with EPERM whenever the user has a subuid range.
    - Rootless pods and `kr ctr run` containers have no outbound connectivity (no slirp/pasta-style egress).

## Build (cont.)
53. **Binary size** — *watch*
    The single binary (server, agent, runtime, TLS/crypto, CRDs, webhooks) is ~1.8 MB on x86_64, just under the 2 MB agent budget from PLAN.md (aarch64: ~1.5 MB). Measure before adding large features; avoid `{:?}` on large types, and keep `opt-level = "z"` + LTO + strip.

## kr-crypto / TLS (ADR-020)
60. **P-256 scalar multiplication is slow** — *watch* (commit: 3440e98)
    Now a constant-time fixed 4-bit window (masked table scan): ~0.5 ms sign, ~0.95 ms verify (was 0.75 / 1.4 ms), dudect |t| 0.4. A fixed-base comb table would make signing ~4x faster again but costs ~100 KB RAM per process; revisit if handshake rate on the API server matters.

## Control plane (ADR-021)
63. **No typed schemas or defaulting** — *partly fixed*
    - Defaulting for core/apps/batch is in (`defaults.rs`, see #86). Fixed: client-sent `status` is dropped on PV/PVC create, so a new volume always starts `Pending` (no `Available` ⇄ `Pending` rewrite).
    - Fixed: built-in kinds are type-checked against the generated protobuf tables on create/update/patch/apply in every fieldValidation mode (400 `<Kind> in version "v1" cannot be handled as a <Kind>: json: cannot unmarshal string into Go struct field Pod.spec.containers of type []object`). Integral floats (`3.0`) are accepted for integers, unlike Go; Go type names in messages are approximate.
    - `fieldValidation` is implemented (`fieldval.rs`): unknown fields of built-in kinds are found with the generated protobuf field tables, those of custom resources are what CRD pruning would drop, and duplicate keys are reported. `Strict` answers 400 `strict decoding error: unknown field "spec.containers[0].imagee"`, `Warn` (the default) adds `Warning: 299` headers, `Ignore` is silent. For PATCH the merged object is checked (fields the stored object already had are not reported). In-process clients use `Ignore`. Per-kind *value* validation (enums, formats, cross-field rules) is still minimal.
    - Plan: generate value validation from the upstream OpenAPI, as the protobuf table does.
65. **Server-side apply is partial** — *mostly fixed*
    `metadata.managedFields` (FieldsV1, per manager/operation/subresource) is recorded on create, update, patch and apply (`crates/kr-apiserver/src/ssa.rs`). Apply (`application/apply-patch+yaml|json`, `fieldManager` required) upserts, removes fields the manager dropped (unless co-owned), returns upstream-format 409 conflicts and honours `force=true`. Lists are keyed `k:{...}` from the strategic-merge tables (built-ins) or `x-kubernetes-list-type/map-keys` (CRDs); atomic lists are owned whole, sets use `v:`. Client-sent managedFields are ignored except the `[]`/`[{}]` reset; malformed ones are 422. Verified live with `kubectl apply --server-side` (re-apply, scale conflict, `--force-conflicts`). No-op writes (PUT/patch/apply/subresources that change nothing but timestamps) are skipped like upstream: same resourceVersion, no managedFields time bump, no watch event. CRD `x-kubernetes-map-type: atomic` maps are owned and replaced whole. Remaining: no version conversion of managedFields, built-in atomic structs (`+structType=atomic`, e.g. LabelSelector) are treated as granular, no deduced-type handling for `x-kubernetes-preserve-unknown-fields`, and apply never removes defaulted values it did not set.
70. **Conformance gaps** — *open; tracked as C1–C9 in PLAN.md*
    Done since: CRDs (#87), admission webhooks (#88), aggregated discovery, ResourceQuota, hostPort, lifecycle hooks, ephemeral containers, storage (PVC/SC/PV #73).
    Since: protobuf responses (objects, lists, Status; encoded from the same tables, checked against upstream `protoc` decoding of live responses; watches and Tables stay JSON, which client-go accepts by Content-Type), built-in type checks (#63).
    Round 7 (2026-10-25, first complete run since the HA work): 460 specs in 43 min, **308 passed, 152 failed**, no hangs. Biggest groups: pod-level behaviour (subpath expansion, termination messages, hostAliases, preStop, init status, probes, LimitRange defaults, pod generation), workload controllers (rollover/proportional scaling, StatefulSet ordering, adoption, Job success policy, CronJob concurrency, preemption), webhooks (matchCondition validation, timeouts, CRD conversion), field validation (duplicates, invalid values), DNS from musl pods, hostPort, kubectl apply/describe/attach details, chunked lists, missing APIs (PodCertificateRequest, DeviceTaintRule, StorageVersionMigration, ImageVolume). The CTB failures are fixed since (2cc219a). List: `tools/test/conformance.sh results`.
    Round 5 (2026-10-25, stopped at ~300/460 specs, 165 failed): pull race gone; fixed since #100, #101. Hangs: ValidatingAdmissionPolicy/MutatingAdmissionPolicy are not enforced, so their tests loop for the full timeout (needs CEL policy evaluation).
    Round 4 (2026-10-25, in progress when triaged): ~320 failures, almost all from #98 (pull race) and #99 (DeleteOptions groups, names); both fixed, a rerun is needed for the real remainder.
    Remaining: protobuf watch streams, value validation (#63), and whatever the current Sonobuoy run reports (`tools/test/conformance.sh results`).
97. **HA (kr-raft, ADR-026) gaps** — *partly fixed*
    `kr server --cluster-init` starts a Raft-replicated control plane; `kr server --server https://<any server>:6443 --token-file <server-token>` joins one (2-phase: key material, then `POST /kr/add-server` with its own server certificate); `POST /kr/remove-server {"id":N}` (system:masters) removes one. Followers serve reads and watches locally and forward writes (HTTP and in-process) to the leader; controllers and the scheduler run on the leader only. `tools/test/ha.sh` (3 servers + agent: join, forwarding, kill -9 of the leader, controller hand-over, catch-up, identical stores, removal) passes; Raft itself is checked by a chaos simulation (`crates/kr-raft/src/tests.rs`).
    Remaining:
    - Fixed: an existing single-server datastore is converted by `kr server --cluster-init` (its image becomes the Raft snapshot at index 1, the old dir is kept as `db.imported`; `tools/test/ha.sh import`). Joining with an existing datastore is refused.
    - Fixed: a restarted server could not reach its peers when they were needed for quorum (their addresses are in the replicated store, which is behind on restart); known addresses are now kept in `raft/peers`.
    - Fixed: agents fail over. They follow the `kubernetes` endpoints (every 30 s, saved to `<agent data>/servers` for restarts) and switch to the next server when a request gets no HTTP response; `tools/test/ha.sh` kills the agent's server and restarts the agent while it is down. A write that failed mid-flight is retried on the next server, so it can be applied twice (kubelet writes are idempotent or precondition-guarded). Pods using the `kubernetes` Service already get every server.
    - A removed server never sees its own removal and keeps pre-campaigning until it is stopped (harmless: pre-vote, and its log is behind). Stop and wipe removed servers.
    - Fixed: a joining server is first a Raft learner (gets the log, counts for no quorum, never campaigns) and is promoted to voter only once it has every committed entry; a newcomer that dies while catching up no longer stalls the cluster. Membership changes are still one at a time.
    - Fixed: after an IP change a server reissues its API and Raft certificates at start, and re-registers its address through any reachable server (its own certificate is the identity); outbound links reconnect as soon as an address changes (`tools/test/ha.sh ipchange`). A server whose IP changes while running needs a restart.
    - Follower reads are as fresh as its applied log (serializable, like etcd's); only the forwarding client gets read-your-writes.
    - Snapshots are sent whole in one message (512 MB frame limit; a store image is typically a few MB to tens of MB). Plan: chunked InstallSnapshot if images grow.

## Node agent and controllers (phase 4)
73. **Volume and token gaps** — *mostly fixed*
    - projected, downwardAPI (fieldRef and resourceFieldRef), configMap and secret volumes work, with per-item modes.
    - They are republished every 20 s through an atomic `..data` symlink swap; the SA token is renewed at 80% of its lifetime.
    - subPath is resolved with RESOLVE_IN_ROOT inside the container mount namespace.
    - PersistentVolumeClaims work with a built-in local-path provisioner (default StorageClass `local-path`, `WaitForFirstConsumer`, hostPath PVs under `/var/lib/kr/storage` pinned to a node, pvc-protection, static binding, Delete/Retain reclaim, kubelet GC of deleted PV directories; verified live on two nodes). PVs carry `kubernetes.io/pv-protection` (released when not bound to a live claim); pods with a missing or unbound non-WaitForFirstConsumer claim stay Pending (PodScheduled=False, Unschedulable). Remaining: other volume types, volume expansion, snapshots, and storage capacity limits (no quota on the directories).
96. **Protobuf request bodies are only handled for DeleteOptions** — *partly fixed*
    Found in conformance round 3 (2026-10-25): about 60 e2e failures were one root cause — client-go sends DELETE bodies as protobuf DeleteOptions, and the run's binary rejected some framings with `invalid DeleteOptions: protobuf ...` (also `cannot create crd protobuf is not supported...`). The committed code decodes typed (`meta.k8s.io/v1`/`v1`) and typeless-with-fallback DeleteOptions correctly — regression-tested in `crates/kr-apiserver/tests/proto_delete.rs`; the failing run predated that binary. Since: protobuf bodies of every served built-in kind decode, including CustomResourceDefinition (apiextensions tables with the `JSONSchemaProps` unions), Binding and Eviction. Remaining: custom resources are JSON-only (as upstream), and protobuf *responses* are not implemented (#70).

## Services, DNS, multi-node (phase 5, ADR-022)
80. **Overlay networking is VXLAN or host-gw only** — *partly fixed*
    - `KR_NET_BACKEND=vxlan` (default) builds a `kr.vxlan` overlay (VNI 1, UDP 8472, nolearning) so nodes need no shared L2 segment; `KR_NET_BACKEND=host-gw` keeps plain routes and needs one L2 segment. Verified live on two docker nodes for both backends (route via `kr.vxlan`, pod-to-pod TCP keeps the pod source IP, deleting a Node removes its route and ARP entry).
    - Pod interfaces get the tunnel MTU (uplink - 50); a 4 MB cross-node transfer was verified intact.
    - Fixed: FDB/neighbour/route state is read back live by `tools/test/vxlan.sh` (3 nodes: one permanent FDB + ARP entry and one route per peer, cross-node pod wget, all removed when a Node is deleted). Nodes annotate `kr.io/net-backend`; a peer on another backend is skipped with a log line naming it (no mixed-backend routing).
    - Remaining: no IPv6, no encryption.
    - Rootless agents have no cross-node pod networking.
87. **CustomResourceDefinitions are a subset** — *open*
    Served CRD versions become resources at runtime (JSON only; protobuf gets 415). The CRD schema is checked for the main structural rules at create/update (types required, properties vs additionalProperties, no types inside allOf/anyOf/oneOf/not, no `$ref`, arrays need `items`, patterns and CEL rules must compile). Enforced on objects: type, nullable, int-or-string, required, properties, additionalProperties, items, enum, minimum/maximum (+exclusive, multipleOf), min/maxLength, `pattern` (small backtracking regex engine, 100k step limit; overflow is a validation error), `format` (date, date-time, byte, int32, int64, uuid, ipv4, ipv6, hostname, uri; loosely), min/maxItems, uniqueItems, min/maxProperties, allOf/anyOf/oneOf/not (value checks only), `x-kubernetes-list-type` set/map uniqueness, `default`, pruning (unless `x-kubernetes-preserve-unknown-fields`), and `x-kubernetes-validations` CEL rules with `self`/`oldSelf` (transition rules run only on update when the node existed; `message`/`messageExpression` supported). The CEL subset (shared with webhook matchConditions) has no `reason`/`fieldPath`, cost limits, maps/duration/timestamp/quantity/regex-capture/string-format libraries, `optional` types, or int/uint/double distinction. Not enforced: embedded-resource checks, pruning inside allOf/anyOf, ratcheting, `x-kubernetes-map-type`, and the rest of upstream's structural rules (metadata restrictions, default pruning/validation, int-or-string anyOf shape, cost estimation). Only `conversion.strategy: None` works (apiVersion is rewritten on get/list/watch); Webhook conversion is not implemented. Deleting a CRD goes through the `customresourcecleanup.apiextensions.k8s.io` finalizer (Terminating condition, creates refused with 405, a controller deletes the instances, honouring their finalizers, then the CRD). There is no aggregated discovery, and removed CRDs leak their small registration strings until restart. CRD storage-version migration is not performed (storedVersions only grows).
88. **Admission webhooks are a subset** — *open*
    Mutating then validating webhooks (admission.k8s.io/v1) run for CREATE/UPDATE/DELETE of resources, `/status`, `*/scale` updates, DELETE collection (per item), and CONNECT for `pods/exec|attach|portforward` (options from the query); `pods/binding` and `serviceaccounts/token` run on the request body. The write path stays synchronous: the request is dry-run through the built-in handler, the webhooks run (the only awaits) on that result, then the real request executes (with the mutated object as the body if patched), so built-in admission runs twice, webhooks see the object after built-in admission, and the dry-run and the write are not atomic. CONNECT and body-only subresources reach webhooks before RBAC/existence checks (no dry-run). `pods/eviction` is served with PodDisruptionBudgets (a PDB status controller computes disruptionsAllowed; 429 with a DisruptionBudget cause); expectedPods counts matching pods rather than the owner's scale, and there are no PDB conditions or `unhealthyPodEvictionPolicy`. Webhooks run sequentially; only `JSONPatch` patches are supported, `caBundle` is required (no system roots), and `matchPolicy: Equivalent` just ignores the rule's version (no conversion; one version per resource). matchConditions use a small CEL subset: `== != < <= > >= ! && || in +`, field/index access, `has()`, `size()`, string `startsWith/endsWith/contains`, literals and lists; any other expression is an evaluation error handled by `failurePolicy`. admissionregistration.k8s.io objects are never sent to webhooks.

# Accepted limitations (by design, or not planned for now)

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

## Echo server (cont.)
92. **Writes by in-process components are durable within ~1 s, not at acknowledgement** — *accepted* (ADR-024)
    Controllers and the server's kubelet call the API in-process. A crash can lose their last ~1 s of writes, which they then re-derive. Watch events are also delivered before the fsync.

# Resolved

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
58. **Constant-time behaviour is by construction, not yet measured** — *fixed* (commit: 290fc9d)
    `crates/kr-crypto/tests/timing.rs`: dudect-style Welch t-tests on fixed vs random secrets (run in release, `-- --ignored --nocapture --test-threads=1`). First run (x86_64, loaded machine): ct_eq |t|=0.4, x25519 1.4, Ed25519 sign 1.1, P-256 sign 1.9, ChaCha20-Poly1305 1.8, AES-128-GCM 2.1, all under the 4.5 threshold; a deliberately leaky compare scores ~11900, so the harness detects leaks. This is evidence, not proof: no leak at these sample sizes on this CPU. Re-run on new hardware and after crypto changes.
61. **No TLS 1.2 client** — *fixed* (commit: bb1ac93)
    Client-only and opt-in (`ClientConfig::tls12`, enabled for registry pulls; kr's own connections stay TLS 1.3). ECDHE (X25519, P-256) with ECDSA or RSA certificates, AES-128-GCM or ChaCha20-Poly1305, SHA-256 PRF. Extended Master Secret is required and the RFC 8446 downgrade sentinel is checked; no renegotiation, no resumption, no client certificates. Tested against `openssl s_server -tls1_2`. Not offered: SHA-384 suites (AES-256-GCM), CBC suites.

## Control plane (ADR-021)
64. **RBAC not implemented** — *fixed*
    - Roles, ClusterRoles and bindings are enforced.
    - Bootstrap policy: cluster-admin, admin/edit/view, system:discovery, public-info, basic-user, issuer discovery.
    - ServiceAccount tokens: ES256 JWTs via TokenRequest, optionally pod-bound; revoked when the SA or pod is deleted.
    - Bearer authentication; `kubectl auth can-i` works via SelfSubjectAccessReview.
    - Remaining: aggregated ClusterRoles (aggregationRule), bootstrap tokens for joining nodes, and the TokenReview/SubjectAccessReview APIs.
68. **Namespace deletion is synchronous** — *fixed* (kr-controllers `namespace`)
    DELETE now sets `Terminating`; the namespace controller empties it (built-in and CRD resources, honouring finalizers and graceful pod deletion) and finalizes it.
69. **No garbage collection by ownerReferences** — *fixed*
    `kr-controllers/src/gc.rs` deletes dependents whose owners are gone (background propagation) and honours orphan/foreground deletion.
98. **Concurrent pulls of one image destroyed each other's rootfs** — *fixed*
    Found in conformance round 4 (2026-10-25): most of ~320 failures were pods stuck `ContainerCreating: pulling image agnhost:2.66.1` for 40+ minutes. Pull keys include the credential identity (namespace/SA/secrets), so every e2e namespace started its own pull of the same image, and all of them unpacked into the same `<image>/rootfs.tmp`, removing each other's tree (`fchownat`/`mkdirat` ENOENT, `ENOTEMPTY`); each failure backed off 10 s and retried. Reproduced outside k8s: 20 concurrent `kr ctr pull` of agnhost took 792 s and 18 failed. Fix: each pull unpacks into `rootfs.tmp-<pid>-<start>-<nonce>` (first rename wins; leftovers of dead processes are removed), and the kubelet waits for an in-flight pull of the same image under another identity instead of starting another. After: 20 concurrent pulls, 3 s, 20 succeed.
99. **Protobuf DeleteOptions stamped with the resource's group; `:` in ClusterTrustBundle/IPAddress names** — *fixed*
    Conformance round 4: client-go stamps DeleteOptions with the deleted resource's group version (`apps/v1`, `apiextensions.k8s.io/v1`, `storage.k8s.io/v1`, `node.k8s.io/v1`), which kr answered 415 (~25 failures); any group's DeleteOptions now decodes as meta/v1 (`tests/proto_delete.rs`). ClusterTrustBundle (`<signer>:<name>`) and IPAddress (the IP, `:` in v6) names were checked as DNS subdomains (11 failures); they are path segments now (`tests/names.rs`). Not done: IPAddress names are not checked to be canonical IPs, CTB names not checked against `spec.signerName`.
100. **Deleted pods held by finalizers kept reporting `Running`** — *fixed*
    Conformance round 5: a pod with a client finalizer (`e2e.example.com/finalizer`) was stopped after its grace period, but the kubelet dropped it from its runtime map without a last status write, so the API object said `Running` forever and the namespace-deletion test hung for 40+ minutes. The kubelet now writes a terminal status first (`Succeeded` if every container exited 0, else `Failed`, not ready, terminated container states). Verified live: deleted with grace 2 s, `Failed` + `terminated` within seconds, removed when the finalizer is dropped.
101. **Downward API `divisor: "0"`, ClusterTrustBundle projection, CRD OpenAPI schemas** — *fixed*
    Conformance round 5 (~45 failures):
    - The API server defaults `resourceFieldRef.divisor` to `"0"`, which kr rejected (`unsupported resourceFieldRef`), failing every downward-API resource test, env and volume (28). Zero now means 1, as upstream.
    - Projected `clusterTrustBundle` sources were ignored (12): by `name`, or `signerName` + `labelSelector` (unset matches none, empty all), certificates deduplicated, `optional` honoured. Verified live (3 certificates in 2 bundles -> 2); a newline lost before `-----END CERTIFICATE-----` (9 failures in round 7) is fixed and unit-tested.
    - CRD schemas were not published (9 `crd_publish_openapi` failures): `/openapi/v2` now has a definition per served CRD version (`com.example.foo.v1.Kind`, with upstream's apiVersion/kind/metadata properties and GVK extension) and the v3 group documents carry the same as component schemas, plus ObjectMeta and its references (`openapi_meta.json`, generated by `tools/gen_openapi_meta.py` from upstream's swagger.json). `kubectl explain` on CRs, their metadata and nested fields matches the e2e patterns; unserved and deleted versions disappear (`tests/openapi.rs`). Not done: built-in kinds still have no schemas, no ETag on `/openapi/v2`, no protobuf form of it.
102. **ValidatingAdmissionPolicy / MutatingAdmissionPolicy were stored but not enforced** — *fixed*
    Conformance round 5: the policy tests looped for their whole timeout because nothing ever denied or mutated. Policies now run in the admission pass (`policy.rs`): mutating policies before mutating webhooks, validating policies before validating webhooks. Supported: bindings with `matchResources`, `matchConstraints` (resourceRules with resourceNames, excludeResourceRules, namespace/object selectors, matchPolicy), `matchConditions`, `variables`, `paramKind`/`paramRef` (name or selector, parameterNotFoundAction), `failurePolicy`, `validationActions` Deny/Warn (Audit is accepted and ignored), `message`/`messageExpression`/`reason`, `ApplyConfiguration` and `JSONPatch` mutations. CEL gained map literals and `Object{...}`/`JSONPatch{...}` construction. `status.typeChecking` is computed on write from the protobuf tables (built-ins) or the CRD schema, reporting operator-overload mismatches with cel-go's wording. Verified: `tests/admission_policy.rs` (mutation-checked) and live with kubectl. Not done: `authorizer` in expressions, audit annotations, `reinvocationPolicy: IfNeeded`, apply configurations merge like a strategic merge patch rather than structured-merge-diff, type checking beyond overloads (unknown fields, function signatures).
103. **A 1337-replica Deployment froze the API server** — *fixed*
    Conformance round 6: the MutatingAdmissionPolicy test sets `replicas: 1337`; the scheduler then listed every pod and node for every pending pod (quadratic), and since in-process API calls never suspend, that loop held the single-threaded executor: TLS handshakes timed out and the whole run stalled (found by attaching gdb to the spinning process and resolving PCs through a linker map of a byte-identical rebuild). Fix: controller work loops yield to the executor after each item (`exec::yield_now`), and the scheduler reuses a node/pod snapshot for up to 1 s, applying its own bindings to it. Verified live: with 1337 replicas `/healthz` answers in 0.7 s and listing 1337 pods takes 2.5 s while the scheduler binds ~10 pods/s up to the 110-pods-per-node limit. Remaining: other controllers still list whole collections per reconcile (fine at these sizes, not at 10k).

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
75. **Resource requests are not enforced** — *fixed*
    CPU requests become `cpu.weight` (upstream formula); memory requests become `memory.min` (Guaranteed) or `memory.low` (Burstable), skipped silently when the memory controller is not delegated; `status.qosClass` is computed as upstream. Every pod gets a cgroup `kr-pods/<uid>` (Guaranteed), `kr-pods/burstable/<uid>` or `kr-pods/besteffort/<uid>` with the summed container limits (memory/cpu/pids only when every container sets one; init containers count as their peak, `spec.overhead` is added), holding the sandbox in a `pause` leaf and the container cgroups below; it is removed with the pod. Memory-pressure eviction: every 10 s, if MemAvailable is below the threshold (default 100Mi, `KR_EVICTION_MEMORY_AVAILABLE` overrides), the node condition `MemoryPressure` is True, the node gets the `node.kubernetes.io/memory-pressure:NoSchedule` taint (removed when pressure clears; the scheduler already filters NoSchedule taints) and one pod is evicted per tick: BestEffort first, then Burstable/Guaranteed pods whose pod-cgroup `memory.current` exceeds their summed requests (largest excess first). Evicted pods get phase Failed, reason `Evicted`, and are not restarted; `system-*-critical` and static pods are never evicted. Verified live on two docker nodes (cgroup tree, Guaranteed `memory.max` 64Mi, BestEffort evicted and Guaranteed spared). Not done: soft thresholds, disk/pid eviction, pod priority ordering, minimum-reclaim, ephemeral containers added later count against the pod limit, and without a delegated cgroup there is no usage data (only BestEffort pods are evictable).
76. **Controllers are basic** — *fixed*
    Deployment (pause, progress deadline, minReadySeconds), StatefulSet, DaemonSet, Job (with pod failure backoff), CronJob, Endpoints/EndpointSlice and the namespace controller exist.
    Remaining gaps: no proportional scaling during a rollout, no adoption of orphan ReplicaSets, namespace deletion conditions are limited to `NamespaceContentRemaining`.
77. **Image pulls block the kubelet sync loop** — *fixed*
    Pulls run as background tasks; failures back off and are reported as `ImagePullBackOff`.
94. **Graceful pod deletion never completes** — *fixed*
    Found in conformance round 3: pods that got a `deletionTimestamp` before the kubelet ever admitted them (tests create + delete faster than the sync loop) stayed `Terminating` forever — `terminate()` returned early when the pod was not in the kubelet's runtime map, so the API object was never removed (49 marker pods stuck on one node for 45+ min; pods with client-set finalizers lingering is upstream-correct behaviour, a different case).
    Fix: the kubelet force-deletes (`gracePeriodSeconds=0`) terminating pods it has no runtime state for, matching upstream `kubelet.deletePod`. Verified live: three create+delete races all removed within one sync cycle.
    Not covered: apiserver-side eviction of pods on a dead node (upstream uses the taint manager; kr has no node-lifecycle controller yet).
95. **Sonobuoy aggregator gets `Unauthorized` from kr's apiserver** — *fixed*
    Found in conformance round 3: about an hour after pod start, every request from a pod's service account returned 401 (sonobuoy spammed `unable to list pods ... Unauthorized` every few seconds, the aggregator never discovered the e2e job pods, and sonobuoy never completed), so the run stayed `running` in the API even though the suite had finished and written its log — `conformance.sh wait` hangs on this.
    Cause: the kubelet's projected-volume refresh decided a mounted token was fresh by file mtime, and every 20 s republish rewrote the file — so an expired token was republished forever.
    Fix: `spec.rs` `stage_volume` reads the token's own `iat`/`exp` claims (`token_lifetime`) and renews at 80% of the real lifetime. Verified live: a pod with `expirationSeconds: 600` rotated its token exactly at 480 s, and the rotated token authenticated (403 on a forbidden list, not 401).

## Services, DNS, multi-node (phase 5, ADR-022)
81. **No Node authorizer** — *fixed* (ADR-023)
    Nodes read only the secrets/configmaps/PVCs of their own pods and write only their own Node, Lease and pods. Pods themselves remain readable cluster-wide (as upstream). Token requests are checked by service account, not by `boundObjectRef`.
82. **Bootstrap token never expires** — *fixed* (ADR-023)
    `kr token create --ttl 24h` mints expiring join tokens; the server's initial `node-token` stays permanent (k3s-style), so delete its Secret (`kube-system/bootstrap-token-<id>`) to retire it. Agents rotate their client and serving certificates at 2/3 of their lifetime and hot-swap them, with no restart. Remaining gaps: expired token Secrets are not garbage-collected, and the server's own certificates (apiserver, admin, kubelet-client; 1 year) are not rotated.
86. **Defaulting is a subset** — *fixed*
    Defaults cover core/apps/batch plus networking (NetworkPolicy), storage (StorageClass, CSIDriver), PV/PVC phase, Endpoints/EndpointSlice ports, PriorityClass, RBAC binding subjects, admissionregistration webhooks and ValidatingAdmissionPolicy, and flowcontrol. Remaining: rarely used legacy volume-source and alpha-field defaults.
89. **Agent join token visible in the process list** — *fixed* (commit: b37c07d)
    `kr agent --token VALUE` exposed the token in /proc/<pid>/cmdline. Use `--token-file` (must be mode 600) or `KR_TOKEN`; `--token` still works but warns.
90. **Pod sandbox holder costs ~0.6–0.9 MB PSS per pod** — *fixed* (commits: 8f76327, bfd9d3e)
    After setup the holder execveats kr (O_PATH|O_CLOEXEC fd of /proc/self/exe) as `kr pause` with an empty environment and all other fds closed: ~77 kB PSS per pod instead of ~700 kB. If the exec fails it silently falls back to the old in-process pause.
93. **Containers survive a killed kr as orphans** — *fixed* (with #75)
    On startup the kubelet kills every process left in the `kr-pods` cgroup tree (`cgroup.kill`, or SIGKILL per pid on older kernels), waits for it to empty and removes the cgroups, before pod sync. Containers started before pod cgroups existed, and rootless/undelegated setups (no cgroups), are not covered.

## kr-net
25. **No DNS: only IP literals, `/etc/hosts` and a built-in `localhost`** — *fixed*
    kr-net has a UDP/TCP stub resolver (`dns.rs`, `SystemResolver`: /etc/hosts then resolv.conf nameservers). IPv6 zone ids are still not parsed.
26. **TLS is not implemented; `https` URLs fail with `Error::TlsUnsupported`** — *fixed (ADR-020)*
    `kr-net::tls::TlsConnector` serves `https`, and image pulls use it. Trust anchors come from `KR_CA_BUNDLE` or the system bundle.
27. **Interim SHA-256 in `kr-net/src/sha256.rs`** — *fixed*
    It now re-exports `kr_crypto::sha2`.
30. **Keep-alive pool has no idle timeout** — *fixed* (13ba669)
    `Config::idle_timeout_ms` (default 90 s): idle connections older than that are dropped, never reused. Remaining: no proactive EOF/readability probe before reuse (a server-closed connection is still found on use, with the existing one retry for GET/HEAD) and no background eviction timer (expiry runs on pool take/put).
31. **Registry auth** — *fixed* (commits: 13ba669, 169b2e7)
    Basic and Bearer-with-credentials (`token`/`access_token`, `expires_in` honoured), docker `identitytoken` (refresh_token POST), `imagePullSecrets` (dockerconfigjson/dockercfg, pod and ServiceAccount), keys matched like the kubelet (repository path prefixes on `/` boundaries, `*.` one-label wildcards, docker.io aliases; most specific wins); `kr ctr pull` reads `$DOCKER_CONFIG/config.json` or `~/.docker/config.json`. Not supported: docker credential helpers (`credsStore`/`credHelpers`); the identitytoken path is untested against a real registry.

## Runtime (kr-rt)
1. **Pending task + Async forms an Rc cycle** — *fixed* (commit: 68940ad)
   The task owns the future, the future owns the `Async`, the `Async`'s I/O slot owns a waker, and the waker owns the task. A task that never completes is never freed.
   Plan: add `JoinHandle::abort()` to drop the future and break the cycle, and add a live-task counter for leak detection. Rule: every network wait must have a deadline.
   Fix: `JoinHandle::abort()` drops the future immediately, and the handle then resolves to `Err(Aborted)` (the output is now `Result<T, Aborted>`, and there is also `is_finished()`). `exec::live_tasks()` counts tasks until their `Task` is freed, and `kr sleep-test` asserts on it (`live_tasks_ok`). A task that never completes and has no deadline or abort is still a leak hazard by design.
2. **`sleep` can fire up to 1 ms early** — *fixed* (commit: 68940ad)
   The millisecond clock is truncated. Plan: round deadlines up, so a sleep never fires before it was asked to.
   Fix: deadlines are computed in ns (`now_ns`), `Sleep` completes only when `now_ns >= deadline`, and the wheel entry uses `ceil(deadline_ns / 1e6)`. `kr sleep-test` verifies every elapsed time is >= the requested one.
4. **Allocator never returns small blocks to the OS** — *fixed (e64a857)*
   RSS grows to peak usage and stays there. Fine for the agent, but it could matter for a long-running server. Fix: 64 KiB-aligned per-class chunks with live counts; an emptied non-current chunk is madvised (header page kept) and reused, with no re-mmap.
6. **Large allocations with alignment above 4096 are not honoured** — *fixed (e64a857)*
   They go through mmap, which only guarantees page alignment. Fix: over-allocate with mmap and munmap the head/tail so the pointer has the requested alignment.
10. **mem\* are byte-by-byte on non-x86_64, and memcmp/bcmp everywhere** — *fixed (e64a857)*
    Fix: word-at-a-time memcpy/memmove/memset (non-x86_64) and memcmp/bcmp, volatile stores keep them from becoming self-calls; exhaustive tests.

## kr-runtime store / unpack / pull
39. **Layer diff_ids are verified** — *fixed* (commit: 38ed253)
    The pull hashes each uncompressed layer tar while inflating and compares it with `rootfs.diff_ids[i]`, failing on mismatch. Still open: zstd layers (`+zstd`) are rejected with `Error::Image`. Pulled-image refs are never refreshed (a moved `:latest` is not re-fetched once present).

## kr-archive
21. **Hardlink/symlink targets and the symlink-traversal check** — *fixed* (commit: 38ed253)
    Every path (and hardlink target) resolves via `openat2(RESOLVE_IN_ROOT)` against the rootfs fd and entries are created with `*at` calls that never follow the final component; regression tests cover absolute/`..` symlinks, earlier-layer symlink parents, outside hardlinks and `..` paths.
24. **Decompression-bomb limits** — *fixed* (commit: 38ed253)
    `Limits` caps uncompressed bytes per layer and per image (8 GiB each, spent down across layers by the pull), entry count and path length; failure removes `rootfs.tmp`.

## kr-fmt
18. **14 clippy style lints in kr-fmt** — *fixed* (commit: )

## Echo server (cont.)
14. **The lingering close holds each connection for up to 1 s after the response** — *fixed* (commit: )
    Under heavy load this raises the number of concurrent connections. Plan: skip the drain when the request was fully read, and cap total lingering connections.
91. **Datastore fsync blocked the event loop; log never compacted** — *fixed* (ADR-024)
    Found in conformance run 3: kr sat in `D` state under write load and the log grew without bound. Writes now go through group commit, with fsync in a helper process, and the log is compacted periodically. Verified: no `D` states during a 300-write burst, and all acknowledged writes survive `kill -9`.

## kr-sys (cont.)
35. **`syscall0..6` lack `# Safety` docs (clippy `missing_safety_doc`)** — *fixed (e64a857)*

## Echo server (demo only)
12. **The 431 path closes with unread data, so the client may see a TCP RST** — *fixed* (commit: 68940ad)
    Plan: lingering close. Send the response, `shutdown(SHUT_WR)`, then drain the input for up to 1 s and close.
    Fix: `linger_close` runs after every response (not only the 431) using the new `kr_sys::shutdown`. Note that a request whose headers are complete is answered 200 even if a large body follows, and the lingering close drains that body without a reset.

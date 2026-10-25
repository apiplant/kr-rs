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
    Round 7 (2026-10-25, first complete run since the HA work): 460 specs in 43 min, **308 passed, 152 failed**, no hangs. Biggest groups: pod-level behaviour (subpath expansion, termination messages, hostAliases, preStop, init status, probes, LimitRange defaults, pod generation), workload controllers (rollover/proportional scaling, StatefulSet ordering, adoption, Job success policy, CronJob concurrency, preemption), webhooks (matchCondition validation, timeouts, CRD conversion), field validation (duplicates, invalid values), DNS from musl pods, hostPort, kubectl apply/describe/attach details, chunked lists, missing APIs (PodCertificateRequest, DeviceTaintRule, StorageVersionMigration, ImageVolume). The CTB failures are fixed since (2cc219a). Per-test list by area: `docs/CONFORMANCE_KNOWN_ISSUES.md`.
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
104. **Pod behaviour gaps (conformance round 7, 29 tests)** — *mostly fixed*
    Fixed: sidecar init containers (`restartPolicy: Always`: started, then treated as initialized; restarted on any exit; stopped after the app containers), which the lifecycle-hook tests use to relay hooks; termination messages (file bind-mounted at `terminationMessagePath`, writable by any user, `FallbackToLogsOnError` = last 80 lines / 2 KiB); `activeDeadlineSeconds` (also when updated: phase Failed, reason DeadlineExceeded); `pods/<name>[:port]/proxy` (sent from the transport on non-blocking sockets, one 30 s budget, host-local pod IPs refused); `subPathExpr` (expansion, absolute/`..`/backtick results fail the container); `hostAliases` and the node's /etc/hosts for hostNetwork pods; pod admission (`admit.rs`): sysctl name validation (422), RuntimeClass (403 when missing; overhead, nodeSelector and tolerations merged) and LimitRanger (container defaults, min/max/ratio); pod `generation` (order-insensitive spec comparison, graceful delete bumps it) and `observedGeneration` on status and conditions; real condition transition times; `PodInitializing` for init containers queued behind one that has not finished; gRPC probes (health v1 over h2c); image volumes (`volumes[].image`, read-only); exec websockets with the bare `channel.k8s.io` protocol. Verified with unit and in-process tests and live on throwaway two-node clusters (not yet by the e2e suite).
    Remaining: sidecars are not stopped when every app container of a Never/OnFailure pod finished; LimitRanger ignores Pod and PVC limit types; unsafe sysctls are not rejected; gRPC probes over TLS; services/proxy; pod proxy cannot reach pod IPs in rootless mode; the termination log fallback can include earlier restarts' output.
105. **Missing APIs, validation, webhook and CRD gaps (conformance round 7)** — *partly fixed*
    Fixed (in-process tests, not yet the e2e suite):
    - TokenReview and SubjectAccessReview / LocalSubjectAccessReview, using the same token verification (signature, expiry, audience, ServiceAccount/pod revocation) and authorizer as requests; both need RBAC `create` (`tests/reviews.rs`). Tokens carry a `jti`, reported as the credential id with pod and node extras.
    - Newly served: events.k8s.io/v1 Event, apiregistration.k8s.io/v1 APIService (stored only, no aggregation), PodCertificateRequest, DeviceTaintRule, StorageVersionMigration; CSR `spec.signerName` and events.k8s.io field selectors.
    - `kube-root-ca.crt` is recreated or reset after ConfigMap writes in live namespaces.
    - List chunking keeps the first page's resourceVersion, reports `remainingItemCount`, and expires continue tokens after 300 s with 410 and an inconsistent continue.
    - Table requests to review APIs get 406.
    - Immutable ConfigMaps/Secrets, data key validation, immutable PriorityClass `value`.
    - Status updates keep label and annotation changes.
    - Namespace deletion removes pods before anything else.
    - Webhook configurations with uncompilable matchConditions are rejected (422); webhook calls carry `?timeout=Ns` and report timeouts as upstream does.
    - Custom resources are defaulted on read; client-written CRD status conditions are kept.
    - `kubectl logs --timestamps` (times are approximate: the file mtime, or the read time when following).
    - Field validation messages: unknown and duplicate fields together; server-side apply's "field not declared in schema"; YAML duplicate keys.
    Remaining: CRD conversion webhooks (and patching a CR in a non-storage version); API aggregation; review APIs in discovery; protobuf tables and spec validation for the new kinds; per-line log timestamps; `kubectl attach` denial message; `kubectl describe service` panic; the Guestbook test.
106. **Workload controller gaps (conformance round 7)** — *mostly fixed*
    Fixed (unit tests; most also on a throwaway cluster, none yet by the e2e suite):
    - Job: `SuccessCriteriaMet`/`CompletionsReached` and `Complete` only after the other pods are gone; `successPolicy` (succeededIndexes, succeededCount); `backoffLimitPerIndex`, `maxFailedIndexes`, `status.failedIndexes`; `podFailurePolicy` (onExitCodes, onPodConditions; FailJob, Ignore, FailIndex, Count); work-queue Jobs keep running pods after the first success.
    - Adoption and release of orphans by Job, ReplicaSet, ReplicationController and Deployment; `ReplicaFailure` on quota denials.
    - StatefulSet scale-down halts on an unhealthy pod; kubelet host-port admission (`HostPortConflict`) so evicted StatefulSet pods are recreated; patch-added list items go first (the specs read `containers[0]`).
    - Garbage collection honours `propagationPolicy` Orphan and Foreground (finalizers on owners).
    - Scheduler: new pods start `Pending`, `Scheduled`/`FailedScheduling` events, the pod's required node affinity, extended resources, and preemption (lower priority first, `DisruptionTarget`, `nominatedNodeName`).
    - Priority admission (`spec.priority`, global default, built-in critical classes). The critical classes outside kube-system need a ResourceQuota that covers them, as upstream's default limitedResources. PriorityClass `value` and `preemptionPolicy` are immutable.
    - Exec probes and hooks get literal and label/annotation fieldRef env; DaemonSet ControllerRevisions carry `controller-revision-hash`.
    Remaining: the DisruptionTarget condition on surviving victims is unverified; Foreground deletion is unit-tested only; CronJob ReplaceConcurrent and concurrency not checked; DaemonSet rollback needs two nodes.
107. **Networking gaps (conformance round 7)** — *partly fixed*
    Fixed:
    - `kr server` and `kr agent` raise `RLIMIT_NOFILE` to the hard limit. At the default soft limit of 1024 `accept` failed with EMFILE once enough Services were listening, which is the likely cause of the `10.96.0.1 i/o timeout` / TLS handshake timeouts seen across the suite (not reproduced in the e2e run itself).
    - The service proxy indexes Endpoints and EndpointSlices, uses slices (falling back to Endpoints), yields while reconciling, and backs off when reconciling is slow.
    - The `kubernetes` Service gets an EndpointSlice.
    - The EndpointSlice mirroring controller.
    - `services/[scheme:]name[:port]/proxy`; proxy URLs are parsed by segment (namespaces named `proxy-*` broke it); `https` targets (certificate not verified, as upstream; the TLS client's insecure mode is an explicit separate constructor); HTML links rewritten through the proxy.
    Remaining: `spec.hostNetwork` is ignored by the kubelet (pods get their own netns and a pod IP); `status.hostIP` is hard-coded to 127.0.0.1; DNS behaviour for musl resolvers (parallel A/AAAA) is unreviewed.

# Accepted limitations (by design, or not planned for now)

# Resolved

## Control plane (ADR-021)
110. **CRD conversion webhooks** — *fixed*
    Webhook CRDs were never converted. Now:
    - **Writes:** POST/PUT/PATCH in any served version are stored in the storage version. The order is authorization, then (PATCH) the stored object converted to the request version, then admission webhooks in the request version, then a dry-run in the request version for errors and field validation, then conversion and the write at the storage version's URL; replies are converted back. Strategy None re-routes synchronously.
    - **Reads:** objects and lists are converted per stored version, one ConversionReview each, validated like upstream (uid, Success, count, apiVersion, kind, metadata unchanged, compared key-order-insensitively: Go webhooks re-serialize with sorted keys).
    - **Watches:** events are converted in the stream (one in-flight batch, non-blocking); a failure ends the watch with an ERROR event (500).
    - Verified: `tests/conversion.rs` (HTTPS webhook in-process: storage form, dry-run, legacy objects, watch, failure) and live with upstream's `agnhost crd-conversion-webhook` and the e2e CRD (create/get/list/patch/watch across v1 and v2, server dry-run, strict validation, namespace deletion).
    Remaining: objects written before this change keep their old stored version (no storage migration); server-side apply through a non-storage version is recorded as an Update; strategy None validates fields against the storage version's schema; a failed watch batch drops the rest of that chunk.
111. **kubectl describe panic and log filters** — *fixed*
    kubectl's `describe service` dereferenced EndpointSlice port names that kr omitted for unnamed ports (now always `name: ""`). `kubectl logs --since/--since-time` were ignored and `--timestamps` used the file's mtime; the kubelet now samples each log file's size every 500 ms, giving per-line times accurate to ~0.5 s for filters and timestamps. Not reproducible on a live cluster (left open): Update Demo, Guestbook and the attach-denial message all worked; their round-7 failures were likely load/connectivity. Noticed: `get -o wide` lacks wide columns; fresh pods show no events in `describe`.

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

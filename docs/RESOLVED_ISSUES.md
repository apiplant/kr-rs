# Resolved

## Control plane (ADR-021)
107. **Networking gaps (conformance round 7)** — *fixed*
    Fixed:
    - `kr server` and `kr agent` raise `RLIMIT_NOFILE` to the hard limit. At the default soft limit of 1024 `accept` failed with EMFILE once enough Services were listening, which is the likely cause of the `10.96.0.1 i/o timeout` / TLS handshake timeouts seen across the suite (not reproduced in the e2e run itself).
    - The service proxy indexes Endpoints and EndpointSlices, uses slices (falling back to Endpoints), yields while reconciling, and backs off when reconciling is slow.
    - The `kubernetes` Service gets an EndpointSlice.
    - The EndpointSlice mirroring controller.
    - `services/[scheme:]name[:port]/proxy`; proxy URLs are parsed by segment (namespaces named `proxy-*` broke it); `https` targets (certificate not verified, as upstream; the TLS client's insecure mode is an explicit separate constructor); HTML links rewritten through the proxy.
    - hostNetwork pods and `status.hostIP`: fixed in #108.
    - DNS for musl clients, checked live with upstream's probe commands (`dig +search` over UDP and TCP, `getent hosts`, PTR) from the Alpine-based agnhost image: services, headless services, `hostname.subdomain` records, pod A records and PTR all resolve, with NODATA (not NXDOMAIN) for AAAA of existing names. Fixed: ExternalName answers now include the records of in-cluster targets after the CNAME, as CoreDNS does (musl does not re-query a CNAME; chains followed up to 8 hops, loops end); `/etc/hosts` lists `<hostname>.<subdomain>.<ns>.svc.cluster.local` for pods with a subdomain, as upstream's kubelet (`hostname -f`, getent).
    Remaining: ExternalName targets outside the cluster are returned as a bare CNAME (CoreDNS also resolves those upstream); the cluster domain is fixed to `cluster.local`.

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

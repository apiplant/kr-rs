# Known Issues & Potential Problems

Only work still to do lives here. Numbers are stable (other docs cite them); new items get the next free number (next: **360**). When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit. When items are merged, the surviving item lists the absorbed numbers in its title so a search for either finds it.

Goal order: **(A) parity with k3s** (needed to call kr production ready) → **(B) verification** of code that exists but has not run on real systems → **(C) performance** beyond k3s → *Nice to have* (beyond k3s) → *Accepted limitations* (nothing to do unless a trigger happens).

# A. Parity with k3s (blocks "production ready")
Ordered by impact. Size: S days, M a week or two, L more.

Nothing left: every parity item is closed (RESOLVED 342-345).

358. **Garbage collection of custom resources** — *S*
    The collector (`kr-controllers/src/gc.rs`) lists a fixed set of built-in dependent kinds (`DEPENDENTS`) and resolves owners only among built-in resources, so a custom resource is never collected and a reference to a custom-resource owner counts as alive (its dependents stay after the owner is deleted). Upstream collects every resource, including CRs, through discovery. Operators that set a CR as owner of their ConfigMaps, Secrets or Deployments rely on it. Fix: walk the served CRDs (and the remaining built-ins) as dependents and owners, with a watch-driven graph instead of listing every kind each sweep once that gets expensive.

# B. Verification backlog (code exists, not run on real systems)
Each is a test run, not new code, unless the run finds a bug. Left: what needs hardware, credentials or a host decision.

- **#131 SELinux**: AppArmor ran on an Ubuntu 24.04 VM (`tools/test/apparmor-vm.sh`, RESOLVED 357). SELinux is still unrun: on Fedora/RHEL (enforcing, container-selinux), a pod with `seLinuxOptions.level` (`ps -Z`, `ls -Z` of the rootfs and `/dev/shm`) and the `context=` mounts.
- **#320 S3 against AWS itself**: the S3 client ran against MinIO (HTTP and HTTPS, `tools/test/snapshot-s3.sh`; multipart with `KR_S3_TEST_*`, `crates/kr-net/tests/s3.rs`) and its signatures match AWS's published SigV4 examples, but never against AWS S3: virtual-hosted addressing (`<bucket>.s3.<region>.amazonaws.com`), `--snapshot-s3-session-token` (STS) and a bucket in a region other than the one in `--snapshot-s3-region` (AWS answers 301/400, which is reported, not followed) are untested. Other providers (R2, Ceph, Backblaze) likewise.
- **GPU, what an RTX 4090 cannot show** (#160, #167): time-slicing, MPS, CDI hooks, restarts and PodResources ran (`tools/test/gpu.sh`, RESOLVED 356). Left: MIG (`mixed`/`single`, `/dev/nvidia-caps/*`; needs an A100/H100-class GPU) and a real unhealthy GPU (XID) evicting its pods within ~10 s (#167; only a fake device plugin did).

# C. Performance (beyond k3s)
126. **Single-threaded control plane: one core** — *ADR-004, ADR-005, ADR-050*, L
    API server, kubelet, controllers, scheduler, userspace proxy and DNS share one executor thread (plus the fsync helper and offload workers). Measured (`kr-apiserver/tests/throughput.rs`, release, 2000 pods): GET 51,000/s, create 16,000/s, status merge-patch 10,000/s, delete 40,000/s, list of 2000 pods 3,200/s, labelSelector list 270/s (3.7 ms). Over the network TLS records and HTTP parsing bring a warm request to ~0.5 ms, roughly 2,000 requests/s per core. Fine for a server plus tens of nodes (stall watchdog and `/metrics` show when not), not for large clusters where k3s spreads over all cores. Next step if needed: front-end worker processes that terminate TLS and parse HTTP and pass requests over socketpairs, forwarding the identity (not threads: state is `Rc`/`RefCell`). Needs streaming (watch, logs, exec, upgrades) designed first.
208. **Remaining CPU and disk work on the event loop** (+209, +210, +212, +213, +215) — *ADR-050, ADR-052*, M
    The offload facility (RESOLVED 237, 238) covers big list renderings, audit bodies and image unpack/verify/fsync. Still inline:
    - #209 full TLS handshakes (resumption covers restarts: RESOLVED 234): a worker would need the private key and session state — design question. Also the variable-base multiplications (P-256 ECDH, `u2 * Q`).
    - #210 selection scan of `labelSelector`/`fieldSelector` lists on kinds other than pods (pods are indexed by node and by label: RESOLVED 350), splice of plain lists, copying to/from workers (~3 ms per 4 MB). The parsed-object cache holds up to 24 MB of JSON (3–4x in memory); a list of hundreds of thousands of objects is one allocation.
    - #212 store digest/`plain_image`, `kr snapshot` and Raft snapshot creation, Raft segment checksums, the AEAD per Secret write (token checks: RESOLVED 350; a token never seen before still costs one P-256 verification). Plan: copy-on-write fork for snapshot images (as Redis; see #295), batched AEAD for re-encryption.
    - #215 rootless infra file and CNI/IPAM/state files written with fsync inline; single start-up sweep steps (one cgroup walk, one pod dir removal) are synchronous.
    - Limits of the facility: 2 workers per class, the 17th concurrent caller runs inline, workers are copy-on-write forks taken at start-up.
    #213 (Raft sharing the loop) is the sum of these: watchdog, heartbeat priority and election timeout are in (RESOLVED 213a, 248).

# Nice to have later (beyond k3s)
Ideas that build on what kr already has and that k3s does not offer. None is planned; do these after A–C. "Not checked" means k3s is believed to lack it but this was not verified. 

291. **Seccomp profile recorder** — *M, not checked against k3s*
    Run a pod with a log-only filter (`SECCOMP_RET_LOG`, ADR-055), collect the syscalls (audit log or a `seccomp_unotify` listener) and write a `Localhost` profile. Reuses `kr_runtime::seccomp`, `spec::seccomp_dir`. Needs `kr seccomp record <pod>` and an annotation `kr.io/seccomp-record`.
292. **FQDN egress policy** — *M, not checked against k3s*
    Egress to `*.example.com` via a NetworkPolicy extension: the built-in DNS feeds answers into nft sets (RESOLVED 278) with the answer TTL. Needs an annotation or small CRD, DNS→netpol plumbing, element expiry. Risk: clients that bypass cluster DNS.
293. **Image signature verification at pull** — *M, not checked against k3s*
    cosign (ECDSA P-256 over the manifest digest; keyless out of scope) with an `image-policy.yaml` (pattern, keys, `enforce`/`warn`). Needs `.sig` fetch, a matcher, a pod event on refusal.
294. **Point-in-time object history and restore** — *M*
    `kr history` over retained revisions and `kr restore --revision N`. Needs a retention knob for selected resources and a diff in `kr-fmt`.
297. **Hot reload of audit policy and PodSecurity configuration** — *S*
    Watch the files, validate, swap atomically; keep the old policy on failure.
298. **`kr why <pod>`** — *S*
    One diagnosis from scheduler reasons, pod status and events.
299. **Upgrade planner: stored objects and removed APIs** — *S*
    `kr upgrade plan` lists stored objects and CRDs the target release no longer serves.
300. **PSI-based node pressure** — *S*
    `/proc/pressure/*` in the eviction loop and node conditions.
301. **Ephemeral-storage limits through project quotas** — *M*
    Per-pod/per-upper-layer project quota at creation (root, `prjquota`), refuse writes at the limit; fall back otherwise. Needs `FS_IOC_FSSETXATTR` in kr-sys.
302. **Built-in GPU status and sharing without the operator** — *M*
    `kr gpu`, sysfs-based node labels, time-slicing as a kubelet setting. Needs hardware (#160).
303. **Server upgrade without dropping client connections** — *L*
    Needs the worker split of #126 and a socket-handoff protocol.
311. **KMS provider or envelope keys for secrets encryption** — *L* (parity closed, RESOLVED 285)
    Unix-socket plugin as KMS v2 or a passphrase/TPM-wrapped key; refuse to start when the provider is down.
312. **Snapshot controller and CRDs bundled, off by default** — *M* (RESOLVED 283)
    Needs a test with a real driver (#136, #137).
313. **Kubelet serving certificates through CSRs, and ClusterTrustBundles** — *M* (RESOLVED 284)
    `serverTLSBootstrap` via the CSR flow (RESOLVED 273), renewal without restart, approver rule for `kubernetes.io/kubelet-serving`.
314. **Keep decrypted values out of memory dumps** — *M* (RESOLVED 286)
    Keep Secret values encrypted in the store map and decrypt on use; `MADV_DONTDUMP`. Benchmark the read path first.
315. **Restart containers when the GPU driver changes** — *S* (RESOLVED 287)
    Hash of resolved CDI edits, 30 s re-check, `DriverChanged` event, opt-in `kr.io/restart-on-driver-change`.
316. **Built-in custom-metrics adapter for HPA** — *L* (RESOLVED 290)
    A small `custom.metrics.k8s.io` backed by kr's own metrics; not a replacement for prometheus-adapter.
317. **Certificate and SA-key rotation without a restart** — *M* (RESOLVED 288)
    Reload API and Raft TLS configs and the SA verification keys on a signal or file change.
295. **Snapshot without a stall (copy-on-write fork)** — *M*
    `kr snapshot`, scheduled backups and Raft snapshot creation hash and copy the store on the event loop (#178, #212). A forked child holds a consistent copy-on-write image and writes the archive while the parent keeps serving, as Redis does. Needs a fork helper safe in the single-threaded `no_std` process (the offload facility already forks workers) and care with disk write bandwidth.
296. **Online secrets re-encryption in background batches** — *S* (remaining part; the reload and online re-encrypt are RESOLVED 309, 311)
    Re-encrypt in small batches through the offload workers with progress in `kr secrets-encrypt status`. The HA replication is #189.

# Accepted limitations (by design, or not planned for now)
Nothing to do unless the stated trigger happens.

127. **Durability limits of in-process writers and watches** — *ADR-024*
    Writes by the controllers and the server's own kubelet are flushed every second (a crash can lose ~1 s of them; they re-derive state). Watch events are delivered when written, not when durable. Revisit if a controller keeps state that cannot be re-derived.
130b. **Rootless images stay flattened** — *ADR-017, ADR-056*
    Rootless stores unpack one rootfs per image (whiteouts and `trusted.` xattrs), so shared layers are duplicated; images pulled before the layered store stay flattened until pulled again.
131b. **Default seccomp filter is a deny-list** — *ADR-055*
    Stricter than upstream's unconfined default, looser than containerd's `RuntimeDefault` allow-list: an allow-list would break workloads that run unconfined upstream.
132. **Pod and Service CIDRs: IPv4 /16 only, set before the first start** — *ADR-053*
    Any `A.B.0.0/16` (RESOLVED 261): at most 256 nodes and 254 pods per node; IPv6 networks fixed; agents must use the server's values (unchecked); changing them on a live cluster is unsupported (as in k3s).
143. **API priority and fairness: width of mutating requests** — *ADR-033*
    One seat per mutating request (upstream adds seats for the write phase and watcher fan-out). Borrowing never revokes a lender's seats (as upstream). Metrics on `/metrics` (RESOLVED 265).
144. **Pod network families: changes and IPv6-only hosts** — *ADR-032, ADR-034*
    Changing `KR_POD_FAMILIES` needs every agent restarted and loses existing pods (as in k3s); IPv6-only pods need host IPv6 for NAT66; host-gw routes IPv6 pod subnets only on an IPv6 underlay.
151. **No bundled Ingress controller** — *ADR-045*
    k3s ships Traefik; kr does not by design: install one as a workload. The Helm controller now exists (RESOLVED 331), so an optional packaged chart is cheap: revisit if asked for.
167. **Unhealthy-device eviction deletes bare pods** — *ADR-038*
    Goes beyond upstream (which only lowers allocatable); chosen by the user. After `KR_DEVICE_UNHEALTHY_GRACE` (30 s) the eviction API removes the pod, a PDB can hold it for `KR_DEVICE_UNHEALTHY_PDB_WAIT` (600 s, RESOLVED 252). Bare pods are gone. Live run in section B.
174b. **ServiceLB corners shared with k3s** — *ADR-042*
    Addresses are served only on the node that owns them; `externalTrafficPolicy: Local` publishes only nodes with a ready endpoint but other nodes still forward the NodePort; source ranges apply to load-balancer addresses only, never to node-local clients.
176. **Air-gap import needs staging space** — *ADR-044*
    Archives are extracted to `<store>/import.tmp-*` first (free disk of one archive size); partial-platform multi-image archives import the rest with a warning; import repoints refs without replacing an image by id; zstd dictionaries and the optional content checksum are not used (layers are verified by digest).
178. **Backup is a point-in-time copy of one server's files, with caveats** — *ADR-043, ADR-024, ADR-026*
    Read on the event loop when scheduled (a very large store stalls it, #208). In HA `--committed-only` can lag (commit index persisted only on term/vote change); by default a follower's archive may hold a few uncommitted entries. Archives are uncompressed and unencrypted (hold `ca.key`, `sa.key`, tokens; mode 0600). Restore yields a single-server data dir; agents must reach the new server at the old address. The `kr` crate has no unit tests (`tools/test/tooling.sh` covers `snapshot.rs`, `rotate.rs`, `manifests.rs`).
192. **Nonce limit and no automatic rotation** — *ADR-047*
    Random 96-bit nonces: 2^32 encryptions per key. No counter warns when it is approached.
195. **`kr snapshot` of an encrypted store keeps ciphertext; store digests ignore encryption** — *info*
    `Store::from_files` loads without a codec; `ApiServer::store_digest` hashes `Store::plain_image()`. Tools reading values must install the codec.
196. **HPA history is stored in `status.krHistory`** — *ADR-048*
    Upstream keeps the stabilization history in memory; kr stores it so it survives restarts (visible in `-o yaml`, copied with the object). Custom/external metrics need an adapter, as in k3s (RESOLVED 290).
197. **Pod metrics need a delegated cgroup and only cover running containers** — *ADR-048, ADR-007*
    Without a delegated cgroup `kubectl top pod` is empty. Terminated, pause and finished init containers are not reported; no fs, network or rlimit stats in `/stats/summary`; `usageNanoCores` is 0 there.
198. **Metrics API: sampling limits** — *ADR-048*
    Values after the second scrape (~20 s); sequential node scrapes with 10 s timeout; each HA server scrapes on its own; entries vanish after 2 minutes; no `APIService` object, `watch`, `Table` or OpenAPI for it.
201b. **NetworkPolicy and the node** — *ADR-049*
    `hostNetwork` pods are not selectable as peers and node→pod traffic is never filtered (the documentation leaves both to the plugin). kr, like kube-router, also applies egress policy to a pod's traffic to the node's own addresses.
202. **Policy tables are replaced as a whole** — *ADR-049*
    Rebuilt atomically on pod/policy changes (at most every 500 ms); no incremental set updates; ipBlock and small peer groups stay plain rules; the IPv6 set path is unit tested only. Revisit if churn shows in the stall report.
204. **Built-in enforcement details** — *ADR-049*
    SCTP matched by protocol/port only; non-first fragments match no port rule; no logging or `status` (upstream v1 has neither). The bridge table needs `nf_tables_bridge` (otherwise same-node pod-to-pod is open; logged). Switching `KR_NETWORK_POLICY` or CNI needs a kubelet restart.
207. **Node authorizer list/watch scoping** — *ADR-023*
    Matches upstream's `system:node` grants: `volumeattachments` list/watch only for its own node, `persistentvolumes` single gets only; `csidrivers`, `csinodes` and CSR reads open; a node may create CSRs of any signer (kr auto-approves only kubelet signers for the requesting node).
220. **TLS resumption: what ADR-051 leaves out** — *ADR-051*
    No TLS 1.2 resumption (client side, opt-in); agents and servers with different `sa.key` use per-process ticket keys; no 0-RTT; a client certificate whose CA was replaced keeps resumed sessions up to an hour; clocks more than an hour apart cannot share tickets. `KR_TLS_RESUMPTION=off` disables it.
223. **A `write()` to a log file can block the event loop** — *ADR-050, #208*
    Not seen again in the stall log. Still inline: store log append, compaction (`rewrite_log`: 21 ms for a 9.2 MB image on NVMe, mostly four fsyncs), pod log files. Hand the fsyncs to the helper if a compaction shows in the stall report.
226. **Start-up latency after a restart (up to ~190 ms, no event-loop stall in the last run)** — *ADR-050, #208*
    First `report_status` after a restart ~150 ms (wall time across awaits; the patch itself is 70–100 us, `tests/patch_timing.rs`), `sync_pod` 77–129 ms for GPU-operator pods, `refresh_volumes` 43 ms. Aggregated `projectcalico.org/v3` requests: 50–86 ms steady, 320–380 ms for the first after a restart (cold connection to the extension server; the rest is Calico's API server). A 116 ms NFD stall did not recur; the connection-loop labels (`http: handled`/`send response`/`next request`) will place it if it does.
227. **Starting a container forks the kubelet twice (~8 ms of the loop)** — *ADR-050*
    Below the stall threshold and never named by a stall report; the fix (fork-server helper or `kr shim` with the spec on a pipe) rewrites the container-start path. Revisit only if a stall report names a container start.
53. **Binary size** — *watch*
    4.93 MB on x86_64 after RSA client keys (#175, ADR-063) and snapshots to S3 (#320, ADR-064): master was 4.86 MB (measured) before the two, so about +61 KB together. 4.75 MB on x86_64 after the WireGuard backend (#319, ADR-062; about 5 KB of it is the backend itself, the rest other work merged since); 4.54 MB on x86_64 (2026-11-13; 3.10 MB on 2026-11-01, 2.87 MB on 2026-10-27); the 2 MB agent budget in PLAN.md is exceeded. Measure before adding large features; avoid `{:?}` on large types; keep `opt-level = "z"` + LTO + strip.
60. **TLS handshake cost** (+125) — *watch*
    P-256 is a constant-time fixed 4-bit window: ~0.5 ms sign, ~0.95 ms verify. A full kr TLS 1.3 handshake is ~2.3 ms vs k3s ~1.6 ms (crypto tuned for size); warm requests are faster (0.5 vs 1.1 ms), and resumption (ADR-051) makes reconnect storms cheap. Revisit if the full-handshake rate matters (#208).
97. **HA (kr-raft, ADR-026) design limits**
    One-server-at-a-time membership changes; a server whose IP changes needs a restart. Linearizable reads use a leader lease (bounded clock drift); reads with an explicit `resourceVersion` and watches are served locally. Snapshots are one message (512 MB frame limit; chunked InstallSnapshot if images grow).
115. **Leftovers of resolved items (not planned)**
    - CRD conversion: objects keep their stored version until a `StorageVersionMigration`; SSA through a non-storage version of a webhook-converted CRD is recorded as an Update.
    - Rootless: the host cannot reach pod IPs directly (use port-forward or the pod proxy).
    - Memory: with 4 KB pods the 32 MiB history keeps ~4,000 events (watch the `410 Expired` rate); no per-category breakdown of per-pod growth (~120 KB at 100 pods).
123. **File bind-mounts of a deleted inode fail (`errno 2`)** — *kernel limit*
    Plain `mount --bind` fails the same way (confirmed 2026-11-11). Restart the container to recreate the mount.

# Operational notes (not issues)
Kept here until there is an operations guide.

**CSI with Longhorn (ADR-041).** Verified on a root kubelet: provisioning, attach, Stage/Publish, data surviving detach/reattach, deletion. CSI needs a root kubelet. The state dir is `/var/lib/kubelet` (`KR_KUBELET_DIR`) and must differ from `cfg.root`. Longhorn detects the kubelet root from a process named `kubelet` or `k3s server`: install with `--set csi.kubeletRootDir=/var/lib/kubelet`. Longhorn disks need FIEMAP (ext4/XFS, not tmpfs); for tests: `truncate -s 4G /tmp/lh.img && mkfs.ext4 -q -F /tmp/lh.img && sudo mount -o loop /tmp/lh.img /tmp/lh-disk`.

**Pods keep the mount setup of the binary that started them.** Containers survive a kubelet restart (ADR-036), so after an upgrade that changes mounts (e.g. `mountPropagation`) recreate affected pods (Longhorn: instance-manager, csi-plugin, manager).

**Calico with an external-CNI server start** (verified 2026-11-12): start with `KR_CNI_CONF_DIR=/etc/cni/net.d KR_CNI_BIN_DIR=/opt/cni/bin` (both must exist; without a CNI config kr keeps its bridge). Install the CRDs first (`helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -`), then `helm install calico projectcalico/tigera-operator -f values.yaml` (pool `10.244.0.0/16`, VXLAN, BGP off; keep off `10.88.0.0/16`). All Calico components Ready; pod-to-pod, DNS, egress, 30 replicas in 18 s, 780 Service requests without failure; NetworkPolicy blocks direct pod-IP traffic (through ClusterIP too, with `KR_PROXY=nft`: RESOLVED 344, `KR_TEST_CNI=calico tools/test/nft-cluster.sh`). Pods from before the switch keep their `10.88.0.x` addresses and reach Calico pods through the host.

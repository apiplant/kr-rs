# Known Issues & Potential Problems

Only work still to do lives here (open items, things to watch, accepted limits). Numbers are stable (other docs cite them); new items get the next number. When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit.

## Open
118. **`kubectl exec` processes get the default capability set**
    `securityContext.capabilities` add/drop are applied to containers (2026-11-12), but exec'd processes still start with the default set. Privileged pods keep all capabilities and skip seccomp/no_new_privs, and kr runs rootful by default, so mknod/ipset/Calico work. `securityContext.capabilities` `add` / `drop` (with `ALL`) are honoured for non-privileged containers, but `kubectl exec` processes still get the default set, and device-node creation is still blocked in rootless (`KR_USERNS=1`) mode.

126. **Single-threaded control plane** — *ADR-004, ADR-005*
    The API server, kubelet, controllers, scheduler, Service proxy and DNS share one executor thread (plus the fsync helper process, ADR-024), and the allocator is single-threaded. On a many-core server one core limits throughput and tail latency under load, where k3s spreads over all cores. Needs per-thread slabs or a lock in `kr-rt`, or sharding by process, before large clusters.
127. **Durability limits of in-process writers and watches** — *ADR-024*
    Writes by the controllers and the server's own kubelet are not awaited for durability: a background task flushes them every second, so a crash can lose up to about one second of them (they re-derive their state from the API). Watch events are delivered when written, not when durable, a deliberate deviation from etcd. Revisit if a controller ever keeps state that cannot be re-derived.
128. **No audit log** — *ADR-029*
    The API server writes no audit log (no `--audit-policy`/`--audit-log-path` equivalent), so the Pod Security `audit` mode is accepted and does nothing and there is no record of who changed what. Most compliance regimes require one.
129. **Pod Security admission: no exemptions, `-version` labels ignored** — *ADR-029*
    `pod-security.kubernetes.io/<mode>-version` labels are accepted and ignored (always `latest`), and there is no exemption configuration (users, runtime classes, namespaces).
130. **Flattened per-image rootfs duplicates shared layers** — *ADR-017*
    Each image is unpacked into its own directory, so images that share base layers do not share disk, and a pull of a similar image unpacks everything again. Layer-level lowerdirs (or a content-addressed layer store) are possible now that the runtime is rootful by default; rootless still needs the flattening for whiteouts and xattrs.
131. **seccomp is a deny-list; no AppArmor or SELinux** — *ADR-018*
    The default seccomp filter denies a list of dangerous syscalls instead of allowing a known set (Docker's/containerd's `RuntimeDefault` is an allow-list). `securityContext.seccompProfile` `Localhost` profiles, `appArmorProfile` and `seLinuxOptions` are not applied.
132. **Pod and Service CIDRs are fixed** — *ADR-019, ADR-022, ADR-025*
    The pod network is `10.88.0.0/16` (a /24 per node, so at most 256 nodes and 254 pods per node), Services are `10.96.0.0/16` and `fd00:96::/112`, pods' IPv6 is `fd00:88::/32`. None is configurable (k3s has `--cluster-cidr` and `--service-cidr`), so a site that already uses these ranges cannot install kr.
133. **Service proxy runs in userspace inside the kubelet** — *ADR-022, ADR-036*
    ClusterIP and NodePort traffic is spliced by kr itself: lower throughput and higher latency than kube-proxy's kernel datapath, and every Service connection is dropped when the kubelet process restarts (pods survive, ADR-036, their Service connections do not). `externalTrafficPolicy: Local` and client source IP preservation depend on the splice. An nftables DNAT datapath behind the same reconcile loop was the plan.
134. **A kubelet restart ends exec and attach sessions** — *ADR-036*
    Containers, terminals and `attach -i` stdin survive a kubelet restart, but a running `kubectl exec`/`attach`/`port-forward` session ends with the old process. Each running container also keeps a ~1 MB shim process (200 pods ≈ 250 MB).
135. **CSI: no `volumesInUse` accounting** — *ADR-041*
    The kubelet does not report `status.volumesInUse`/`volumesAttached`, and the attach/detach controller decides from pods alone. A volume can be detached while the node still has it mounted (for example while a pod is terminating), which can corrupt data for drivers that do not refuse it.
136. **CSI: no `NodeExpandVolume`, no volume stats** — *ADR-041*
    Growing a PVC does not grow the filesystem on the node (`NodeExpandVolume` is not called), and the kubelet does not call `NodeGetVolumeStats`, so `kubelet_volume_stats_*` metrics and capacity alerts are missing.
137. **CSI: block volumes, inline ephemeral volumes, per-driver volume limits** — *ADR-041*
    `volumeMode: Block`, inline `csi:` ephemeral volumes and generic ephemeral volumes backed by CSI are not supported; the scheduler ignores per-driver attach limits (`CSINode` allocatable counts); only the first PV access mode is sent to the driver.
138. **Device plugins: no `GetPreferredAllocation`, no topology hints** — *ADR-038*
    The first free healthy devices are handed out, so multi-GPU pods can get poorly connected GPUs (NVLink/PCIe topology) and NUMA alignment is not considered.
139. **Device plugins: a device turning unhealthy does not fail or evict its pod** — *ADR-038*
    Allocatable drops to zero for the resource, but pods already running on the unhealthy device keep running.
140. **No `PodResources` API** — *ADR-038*
    The kubelet does not serve `/var/lib/kubelet/pod-resources/kubelet.sock`. Tools that map devices to pods (the dcgm-exporter, monitoring agents, NUMA-aware schedulers) cannot attribute GPUs to pods.
141. **Device plugins: one `Allocate` per container and resource, connection not reused** — *ADR-038*
    `Allocate` is called once per container and resource (upstream batches containers of a pod), and the plugin connection is opened per call. Works, but costs extra round trips on pod start.
142. **OCI hooks are not run for exec'd processes; the NVIDIA runtime class is detected in the kubelet** — *ADR-039*
    CDI `startContainer`-style setup for `kubectl exec` processes is not repeated (they inherit the container's already-modified root). `NVIDIA_VISIBLE_DEVICES` under a RuntimeClass whose handler is `nvidia*` is turned into CDI device names by the kubelet, as `nvidia-container-runtime` does in CDI mode; other runtime handlers are ignored (kr has one runtime, so `overhead` and `scheduling` come only from admission).
143. **API priority and fairness: no work estimation, no borrowing** — *ADR-033*
    Every request takes one seat whatever its size (a large LIST costs the same as a GET), priority levels cannot borrow unused seats (`lendablePercent`/`borrowingLimitPercent` are stored only), and the total is a fixed 600 seats.
144. **Pod network families: changes and IPv6-only hosts** — *ADR-032, ADR-034*
    Changing `KR_POD_FAMILIES` needs every agent restarted (and pods from before are lost), IPv6-only pods need host IPv6 (bridge setup fails otherwise), the host-gw backend routes IPv6 pod subnets only on an IPv6 underlay and leaves stale routes until restart, and the registry mirror, image pulls and DNS upstreams use whatever the host resolver offers.
145. **Node lifecycle: no eviction rate limiting or zone awareness** — *ADR-037*
    Pods of an `Unknown` node are deleted once their toleration ends, with no rate limit and no unhealthy-zone logic (`--node-eviction-rate`, `--unhealthy-zone-threshold`). If the control plane loses sight of many nodes at once (a partition), their pods are all evicted together.
146. **Server-side apply merges with strategic-merge code, not structured-merge-diff** — *ADR-021, ADR-028*
    Field ownership for apply configurations and `kubectl apply --server-side` follows the strategic-merge tables; results agree for maps and keyed lists but differ for atomic structs and sets (`x-kubernetes-list-type`/`map-type: atomic`/`set`), which can show up as spurious conflicts with Helm, Argo CD or Flux using SSA.
147. **No CSR approver or signer** — *ADR-023*
    `CertificateSigningRequest` objects are stored, but nothing approves or signs them (kr issues node and server certificates itself, ADR-023). Software that expects `kubernetes.io/kube-apiserver-client` or `kubelet-serving` CSRs to be signed (cert-manager's `Kubernetes` issuer, kubeadm-style tooling, some operators) does not get a certificate.
148. **Registry mirrors: no authentication, no config file** — *ADR-027*
    `KR_REGISTRY_MIRRORS` is an environment variable only, mirrors are contacted anonymously, and credentials are never sent to them. There is no per-registry TLS/CA/client-certificate configuration (k3s `registries.yaml`), so a private mirror that needs auth or a private CA cannot be used.

165. **`NetworkPolicy` is bypassed through Service ClusterIPs** — *ADR-022* — **security, to fix**
    The userspace Service proxy terminates the client connection and opens a new one to the backend from the host, so the backend (and Calico) sees the node as the source, which policy engines allow by default. A policy that admits only `client` still lets any pod in through `web.ns.svc` (verified with Calico 3.33, 2026-11-12: `other` reached `web` through the Service while the same request to the pod IP timed out). Kubernetes (kube-proxy DNAT) keeps the client pod's source IP, so policy applies there; this is a real difference, not just a limit, and policy specs that go through Services will fail. Plan: connect to the backend from the client's own address (`IP_TRANSPARENT`/`IP_FREEBIND` bind plus the local route and return path through kr), keeping the userspace design; alternative: nftables DNAT, which needs the NAT modules on the host. Tests: a policy test that allows one pod and checks both the pod IP and the Service IP.

### Missing compared with k3s
149. **No metrics API (`metrics.k8s.io`)** — *missing compared with k3s*
    k3s ships metrics-server, so `kubectl top` and the HPA's resource metrics work. kr serves no `metrics.k8s.io` API and no kubelet resource-metrics/summary endpoint a metrics-server could scrape, so `kubectl top` fails and `HorizontalPodAutoscaler` CPU/memory targets never get values.
150. **No LoadBalancer implementation** — *missing compared with k3s*
    k3s ships ServiceLB (klipper-lb). In kr a `type: LoadBalancer` Service gets its NodePort but stays `<pending>` forever; nothing assigns `status.loadBalancer`.
151. **No Ingress controller** — *missing compared with k3s*
    k3s ships Traefik. kr stores `Ingress`/`IngressClass` objects but runs no controller; an ingress controller must be installed (it needs `LoadBalancer` or host ports, see the issue above).
152. **No built-in NetworkPolicy enforcement** — *missing compared with k3s*
    k3s ships a network-policy controller (kube-router). kr stores `NetworkPolicy` objects and nothing enforces them, so every pod can reach every pod. A CNI that enforces them (Calico, with an external-CNI server start, see below) is the only way.
153. **No VolumeSnapshot support** — *missing compared with k3s*
    k3s can run the external snapshotter. kr ships no `VolumeSnapshot*` CRDs or controller and the CSI node side does not exercise snapshots; an external snapshot-controller with its CRDs may work but is untested.
154. **No Helm controller or manifest auto-deploy directory** — *missing compared with k3s*
    k3s watches `/var/lib/rancher/k3s/server/manifests` and ships the `HelmChart` CRD and controller. kr has neither: addons are installed with `kubectl`/`helm` by hand.
155. **No `registries.yaml` and no air-gap image import** — *missing compared with k3s*
    k3s reads `registries.yaml` (mirrors, auth, TLS) and imports image tarballs from `agent/images` at start. kr has neither (mirrors are covered by the registry mirror issue), so an air-gapped install must run a local registry.
156. **No certificate and CA rotation tooling** — *missing compared with k3s*
    k3s has `certificate rotate` and CA rotation. kr renews node certificates itself (ADR-023) and has no command or procedure to rotate the cluster CA, the API server and server certificates, the front-proxy and the service-account signing key; expiry of those means a manual rebuild.
157. **No secrets encryption at rest** — *missing compared with k3s*
    k3s has `secrets-encrypt` (an `EncryptionConfiguration` with key rotation). kr stores Secrets in plain text in the store log and Raft snapshots (and in backups), so anyone who can read the data directory can read every Secret.
158. **No backup, restore or external datastore** — *missing compared with k3s*
    k3s has `etcd-snapshot` (scheduled, S3) and can run on an external SQL database or etcd. kr's store and Raft log live on the server's disk only: there is no snapshot command, scheduled snapshot, restore procedure (apart from `--cluster-init` import, ADR-026) or alternative datastore. Losing a single-server install's disk loses the cluster.
159. **No system upgrade tooling** — *missing compared with k3s*
    k3s has system-upgrade-controller and a documented node upgrade flow. kr has `docs/UPGRADING.md` for record-format compatibility but no controller or script that drains, upgrades and uncordons nodes in order.

### NVIDIA GPU support: open items (ADR-038, ADR-039)
Related: #138 (topology), #139 (unhealthy devices), #140 (`PodResources`), #141 (`Allocate` batching), #142 (exec'd processes).
160. **MIG, time-slicing and MPS are untested** — *ADR-038*
    They are exposed by the NVIDIA device plugin and should work through `Allocate`/CDI, but none has been run. MPS also needs the shared `/run/nvidia/mps` mount (mount propagation, ADR-041) and shared IPC between pods.
161. **CDI hooks run as root without a path allow-list or signature** — *ADR-039*
    Hooks come from specs in `/etc/cdi` and `/var/run/cdi` (or `KR_CDI_DIRS`); a spec is ignored unless root owns it and it is not group/world-writable. The hook binary's own ownership and permissions are not checked, and there is no allow-list of hook paths. Anyone who can write a root-owned spec (or the binary it names) gets root on the node at the next container start.
162. **No device cgroup filter: any root pod can create and open host device nodes** — *ADR-018, ADR-038, ADR-039* — **confirmed 2026-11-12, security; fixed in code, live check pending**
    A pod with no GPU and no special securityContext ran `mknod /dev/nvidia0 c 195 0` and `mknod /dev/sda b 8 0` successfully and opened `/dev/nvidia0`. Containers keep `CAP_MKNOD` (Docker's default set, ADR-018) and kr installs no device-cgroup (eBPF `BPF_PROG_TYPE_CGROUP_DEVICE`) allow-list, which is what makes that capability safe elsewhere. So GPU allocation by the device plugin is not enforced, and any root-in-container pod can reach raw host disks and any other device. Fixed: `devfilter` attaches an eBPF device allow-list to each non-privileged rootful container cgroup (ADR-018). To check on the root server after a restart: the `nogpu` pod from 2026-11-12 must get `Operation not permitted` on `/dev/nvidia0` and `/dev/sda` (`mknod` itself still succeeds), while the GPU pods and the GPU Operator pods still work. Pods started by an older binary stay unfiltered until recreated.
163. **A driver upgrade does not reach running pods** — *ADR-039*
    The toolkit rewrites `/var/run/cdi/*.yaml` when the driver changes. Specs are read per container start, so new containers get the new libraries; running ones keep the old (bind-mounted, now stale) files until they restart, and may break when the old driver libraries are removed.
164. **Hooks, `additionalGids` and the RuntimeClass lookup: live verification pending** — *ADR-039*
    Verified only with `kr ctr run --cdi` on an RTX 4090 (rootless). To do on the root server after restarting it on the new binary: a non-root pod with `runtimeClassName: nvidia` and `NVIDIA_VISIBLE_DEVICES=all` (groups 985/989 present, `nvidia-smi` works), a pod requesting `nvidia.com/gpu`, the GPU Operator validator pods, `poststop` running when pods are deleted, and a kubelet restart with GPU pods running.

# Accepted limitations (by design, or not planned for now)
11. **aarch64 path is only partly exercised**
    Cross-built binaries run under qemu-user (`tools/test/aarch64.sh`); `kr ctr`/kubelet/apiserver paths (namespaces, cgroups, clone3, mounts) do not work there and need a real aarch64 host. No CI job yet.
53. **Binary size** — *watch*
    The single binary (server, agent, runtime, TLS/crypto, CRDs, webhooks, aggregation, protobuf tables) is 3.10 MB on x86_64 (measured 2026-11-01; was 2.87 MB on 2026-10-27, and 2.32 MB on aarch64 then; it was ~1.8 MB when the 2 MB agent budget in PLAN.md was set, which is now exceeded). Measure before adding large features; avoid `{:?}` on large types, and keep `opt-level = "z"` + LTO + strip.
60. **P-256 scalar multiplication is slow** — *watch*
    Now a constant-time fixed 4-bit window (masked table scan): ~0.5 ms sign, ~0.95 ms verify (was 0.75 / 1.4 ms), dudect |t| 0.4. Fast enough for the API server's handshake rate so far; revisit if that changes.
97. **HA (kr-raft, ADR-026) design limits**
    - Membership changes are one server at a time (single-server changes, the safe protocol); a server whose IP changes while running needs a restart.
    - Linearizable reads rely on a leader lease (a quorum heard within half an election timeout); it assumes bounded clock drift between servers. Reads with an explicit `resourceVersion`, and watches, are served from the local applied state without a barrier.
    - Snapshots are sent whole in one message (512 MB frame limit). Plan: chunked InstallSnapshot if images grow.
115. **Leftovers of resolved items (not planned)**
    - CRD conversion: objects written earlier keep their stored version (a `StorageVersionMigration` rewrites them on request); for a CRD with a conversion webhook, server-side apply through a non-storage version is recorded as an Update (the converted write is a PUT).
    - Rootless: the host cannot reach pod IPs directly (use port-forward or the API server's pod proxy).
    - Memory: with 4 KB pods the 32 MiB history budget keeps about 4,000 events (watch the `410 Expired` rate); per-pod server growth (about 120 KB at 100 pods) has no per-category breakdown.

125. **API TLS handshake ~40% slower than k3s**
    `kr-crypto` TLS 1.3 handshake ~2.3 ms vs k3s ~1.6 ms (crypto optimized for memory/size). Request handling on warm connections is faster (0.5 ms vs 1.1 ms). Optimize handshake if needed.

123. **File bind-mounts of a deleted inode fail (`errno 2`)** — *kernel limit, not a kr bug*
    A hostPath file that is a bind mount whose source inode was unlinked (e.g. `findmnt` shows `[/src.txt//deleted]`, link count 0) fails with `volume mount: errno 2`. Confirmed 2026-11-11: plain `mount --bind` of such a file fails the same way (`move_mount() failed: No such file or directory`), while a bind mount with an intact source works through kr. Docker produces this when the host file is replaced after the container started; recreate the mount (restart the container).

### Terminal Ctrl-C of `kr server` killed the pods (fixed, untested live)
Sandboxes (`kr pause`) stayed in the server's process group, so a Ctrl-C in the terminal sent them SIGINT and the restarted kubelet found nothing to adopt (`adopted 0 pods`), leaving `Failed`/`SandboxFailed` ghost pods (a rejected or failed-setup pod now reports no `containerStatuses`, so `kubectl` shows its reason instead of `ContainerCreating`). ADR-036 was only tested with `kill -9`. `clear_pdeathsig` now also calls `setsid` in survive mode. Needs a live check: Ctrl-C the server and see that the next start adopts the pods. Pods started by the previous binary still die once.

### CSI node side (ADR-041): works with Longhorn; limits
Verified with Longhorn 1.x on a root kubelet: provisioning, attach, Stage/Publish, a pod writing and a second pod reading the data after detach/reattach, and deletion through the external provisioner. Not supported: block volumes, inline `csi:` ephemeral volumes, node-side expansion, volume stats; only the first PV access mode is sent. CSI needs a root kubelet. The state dir is `/var/lib/kubelet` (`KR_KUBELET_DIR`) and must differ from the kubelet root (`cfg.root`). Longhorn's deployer detects the kubelet root from a host process named `kubelet` or `k3s server`, so install it with `--set csi.kubeletRootDir=/var/lib/kubelet`.

### Longhorn disks must support FIEMAP (ext4/XFS), not tmpfs
Not a kr bug. A Longhorn replica exits at once on a tmpfs data path (`FS_IOC_FIEMAP` returns ENOTSUP), while the node still reports the disk Ready. For throwaway tests use an ext4 image on tmpfs: `truncate -s 4G /tmp/lh.img && mkfs.ext4 -q -F /tmp/lh.img && sudo mount -o loop /tmp/lh.img /tmp/lh-disk`, and add `/tmp/lh-disk` as the node disk.

### Pods keep the mount setup of the binary that started them
Containers survive a kubelet restart (ADR-036), so after an upgrade that changes how mounts are made (e.g. `mountPropagation`, ADR-041) a running pod keeps the old behaviour until it is recreated. Delete the affected pods (Longhorn: instance-manager, csi-plugin, manager).

### Calico (tigera-operator, VXLAN, `NetworkPolicy`) works with an external-CNI server start
Verified 2026-11-12 on the shared cluster: start the server with `KR_CNI_CONF_DIR=/etc/cni/net.d KR_CNI_BIN_DIR=/opt/cni/bin` (both directories must exist); without a CNI config kr keeps its bridge, so the restart changes nothing until Calico writes its conflist. Install the CRDs first (`helm template calico-crds projectcalico/crd.projectcalico.org.v1 | kubectl apply --server-side -f -`), then `helm install calico projectcalico/tigera-operator -f values.yaml` (pool `10.244.0.0/16`, VXLAN, BGP disabled; keep it off `10.88.0.0/16`). Results: typha, calico-node, kube-controllers, API server, goldmane and whisker Ready; pods get Calico IPs; pod-to-pod, DNS and egress work; 30 replicas ready in 18 s with distinct IPs; 780 Service requests (300 sequential, 480 concurrent) without a failure; `NetworkPolicy` blocks direct pod-IP traffic from a pod that is not allowed.
- **`NetworkPolicy` is not enforced for traffic through a Service ClusterIP**: see #165. Direct pod-IP traffic is enforced.
- **A host process listening on a wildcard port blocks Services on that port.** The proxy binds `ClusterIP:port`, which fails with `EADDRINUSE` while something owns `0.0.0.0:port` (here a non-kr process on `:80`). A Service port with no ready endpoint is no longer bound, so a host-network pod such as typha (`:5473`) can bind it first.
- Pods that existed before the switch keep their `10.88.0.x` addresses and bridge; they and Calico pods reach each other through the host.
- Helm charts that contain custom resources need the cluster to serve `/openapi/v2` as protobuf (now done), and the operator's `istios` CRD needs `type: integer` with `x-kubernetes-int-or-string` accepted (now done).
- `kubectl get endpoints` shows only NAME and AGE (no ENDPOINTS column).

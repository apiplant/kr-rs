# Known Issues & Potential Problems

Only work still to do lives here (open items, things to watch, accepted limits). Numbers are stable (other docs cite them); new items get the next number. When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit.

## Open
118. **Capability *adds* in `securityContext` are not applied**
    Privileged pods keep all capabilities and skip seccomp/no_new_privs, and kr runs rootful by default, so mknod/ipset/Calico work. `securityContext.capabilities` `add` / `drop` (with `ALL`) are honoured for non-privileged containers, but `kubectl exec` processes still get the default set, and device-node creation is still blocked in rootless (`KR_USERNS=1`) mode.

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

### Calico needs an external-CNI server start
kr uses an external CNI only when the server is started with `KR_CNI_CONF_DIR` (and `KR_CNI_BIN_DIR`); otherwise the built-in bridge is used and Calico's `install-cni` output is ignored. Not tried on the shared test cluster because switching would change networking for every new pod.


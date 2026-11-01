# Known Issues & Potential Problems

Only work still to do lives here (open items, things to watch, accepted limits). Numbers are stable (other docs cite them); new items get the next number. When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit.

## Open

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

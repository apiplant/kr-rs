# Known Issues & Potential Problems

Only work still to do lives here (open items, things to watch, accepted limits). Numbers are stable (other docs cite them); new items get the next number. When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit.

## Open

63. **Value validation is partial**
    Checked (`fieldval::value_errors`): `+enum` values, required strings, port ranges, non-negative counts, quantity syntax, names (containers, volumes, Service ports, hostname/subdomain, service account, env vars), volume sources and probe/lifecycle handlers (exactly one), affinity weights, workload selectors against template labels, selector expressions, a pod's containers. Not checked: formats of other free-form fields, label-selector key/value syntax, and rarer cross-field rules (for example per-volume-source requirements, topology spread constraints).
115. **Leftovers of resolved items**
    - CRD conversion: objects written earlier keep their stored version (no storage migration); server-side apply through a non-storage version is recorded as an Update.
    - Streaming: attach is output-only; `exec -t` has no terminal-size stream over SPDY (WebSocket resize works).
    - Rootless: the host cannot reach pod IPs directly (use port-forward).
        - Security: docker credential helpers are unsupported.
    - Defaults: rarely used legacy volume-source and alpha-field defaults.
    - Memory: with 4 KB pods the 32 MiB history budget keeps about 4,000 events (watch the `410 Expired` rate); per-pod server growth (about 120 KB at 100 pods) has no per-category breakdown.

# Accepted limitations (by design, or not planned for now)
11. **aarch64 path is only partly exercised**
    Remaining: `kr ctr`/kubelet/apiserver paths (namespaces, cgroups, clone3, mounts) are not run under qemu-user and need a real aarch64 host; no CI job yet.
53. **Binary size** — *watch*
    The single binary (server, agent, runtime, TLS/crypto, CRDs, webhooks, aggregation, protobuf tables) is 3.10 MB on x86_64 (measured 2026-11-01; was 2.87 MB on 2026-10-27, and 2.32 MB on aarch64 then; it was ~1.8 MB when the 2 MB agent budget in PLAN.md was set, which is now exceeded). Measure before adding large features; avoid `{:?}` on large types, and keep `opt-level = "z"` + LTO + strip.
60. **P-256 scalar multiplication is slow** — *watch*
    Now a constant-time fixed 4-bit window (masked table scan): ~0.5 ms sign, ~0.95 ms verify (was 0.75 / 1.4 ms), dudect |t| 0.4. A fixed-base comb table would make signing ~4x faster again but costs ~100 KB RAM per process; revisit if handshake rate on the API server matters.
97. **HA (kr-raft, ADR-026) design limits**
    - Membership changes are one server at a time (single-server changes, the safe protocol); a server whose IP changes while running needs a restart.
    - Follower reads are as fresh as the applied log (serializable); only the forwarding client gets read-your-writes. Plan if linearizable follower reads matter: ReadIndex.
    - Snapshots are sent whole in one message (512 MB frame limit). Plan: chunked InstallSnapshot if images grow.

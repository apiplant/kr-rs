# Known Issues & Potential Problems

Only work still to do lives here (open items, things to watch, accepted limits). Numbers are stable (other docs cite them); new items get the next number. When something is fixed, move it to `RESOLVED_ISSUES.md` with the commit.

## Open

63. **Value validation is minimal**
    Per-kind value validation (enums, formats, cross-field rules) is minimal. Plan: generate it from the upstream OpenAPI, as the protobuf table does.
65. **Server-side apply gaps**
    No version conversion of managedFields, built-in atomic structs (`+structType=atomic`, e.g. LabelSelector) are treated as granular, no deduced-type handling for `x-kubernetes-preserve-unknown-fields`, and apply never removes defaulted values it did not set.
70. **Conformance**
    Two nodes: 460 of 460 (rounds 22-26); one node: 458 of 460 (the 2 two-node specs cannot pass). Still to do: protobuf watch streams, value validation (#63), timeouts under the parallel load, `kubectl attach` denial by an admission webhook, SelfSubjectRulesReview. History: `docs/CONFORMANCE_KNOWN_ISSUES.md`.
97. **HA (kr-raft, ADR-026) gaps**
    - A removed server never sees its own removal and keeps pre-campaigning until it is stopped (harmless: pre-vote). Stop and wipe removed servers.
    - Membership changes are one at a time; a server whose IP changes while running needs a restart.
    - Follower reads are as fresh as the applied log (serializable); only the forwarding client gets read-your-writes.
    - Snapshots are sent whole in one message (512 MB frame limit). Plan: chunked InstallSnapshot if images grow.
104. **Pod behaviour gaps**
    Remaining: sidecars are not stopped when every app container of a Never/OnFailure pod finished; LimitRanger ignores Pod and PVC limit types; unsafe sysctls are not rejected; gRPC probes over TLS; pod proxy cannot reach pod IPs in rootless mode; the termination log fallback can include earlier restarts' output.
105. **API gaps**
    Protobuf tables and spec validation for the newer kinds; `kubectl attach` denial message; the Guestbook test.
106. **Workload controller gaps**
    Remaining: the DisruptionTarget condition on surviving victims is unverified; Foreground deletion is unit-tested only; CronJob ReplaceConcurrent and concurrency not checked; DaemonSet rollback needs two nodes.
113. **Intermittent `BadCertificate` calling the CRD conversion webhook** — *open* (round 20)
    The API server's TLS client rejected the webhook pod's certificate for a whole spec (159 consecutive `Tls(Local(BadCertificate))`), failing `CustomResourceConversionWebhook` (x2) and `CustomResourceFieldSelectors` on one node. Not reproduced since: 3000 Go-generated RSA-2048 CA+leaf chains all verify (`crates/kr-crypto/tests/x509_corpus.rs`, ignored test, `KR_CERT_CORPUS`), the focused specs pass, and a full one-node run (2026-10-27) had only the 2 two-node failures (458/460). Diagnostics added: certificate failures now surface as `CertParse`, `CertBadSignature`, `CertUsage`, `CertHostMismatch`, `CertUnsupportedKey` or `CertNoKey` (still alert 42 on the wire), and `kr: webhook NAME call failed (...)` is logged. If it recurs, the log names the check that failed.
115. **Leftovers of resolved items**
    - DNS: ExternalName targets outside the cluster are returned as a bare CNAME; the cluster domain is fixed to `cluster.local`.
    - CRD conversion: objects written earlier keep their stored version (no storage migration); server-side apply through a non-storage version is recorded as an Update; a failed watch batch drops the rest of that chunk.
    - Streaming: no TTY for `exec -t`; attach is output-only; `logs --previous` returns the current file; `get -o wide` lacks wide columns.
    - Rootless: the host cannot reach pod IPs directly (use port-forward).
    - Controllers: namespace deletion conditions are limited to `NamespaceContentRemaining`.
    - Security: expired bootstrap-token Secrets are not garbage-collected; the server's own certificates (1 year) are not rotated; docker credential helpers are unsupported.
    - Defaults: rarely used legacy volume-source and alpha-field defaults. HTTP client: no proactive EOF probe before reusing a pooled connection.
    - Memory: with 4 KB pods the 32 MiB history budget keeps about 4,000 events (watch the `410 Expired` rate); per-pod server growth (about 120 KB at 100 pods) has no per-category breakdown.

# Accepted limitations (by design, or not planned for now)
11. **aarch64 path is only partly exercised**
    Remaining: `kr ctr`/kubelet/apiserver paths (namespaces, cgroups, clone3, mounts) are not run under qemu-user and need a real aarch64 host; no CI job yet.
53. **Binary size** — *watch*
    The single binary (server, agent, runtime, TLS/crypto, CRDs, webhooks, aggregation, protobuf tables) is 2.87 MB on x86_64 and 2.32 MB on aarch64 (measured 2026-10-27; it was ~1.8 MB when the 2 MB agent budget in PLAN.md was set, which is now exceeded). Measure before adding large features; avoid `{:?}` on large types, and keep `opt-level = "z"` + LTO + strip.
60. **P-256 scalar multiplication is slow** — *watch*
    Now a constant-time fixed 4-bit window (masked table scan): ~0.5 ms sign, ~0.95 ms verify (was 0.75 / 1.4 ms), dudect |t| 0.4. A fixed-base comb table would make signing ~4x faster again but costs ~100 KB RAM per process; revisit if handshake rate on the API server matters.

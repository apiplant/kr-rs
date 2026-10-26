# Conformance known issues

Results of the Kubernetes v1.37 conformance suite (Sonobuoy `non-disruptive-conformance`, `E2E_PARALLEL=true`, 460 specs) against `kr`, from `tools/test/conformance.sh`. Tracked overall as KNOWN_ISSUES #70; root causes found and fixed are recorded there with their own numbers (#112 for rounds 8 to 20).

## Current status

| Cluster | Run | Result |
|---|---|---|
| Two nodes (`KR_NODES=2`: server `kr1` and agent `kr2`) | round 19 | **460 passed, 0 failed** (20 min) |
| One node | round 20 | 455 passed, 5 failed (20 min) |

A single node can pass at most 458: the two specs below need a second node, and are expected to fail there.

## Open on one node (round 20)

- [sig-architecture] Conformance Tests should have at least two untainted nodes — `Conformance requires at least two nodes` (environment: passes on two nodes)
- [sig-apps] Daemon set should rollback without unnecessary restarts — `Conformance test suite needs a cluster with at least 2 nodes.` (environment: passes on two nodes)
- [sig-api-machinery] CustomResourceConversionWebhook should be able to convert from CR v1 to CR v2 — `context deadline exceeded`
- [sig-api-machinery] CustomResourceConversionWebhook should be able to convert a non homogeneous list of CRs — `context deadline exceeded`
- [sig-api-machinery] CustomResourceFieldSelectors MUST list and watch custom resources matching the field selector — `context deadline exceeded`

The last three share one cause: all of them call the CRD conversion webhook pod, and the API server rejected its TLS certificate for the whole spec (159 consecutive `Tls(Local(BadCertificate))` while converting). They passed in earlier runs, so the fault is intermittent and depends on the key or certificate the test generates that run. Suspects: RSA verification in `kr-crypto` (`rsa.rs`) or a rule in `x509::verify_chain`. Next step (KNOWN_ISSUES #113): report which `VerifyError` fired, and fuzz RSA certificate verification against OpenSSL.

## How the count moved

| Round | Date | Passed | Notes |
|---|---|---|---|
| 7 | 2026-10-25 | 308 / 460 | first complete run |
| 8 | 2026-10-26 | 406 | review APIs, events, pod certificates, resize, field selectors, controllers |
| 9 | 2026-10-26 | 432 | CRD multi-version apply, DaemonSet revisions, events and HPA discovery, pod resize |
| 10-11 | 2026-10-26 | 412, 416 | connection resets and timeouts under parallel load |
| 12 | 2026-10-26 | 447 | bridge MAC pinned: the stale gateway MAC after pod bursts caused 40 s outages (the main source of the "10.96.0.1 i/o timeout" failures) |
| 13 | 2026-10-26 | 455 | DaemonSet revision data and labels, collection delete, resize, mTLS server |
| 14 | 2026-10-26 | 452 (two nodes) | first run on two nodes; cross-node RBAC and websocket gaps found |
| 15-18 | 2026-10-26 | 457, 459, 459, 459 (two nodes) | stale ARP entries for reused pod IPs, remote-node websocket subprotocols, Deployment rollout stall |
| 19 | 2026-10-26 | **460** (two nodes) | |
| 20 | 2026-10-27 | 455 (one node) | the two-node specs plus 3 intermittent conversion-webhook certificate failures |

The causes behind the intermittent failures, for future triage:
- A burst of new pods used to change the bridge's MAC (a bridge without a fixed address takes the lowest MAC of its ports), so existing pods sent to the old gateway MAC until their ARP entry expired. Fixed by pinning the MAC.
- A pod IP reused by a new pod kept the previous pod's MAC in the host's ARP cache, so connections timed out for seconds up to a minute. Fixed by flushing the entry on attach and sending a gratuitous ARP from the new pod.
- The service proxy exhausted ephemeral ports when it closed first on many short connections to the API server on the node address. Fixed by dialing local backends over loopback.
- Pods on the agent node: the kubelet relay did not accept the `channel.k8s.io`, `binary.k8s.io` and `base64.binary.k8s.io` websocket subprotocols, and the node RBAC lacked ClusterTrustBundle and PodCertificateRequest access.
- A Deployment resized in the middle of a rollout could livelock when the proportional-scaling step never updated the replica annotations.

## Reproducing and triaging

```sh
tools/test/conformance.sh run full                  # one node, throwaway container
KR_NODES=2 tools/test/conformance.sh run full       # server plus agent
tools/test/conformance.sh run focus 'REGEX'         # a subset (5-20 minutes less)
tools/test/conformance.sh results DIR               # DIR/failed-tests.txt, failure summary
```

Extra diagnostics in the server log (`docker exec kr1 cat /tmp/srv.log`): `kr: slow request ...` (requests over 300 ms), `kr: event loop stalled Nms`, `kr: webhook NAME call failed ...` (also when `failurePolicy: Ignore` hides it) and `kr: proxy dial IP:PORT ...`.

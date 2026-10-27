# kr

A Kubernetes distribution in a single static binary of about 2.9 MB, written in Rust with no libc and no third-party crates.

`kr` is the API server, datastore, scheduler, controllers, kubelet, container runtime, pod network, service proxy and cluster DNS in one executable. It is built to idle in single-digit megabytes, start in well under a second, and run unmodified `kubectl` and standard workloads. It passes the Kubernetes v1.37 conformance suite (460 of 460 specs on a two-node cluster, 458 of 460 on one node; see [Conformance](#conformance)).

```
$ sudo kr server &
$ export KUBECONFIG=/var/tmp/srv/admin.kubeconfig
$ kubectl create deployment web --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 --replicas=3 -- /agnhost netexec
$ kubectl get pods
```

## Contents
- [Quick start](#quick-start)
- [Benchmarks](#benchmarks)
- [Features](#features)
- [How it is built](#how-it-is-built)
- [Conformance](#conformance)
- [Limitations](#limitations)
- [Development](#development)

## Quick start

Requirements: Linux 5.10 or newer on x86_64 or aarch64, cgroup v2, overlayfs, and root for the full feature set (pod networking, cgroup limits). A rootless mode exists with reduced networking. Building needs a Rust nightly toolchain.

```sh
cargo build --release          # produces target/release/kr (about 2.9 MB)
```

### Single node

```sh
sudo target/release/kr server --data /var/lib/kr &      # API on :6443; the node registers itself
export KUBECONFIG=/var/lib/kr/admin.kubeconfig
kubectl get nodes
kubectl run hello --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 -- netexec
kubectl get pods -o wide
```

The server is also the first node: it runs the kubelet and the service proxy in-process.

### Add a node

```sh
# on the server
kr token create --ttl 24h --data /var/lib/kr

# on the new machine
sudo kr agent --server https://SERVER:6443 --token TOKEN
```

Agents get a pod subnet from the server and reach each other over VXLAN (default) or host routes (`KR_NET_BACKEND=host-gw`).

### High availability

```sh
kr server --cluster-init                                  # first server, Raft-replicated store
kr server --server https://FIRST:6443 --token-file F     # additional servers
```

### Running containers without Kubernetes

```sh
kr ctr pull docker.io/library/busybox
kr ctr run --memory 64Mi --cpus 500m docker.io/library/busybox -- echo hello
```

### Useful environment variables

| Variable | Effect |
|---|---|
| `KR_REGISTRY_MIRRORS` | `registry.k8s.io=http://host:5000,docker.io=https://cache:5000` pull-through mirrors |
| `KR_NET_BACKEND` | `vxlan` (default) or `host-gw` |
| `KR_ROOT` | where images, pod state and IP leases live |

## Benchmarks

Measured on one 32-core x86_64 Linux machine, each node in a privileged Docker container, with cached images (`pause` and `agnhost`). Memory is the resident set size (RSS) of the `kr` processes; "PSS" is memory divided between processes that share pages.

### Size

| | x86_64 | aarch64 |
|---|---|---|
| `kr` binary (stripped, `opt-level=z`, LTO, `panic=abort`) | **2.87 MB** | **2.32 MB** |
| Third-party crates | 0 | 0 |
| Rust source (13 workspace crates) | about 58,600 lines | |

For scale: the binary contains the TLS 1.3 stack, X.509, the HTTP/1.1 and WebSocket stacks, the Raft and storage engines, the OCI runtime, the API server with its generated protobuf tables, and the controllers.

### Memory

| State | `kr server` | `kr agent` |
|---|---|---|
| Idle, no pods | **7.4 MB** RSS (+1.2 MB helper) | **3.2 MB** RSS |
| 10 pods | 9.4 MB | |
| 50 pods | 13.9 MB | |
| 100 pods | **19.8 MB** | **9.0 MB** |

The watch history (the recent writes kept so a watch can resume) is limited to 32 MiB, so memory under sustained writes levels off instead of growing: 62,000 updates of a 1 KB object leave the server at about 36 MB.

Each pod also has a sandbox holder process that keeps its namespaces alive: about 0.5 MB RSS, of which only 60 to 90 KB is private (the rest is shared with the main process).

### Latency and throughput

| Operation | Result |
|---|---|
| `kr server` to node Ready | under 1 s |
| 100 `pause` pods Deployment, cached image, single node | about 2 s to all Running |
| `GET /version`, new TLS 1.3 connection each time | p50 4.0 ms, p99 7.9 ms |
| `GET /api/v1/namespaces/default/pods` (100 pods, 420 KB) | p50 7.2 ms, p99 10.1 ms |
| New TLS connections served to pods under 40 parallel clients | about 600 per second, no failures |

Numbers will vary with hardware; the commands to reproduce them are in `tools/test/` (`two-node.sh`, `conformance.sh`) and the measurements above used `/proc/<pid>/status` (`VmRSS`) and `smaps_rollup` (`Pss`).

## Features

**Control plane**
- Kubernetes API v1.37: core, apps, batch, autoscaling, policy, networking, storage, RBAC, certificates, coordination, discovery, flowcontrol, scheduling, resource (DRA), events and more, served as JSON and protobuf, with watches, chunked lists, Tables and aggregated discovery
- Embedded datastore (append-only log with MVCC revisions, compaction, optional Raft replication for 3 or more servers) instead of etcd
- Server-side apply with managed fields, strategic merge and JSON patch, field validation, defaulting
- CustomResourceDefinitions with structural schemas, CEL validation, defaulting, pruning, selectable fields, status and scale subresources, and conversion (None and webhook)
- Admission: validating and mutating webhooks, ValidatingAdmissionPolicy and MutatingAdmissionPolicy (CEL), Pod Security admission, ResourceQuota, LimitRange, priority classes, ServiceAccount
- Authentication: client certificates, bootstrap tokens, signed ServiceAccount tokens (TokenRequest, projected, audience-bound), TokenReview, impersonation
- Authorization: RBAC, Node authorizer, SubjectAccessReview and the self-service review APIs
- API aggregation: APIServices backed by a Service, with front-proxy authentication
- Pod certificates (`PodCertificateRequest` and projected `podCertificate` volumes) and ClusterTrustBundles

**Controllers and scheduler**
- Deployment (rolling update with proportional scaling, rollback, history), ReplicaSet, ReplicationController, StatefulSet, DaemonSet, Job (success policies, indexed jobs, backoff per index, pod failure policy), CronJob
- Endpoints, EndpointSlice and mirroring, namespace and garbage collection (orphan and foreground), PV and PVC provisioning with a built-in local provisioner, PodDisruptionBudget, eviction
- Scheduler with resource fit, node selectors and affinity, taints and tolerations, topology spread, extended resources and priority preemption

**Node**
- OCI image pull (registry v2 with mirrors), overlayfs rootfs, containers in user, mount, PID, network, IPC, UTS and cgroup namespaces, seccomp, capability dropping, cgroup v2 limits, in-place pod resize
- Probes (HTTP, TCP, exec, gRPC), lifecycle hooks, init containers and sidecars, ephemeral containers, `exec`, `attach`, `logs`, `port-forward` over WebSocket and SPDY
- Volumes: emptyDir, hostPath, configMap, secret, downwardAPI, projected (token, configMap, secret, ClusterTrustBundle, pod certificate), PVC, image volumes
- Memory-pressure eviction, node leases, node authorization and certificate rotation

**Networking**
- Built-in bridge and veth pod network with host-local IPAM, no CNI plugins
- Cross-node VXLAN or host-gw, NAT through nftables over netlink (no `iptables`/`nft` binaries needed)
- Service proxy for ClusterIP, NodePort and hostPort (with ClientIP affinity), in-process cluster DNS (`cluster.local`, pod and service records, ExternalName)

## How it is built

Every crate is `#![no_std]` with `alloc`; only the final `kr` binary provides `_start`, the panic handler, the allocator and the syscall layer (inline assembly). There is no libc and no external crate.

| Crate | Role |
|---|---|
| `kr-sys` | raw syscalls for x86_64 and aarch64, namespaces, cgroups, netlink primitives |
| `kr-rt` | process start-up, allocator, single-threaded epoll executor for async/await |
| `kr-fmt` | JSON, YAML subset, protobuf wire format, base64, quantities |
| `kr-crypto` | SHA-2, HMAC, X25519, Ed25519, ECDSA P-256, RSA verification, AES-GCM, ChaCha20-Poly1305, X.509, TLS 1.3 client and server |
| `kr-net` | TCP, HTTP/1.1 client and server, WebSocket, SPDY, DNS server, netlink, nftables |
| `kr-archive` | gzip and tar for image layers |
| `kr-store` | embedded MVCC datastore with watch |
| `kr-raft` | Raft for replicated servers |
| `kr-apiserver` | REST, discovery, authn/authz, admission, CRDs, webhooks, aggregation |
| `kr-controllers` | built-in controllers and the scheduler |
| `kr-runtime` | OCI image store and container runtime, pod network |
| `kr-kubelet` | pod lifecycle, probes, volumes, node status, service proxy |
| `kr` | the binary: `server`, `agent`, `ctr`, `token`, `pki` |

Design points:
- One thread. The runtime is a cooperative epoll executor, so there are no locks and no data races; clone3, setns and friends are used safely because of it. (Decision records: `docs/DECISIONS.md`.)
- The kubelet calls the runtime in-process; there is no CRI, no containerd, no runc and no separate daemons.
- The Kubernetes protobuf schema tables are generated from the upstream `.proto` files by `tools/gen_k8s_proto_schema.py` and compiled into the binary.

## Conformance

Results of the CNCF conformance suite (Sonobuoy, `non-disruptive-conformance`, parallel), Kubernetes v1.37 e2e image:

| Cluster | Result |
|---|---|
| 2 nodes (server and agent) | **460 of 460** |
| 1 node | 458 of 460 in the latest full run: the other 2 specs need a second node and cannot pass on one |

Reproduce with `tools/test/conformance.sh` (see `docs/CONFORMANCE_README.md`):

```sh
tools/test/conformance.sh run full               # one node, in a throwaway container
KR_NODES=2 tools/test/conformance.sh run full    # server plus agent
tools/test/conformance.sh run focus 'Aggregator.*\[Conformance\]'   # a subset
tools/test/conformance.sh results /tmp/out       # failures by area
```

## Limitations

- IPv4 only. Rootless pods and `kr ctr run` containers reach the outside through a userspace NAT (about 300 MB/s on loopback-class links; `ping` works when `net.ipv4.ping_group_range` allows it; IP fragments are reassembled and window scaling is negotiated).
- Watches of aggregated APIs are not supported (the API returns 501).
- Pod resize has no restart policies and does not model `PodResizePending`.
- Only ECDSA P-256 keys for pod certificates; RSA is verify-only.
- API priority and fairness objects exist but are not enforced.
- Not certified by the CNCF: the suite passes, but the certification process has not been run.
- The full list is in [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md).

## Development

```sh
tools/test/unit.sh            # every library crate (the kr binary itself has no unit tests)
cargo test --workspace
tools/test/aarch64.sh         # cross-build and smoke test under qemu-user
tools/test/two-node.sh up     # server kr1 and agent kr2 in Docker
tools/test/ha.sh              # three-server Raft cluster
```

Documents: [`docs/PLAN.md`](docs/PLAN.md) (design and budgets), [`docs/DECISIONS.md`](docs/DECISIONS.md) (architecture decision records), [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md), [`docs/CONFORMANCE_KNOWN_ISSUES.md`](docs/CONFORMANCE_KNOWN_ISSUES.md).

License: Apache-2.0.

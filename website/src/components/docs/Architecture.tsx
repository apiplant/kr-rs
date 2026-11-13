import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table } from "./Prose";

export function DocsArchitecture() {
  return (
    <DocsLayout>
      <H1>Architecture</H1>
      <Lead>
        Thirteen workspace crates, no third-party code, and one thread. Every design decision is recorded as an ADR in{" "}
        <IC>docs/DECISIONS.md</IC>.
      </Lead>

      <Section>
        <H2>Crates</H2>
        <P>
          Every crate is <IC>#![no_std]</IC> with <IC>alloc</IC>. Only the final <IC>kr</IC> binary provides{" "}
          <IC>_start</IC>, the panic handler, the allocator and the syscall layer (inline assembly).
        </P>
        <Table
          head={["Crate", "Role"]}
          rows={[
            ["kr-sys", "Raw syscalls for x86_64 and aarch64, namespaces, cgroups, netlink primitives."],
            ["kr-rt", "Process start-up, allocator, a single-threaded epoll executor for async/await, and worker processes for CPU-bound work."],
            ["kr-fmt", "JSON, a YAML subset, protobuf wire format, base64, quantities."],
            ["kr-crypto", "SHA-2, HMAC, X25519, Ed25519, ECDSA P-256, RSA, AES-GCM, ChaCha20-Poly1305, X.509, TLS 1.3 client and server with session resumption, TLS 1.2 client (opt-in)."],
            ["kr-net", "TCP, HTTP/1.1 client and server, HTTP/2 with HPACK, gRPC (unary and streaming, client and server), WebSocket, SPDY, DNS client and server, OCI registry client, S3 client (SigV4), netlink (incl. WireGuard), nftables, userspace NAT for rootless pods."],
            ["kr-archive", "gzip (inflate), zstd and tar for image layers."],
            ["kr-store", "The embedded MVCC datastore with write-ahead log, watch and snapshots."],
            ["kr-raft", "Raft for replicated servers."],
            ["kr-apiserver", "REST (JSON and protobuf), discovery, OpenAPI, authn/authz (RBAC, node authorizer), admission (incl. Pod Security, quota, CEL validating policies), CRDs with conversion, server-side apply, webhooks, aggregation, API priority and fairness, audit (log and webhook), encryption at rest, metrics, Raft cluster join and forwarding."],
            ["kr-controllers", "Built-in controllers (workloads, GC, namespaces, nodes, HPA, PVC and attach/detach, CSR signing, quota, service LB, storage version migration), the Helm controller, the manifests directory, the scheduler."],
            ["kr-runtime", "OCI image pull and store, container runtime with seccomp, AppArmor/SELinux, device cgroup filter and OCI hooks, image GC, pod network."],
            ["kr-kubelet", "Pod lifecycle, probes (incl. gRPC), volumes and CSI, device plugins, pod resources API, eviction, stats, exec/attach/port-forward, CNI, network policy, egress, DNS, service proxy (userspace and nftables), adoption of running pods."],
            ["kr", "The binary: server, agent, ctr, token, pki/certificate, snapshot, secrets-encrypt."],
          ]}
        />
      </Section>

      <Section>
        <H2>Design points</H2>
        <UL>
          <LI><strong class="font-medium text-ink">One thread.</strong> The runtime is a cooperative epoll executor. There are no locks and no data races, and <IC>clone3</IC>, <IC>setns</IC> and friends can be used safely because of it.</LI>
          <LI><strong class="font-medium text-ink">In-process runtime.</strong> The kubelet calls the container runtime directly. No CRI, no containerd, no runc, no separate daemons.</LI>
          <LI><strong class="font-medium text-ink">Crypto in one crate.</strong> TLS 1.3 and the primitives are isolated in <IC>kr-crypto</IC> so they can be reviewed and tested on their own, and swapped without touching anything else. The P-256 scalar multiplication is constant-time (a fixed 4-bit window with a masked table scan), checked with a dudect-style test.</LI>
          <LI><strong class="font-medium text-ink">Generated schemas.</strong> The Kubernetes protobuf schema tables are generated from the upstream <IC>.proto</IC> files by <IC>tools/gen_k8s_proto_schema.py</IC> and compiled in.</LI>
          <LI><strong class="font-medium text-ink">Unsafe is contained.</strong> Unsafe code lives in the syscall, runtime and crypto-assembly layers only.</LI>
          <LI><strong class="font-medium text-ink">Detached containers.</strong> A per-container shim and an adopt record let pods outlive the kubelet process (ADR-036).</LI>
        </UL>
      </Section>

      <Section>
        <H2>Decision records</H2>
        <P>A selection of the thirty-seven ADRs. All are in <IC>docs/DECISIONS.md</IC>.</P>
        <Table
          head={["ADR", "Decision"]}
          rows={[
            ["001", "A single multicall binary."],
            ["002", "no_std + alloc, no libc, no crates.io dependencies."],
            ["005", "A hand-rolled epoll executor instead of tokio."],
            ["006", "An embedded store replaces etcd."],
            ["007", "An in-process container runtime, with no CRI or gRPC."],
            ["008", "Networking built in."],
            ["016", "Rootless-first runtime using kernel isolation."],
            ["018", "Container security profile and cgroup supervision."],
            ["020", "kr-crypto and TLS 1.3."],
            ["022", "Services, cluster DNS and multi-node."],
            ["025", "VXLAN as the default pod network backend."],
            ["026", "kr-raft, replicating the store across servers."],
            ["031", "Rootless egress through a TUN device and a userspace NAT."],
            ["032, 034", "Dual-stack pod network, with configurable families."],
            ["035", "Linearizable follower reads by leader lease."],
            ["036", "Pods survive a restart or crash of the kubelet."],
            ["037", "The node lifecycle controller."],
          ]}
        />
      </Section>
    </DocsLayout>
  );
}

import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table } from "./Prose";

export function DocsOverview() {
  return (
    <DocsLayout>
      <H1>Documentation</H1>
      <Lead>
        <IC>kr</IC> is a Kubernetes distribution in a single static binary of about 5.0 MB, written in Rust with no
        libc and no third-party crates. It is the API server, datastore, scheduler, controllers, kubelet, container
        runtime, pod network, service proxy and cluster DNS in one executable.
      </Lead>

      <Section>
        <H2>What you get</H2>
        <UL>
          <LI>Unmodified <IC>kubectl</IC> and standard workloads against Kubernetes API v1.37.</LI>
          <LI>
            The v1.37 conformance suite passes: 460 of 460 specs on a two-node cluster, 458 of 460 on one node (the
            other two need a second node). See <a class="text-accent hover:text-accent-dim" href="/docs/conformance">Conformance</a>.
          </LI>
          <LI>Idle memory of about 13 MB for the server and 5 MB for an agent, and nodes that are Ready in about 2 seconds.</LI>
          <LI>Multi-node clusters over VXLAN or host routes, and Raft-replicated servers for high availability.</LI>
          <LI>Pods that keep running while <IC>kr</IC> is restarted, crashes, or is replaced by a newer binary.</LI>
        </UL>
      </Section>

      <Section>
        <H2>What it replaces</H2>
        <P>
          A conventional distribution is a bundle of separate programs. kr folds each into the same process, so there
          is nothing else to install, configure or keep in step.
        </P>
        <Table
          head={["Usually", "In kr"]}
          rows={[
            ["etcd", "An embedded MVCC datastore, with built-in Raft for three or more servers"],
            ["kube-apiserver, scheduler, controller-manager", "`kr server`, one process"],
            ["kubelet, kube-proxy", "In-process; the server is also the first node"],
            ["containerd and runc, over CRI gRPC", "An in-process OCI runtime; the kubelet calls it directly"],
            ["A CNI plugin", "A built-in bridge and veth network with VXLAN or host-gw"],
            ["iptables or nft binaries", "nftables programmed directly over netlink"],
            ["CoreDNS", "An in-process cluster DNS server"],
            ["OpenSSL, cfssl", "TLS 1.3, X.509 and `kr pki` in the binary"],
          ]}
        />
      </Section>

      <Section>
        <H2>What it asks of the host</H2>
        <P>
          Linux 5.10 or newer on x86_64 or aarch64, cgroup v2 and overlayfs, and root for the full feature set (pod
          networking, cgroup limits). A <a class="text-accent hover:text-accent-dim" href="/docs/rootless">rootless mode</a>{" "}
          exists, with reduced networking. Pods survive restarts of <IC>kr</IC> on Linux 5.9 and newer. Nothing else
          is needed on the host: not even <IC>/bin/sh</IC>.
        </P>
        <P>
          "No dependencies" means no crates.io crates and no libc. The Linux kernel ABI is still a dependency: raw
          syscalls, namespaces, cgroup v2, netlink, seccomp and overlayfs. A container runtime cannot exist without
          them.
        </P>
      </Section>

      <Section>
        <H2>Where to read next</H2>
        <UL>
          <LI><a class="text-accent hover:text-accent-dim" href="/docs/quickstart">Quick start</a>: build it and run a workload.</LI>
          <LI><a class="text-accent hover:text-accent-dim" href="/docs/nodes">Nodes and tokens</a> and <a class="text-accent hover:text-accent-dim" href="/docs/ha">High availability</a>: grow the cluster.</LI>
          <LI><a class="text-accent hover:text-accent-dim" href="/docs/operations">Operations</a>: systemd, upgrades, and what happens when a node fails.</LI>
          <LI><a class="text-accent hover:text-accent-dim" href="/docs/architecture">Architecture</a>: how it is built and why.</LI>
        </UL>
      </Section>
    </DocsLayout>
  );
}

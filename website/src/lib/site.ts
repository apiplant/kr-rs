/** Everything the home page says about the project, in one place. */

export interface Card {
  name: string;
  href: string;
  tagline: string;
  body: string;
}

export interface Feature {
  title: string;
  body: string;
}

export interface Stat {
  value: string;
  label: string;
}

export const SITE = {
  pkg: "kr",
  bins: ["kr"],
  badges: ["Rust", "no libc", "0 crates", "Conformance 460/460", "Apache-2.0"],
  hero: { pre: "Kubernetes in ", accent: "one 3 MB binary", post: "." },
  lead: "API server, datastore, scheduler, controllers, kubelet, container runtime, pod network, service proxy and cluster DNS in a single static executable. Written in Rust with no libc and no third-party crates. Runs unmodified kubectl and standard workloads.",
  heroNote:
    "Passes the Kubernetes v1.37 conformance suite: 460 of 460 specs on two nodes. The server idles at 7 MB of RAM and the node is Ready in under a second.",
  stats: [
    { value: "2.9 MB", label: "static binary, x86_64" },
    { value: "7.4 MB", label: "server RSS, idle" },
    { value: "< 1 s", label: "start to node Ready" },
    { value: "460 / 460", label: "conformance specs" },
  ] as Stat[],
  terminal: {
    title: "kr",
    command: `sudo kr server --data /var/lib/kr &
export KUBECONFIG=/var/lib/kr/admin.kubeconfig
kubectl create deployment web --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 --replicas=3 -- /agnhost netexec
kubectl get pods -o wide`,
    outputLang: "text",
    output: `NAME                   READY   STATUS    RESTARTS   AGE   IP          NODE
web-6bd98c9549-4txpd   1/1     Running   0          12s   10.88.1.2   kr2
web-6bd98c9549-llv9q   1/1     Running   0          12s   10.88.0.3   kr1
web-6bd98c9549-mdhpr   1/1     Running   0          12s   10.88.1.3   kr2`,
  },
  cardsTitle: "One binary, every role",
  cardsLead: "Subcommands of the same executable. There are no sidecar daemons, no containerd, no runc and no CNI plugins to install.",
  cards: [
    {
      name: "kr server",
      href: "/docs/cli#server",
      tagline: "Control plane, and the first node",
      body: "API server, embedded datastore, scheduler and controllers. It also runs the kubelet and service proxy in-process, so one command gives you a working single-node cluster. Add --cluster-init for a Raft-replicated store.",
    },
    {
      name: "kr agent",
      href: "/docs/cli#agent",
      tagline: "A worker node",
      body: "Joins with a bootstrap token, gets a pod subnet, and reaches other nodes over VXLAN or host routes. Idles at about 3 MB of RSS.",
    },
    {
      name: "kr ctr",
      href: "/docs/ctr",
      tagline: "Containers without Kubernetes",
      body: "Pull an OCI image and run it isolated, with cgroup limits and networking, straight from the command line. The same runtime the kubelet uses.",
    },
    {
      name: "kr token / kr pki",
      href: "/docs/cli#token",
      tagline: "Join tokens and certificates",
      body: "Create bootstrap tokens for new nodes, and issue CA and leaf certificates yourself. No openssl needed.",
    },
  ] as Card[],
  featuresTitle: "A real cluster, not a demo",
  featuresLead: "The Kubernetes API surface kubectl and common workloads need, built from scratch and checked against the upstream conformance suite.",
  features: [
    {
      title: "Conformance-passing",
      body: "460 of 460 specs of the Kubernetes v1.37 suite on a two-node cluster, 458 of 460 on one node (the other two need a second node).",
    },
    {
      title: "No etcd",
      body: "An embedded MVCC datastore with watches and compaction. Three or more servers replicate it with a built-in Raft, with linearizable follower reads.",
    },
    {
      title: "No containerd, no runc",
      body: "Images are pulled and unpacked in-process, then run in user, mount, PID, network, IPC, UTS and cgroup namespaces with seccomp and cgroup v2 limits.",
    },
    {
      title: "Pods survive restarts",
      body: "A small shim per container keeps pods, their IPs and connections alive while kr restarts or crashes, and the next process adopts them. Upgrade in place.",
    },
    {
      title: "Networking built in",
      body: "Bridge and veth pod network, VXLAN or host-gw across nodes, Services through nftables over netlink, in-process cluster DNS. IPv4, IPv6 or dual stack.",
    },
    {
      title: "Rootless mode",
      body: "Run without root with a TUN device and a userspace NAT for pod egress. Reduced networking, same API.",
    },
    {
      title: "Full API machinery",
      body: "CRDs with CEL validation and conversion, admission webhooks and policies, server-side apply, aggregation, API priority and fairness, Pod Security admission.",
    },
    {
      title: "Security by construction",
      body: "TLS 1.3, X.509 and the crypto primitives are in one isolated crate. Client certificates, bootstrap and ServiceAccount tokens, RBAC and the Node authorizer.",
    },
    {
      title: "Zero third-party crates",
      body: "Every crate is no_std. Only the Linux kernel ABI is a dependency: raw syscalls, written in inline assembly, for x86_64 and aarch64.",
    },
  ] as Feature[],
  tableTitle: "Small, measured",
  tableLead: "One 32-core x86_64 machine, each node in a privileged Docker container, images cached.",
  table: [
    ["Binary, stripped (x86_64)", "2.87 MB"],
    ["Third-party crates", "0"],
    ["kr server idle, no pods", "7.4 MB RSS"],
    ["kr server, 100 pods", "19.8 MB RSS"],
    ["kr agent idle", "3.2 MB RSS"],
    ["kr agent, 100 pods", "9.0 MB RSS"],
    ["100-pod Deployment, all Running", "about 2 s"],
    ["GET /version, new TLS 1.3 connection", "p50 4.0 ms"],
  ] as [string, string][],
  cargo: `git clone https://github.com/apiplant/kr-rs && cd kr-rs
cargo build --release        # needs a Rust nightly toolchain
sudo install -m755 target/release/kr /usr/local/bin/kr`,
};

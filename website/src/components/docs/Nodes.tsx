import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table, Note } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsNodes() {
  return (
    <DocsLayout>
      <H1>Nodes and tokens</H1>
      <Lead>Join machines to a cluster with a bootstrap token. Each agent gets a pod subnet from the server.</Lead>

      <Section>
        <H2>Create a token</H2>
        <CopyBlock command={`kr token create --ttl 24h --data /var/lib/kr`} />
        <P>
          The default lifetime is 24 hours; <IC>--ttl 0</IC> never expires. Pass <IC>--server</IC> to target a server
          other than <IC>https://127.0.0.1:6443</IC>. Treat a token like a password: anyone holding it can join a
          node.
        </P>
      </Section>

      <Section>
        <H2>Join an agent</H2>
        <CopyBlock command={`sudo kr agent --server https://SERVER:6443 --token TOKEN --data /var/lib/kr`} />
        <P>
          Prefer <IC>--token-file FILE</IC> or <IC>KR_TOKEN</IC> in the environment: a token on the command line is
          readable by every local user in <IC>/proc/PID/cmdline</IC>, and kr prints a warning. The token embeds the
          hash of the cluster CA, so the agent fetches the CA over TLS pinned to that hash, then exchanges the token
          for node certificates. The token is needed only for the first join. Node certificates are rotated before they
          expire (<IC>KR_NODE_CERT_SECONDS</IC> sets their lifetime on the server). The agent registers the node, takes a pod
          subnet and starts the kubelet, service proxy and cluster DNS, and serves the kubelet API on port 10250
          for the API server's logs, exec and port-forward proxy.
        </P>
        <Note>
          Only one <IC>kr server</IC> or <IC>kr agent</IC> can run on a given <IC>KR_ROOT</IC>: a lock file makes a
          second one exit, so two processes can never adopt the same pods.
        </Note>
      </Section>

      <Section>
        <H2>Cross-node pod traffic</H2>
        <Table
          head={["Backend", "Set with", "How it works"]}
          rows={[
            ["vxlan", "default", "A VXLAN overlay built over netlink. Works across routed networks."],
            ["host-gw", "KR_NET_BACKEND=host-gw", "Plain host routes to each node's pod subnet, with no encapsulation."],
          ]}
        />
        <P>
          Each node owns one /24 for IPv4 (<IC>10.88.N.0/24</IC>), about 253 addresses, while the node advertises
          110 pods. When a subnet has no free address the pod waits in <IC>ContainerCreating</IC> and retries instead
          of starting without a network.
        </P>
      </Section>

      <Section>
        <H2>What happens when a node stops</H2>
        <P>
          A node lifecycle controller watches node leases and heartbeats every 5 seconds.
        </P>
        <UL>
          <LI>After <strong class="font-medium text-ink">40 seconds</strong> without a sign of life the node's conditions become <IC>Unknown</IC> and it receives the <IC>node.kubernetes.io/unreachable</IC> taints (<IC>NoSchedule</IC> and <IC>NoExecute</IC>).</LI>
          <LI>Its pods are marked not Ready, so Endpoints and EndpointSlices stop sending traffic to them.</LI>
          <LI>Pods are evicted once their toleration of the <IC>NoExecute</IC> taint ends: after <IC>tolerationSeconds</IC>, or 300 seconds when they set none.</LI>
          <LI>When heartbeats resume, the taints are removed and the kubelet restores the node and pod conditions.</LI>
        </UL>
        <P>
          A DaemonSet pod already on a node is not deleted just because the node went NotReady: the controller keeps a
          node eligible while it has a live pod there and only <IC>NoExecute</IC> taints are in the way.
        </P>
      </Section>

      <Section>
        <H2>Draining and removing a node</H2>
        <CopyBlock
          command={`kubectl drain NODE --ignore-daemonsets --delete-emptydir-data
kubectl delete node NODE`}
        />
        <P>Drain uses the eviction API, so PodDisruptionBudgets are honoured.</P>
      </Section>
    </DocsLayout>
  );
}

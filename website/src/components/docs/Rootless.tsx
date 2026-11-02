import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Note } from "./Prose";

export function DocsRootless() {
  return (
    <DocsLayout>
      <H1>Rootless mode</H1>
      <Lead>
        Run <IC>kr ctr</IC>, an agent or a server as a normal user, with user namespaces and a userspace network.
      </Lead>

      <Section>
        <H2>What is different</H2>
        <UL>
          <LI>Data defaults to <IC>$XDG_DATA_HOME/kr</IC> or <IC>~/.local/share/kr</IC> instead of <IC>/var/lib/kr</IC>.</LI>
          <LI>Containers live in an infra user and network namespace with no route out of its own. kr gives it a TUN device, <IC>kr-out</IC> (100.64.255.1/30), as the default route.</LI>
          <LI>A slirp-style userspace NAT in the host namespace terminates the pod's TCP and relays each flow over ordinary host sockets. UDP maps to host UDP sockets and ICMP echo goes out through an unprivileged ICMP socket (it needs <IC>ping_group_range</IC>).</LI>
          <LI>DNS to 100.64.255.2:53 is forwarded to the host's first nameserver.</LI>
          <LI>Service ClusterIPs and pod-to-pod traffic stay inside the infra namespace and never touch the TUN.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Limits</H2>
        <UL>
          <LI>The host cannot reach pod IPs directly. Use <IC>kubectl port-forward</IC> or the API server's pod proxy.</LI>
          <LI>The userspace NAT handles IPv4 and IPv6 flows; there is no retransmission toward the pod, since the TUN is lossless.</LI>
          <LI>cgroup limits need a delegated cgroup subtree (for example a systemd user service with <IC>Delegate=yes</IC>).</LI>
        </UL>
      </Section>

      <Section>
        <H2>Surviving restarts</H2>
        <P>
          Rootless nodes keep their pods through a restart too. The NAT runs as a separate detached process,{" "}
          <IC>kr egress</IC>, which owns the TUN device, and the namespace holder is recorded in{" "}
          <IC>infra.adopt</IC>. At start the kubelet adopts both if they are alive. If the namespace holder died, the
          pods that used it are killed and recreated.
        </P>
        <Note>
          Tests: <IC>tools/test/rootless-egress.sh</IC> (download, upload, DNS, ping), <IC>rootless-egress-v6.sh</IC>,{" "}
          <IC>rootless-families.sh</IC> and <IC>rootless-survive.sh</IC>.
        </Note>
      </Section>
    </DocsLayout>
  );
}

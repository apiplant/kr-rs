import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsNetworking() {
  return (
    <DocsLayout>
      <H1>Networking</H1>
      <Lead>
        Pod network, Services and DNS are built in. No CNI plugins, no <IC>iptables</IC> or <IC>nft</IC> binaries and no
        CoreDNS to install.
      </Lead>

      <Section>
        <H2>Pod network</H2>
        <UL>
          <LI>A bridge and veth pair per pod, with host-local IP address management. Leases are files under <IC>KR_ROOT/ipam</IC>, one /24 per node.</LI>
          <LI>Between nodes: a VXLAN overlay (the default) or host routes. Pick with <IC>KR_NET_BACKEND=vxlan|host-gw</IC>.</LI>
          <LI>Egress NAT, and Service rules, are programmed into nftables directly over netlink.</LI>
        </UL>
      </Section>

      <Section>
        <H2>IPv4, IPv6 and dual stack</H2>
        <P>Choose the families with <IC>KR_POD_FAMILIES</IC>: <IC>4</IC>, <IC>6</IC> or <IC>4,6</IC>. The server default is <IC>4,6</IC>.</P>
        <Table
          head={["", "IPv4", "IPv6"]}
          rows={[
            ["Pod subnet per node", "10.88.N.0/24", "fd00:88:0:N::/64"],
            ["Service ClusterIPs", "10.96.0.0/16", "fd00:96::/112"],
          ]}
        />
        <UL>
          <LI>Pods get an address in each configured family. Services honour <IC>ipFamilies</IC> and <IC>ipFamilyPolicy</IC>, with AAAA records and per-family EndpointSlices.</LI>
          <LI>Hosts may be IPv4, IPv6 or both: joining, Raft, the kubelet API and VXLAN all run over an IPv6 underlay.</LI>
          <LI>Changing the families of an existing cluster is supported by restarting it with the new setting (<IC>tools/test/families-change.sh</IC>).</LI>
        </UL>
      </Section>

      <Section>
        <H2>Services</H2>
        <P>
          ClusterIP, NodePort and hostPort are implemented by the in-process service proxy, with ClientIP session
          affinity. ExternalName services are answered by DNS. Services and Endpoints are tracked per family.
        </P>
      </Section>

      <Section>
        <H2>Cluster DNS</H2>
        <P>
          A small authoritative DNS server runs inside <IC>kr</IC> for the <IC>cluster.local</IC> domain (change it
          with <IC>KR_CLUSTER_DOMAIN</IC>): Service and pod records, SRV records for named ports, headless services
          and ExternalName. Pods find it through the <IC>resolv.conf</IC> the kubelet writes for them.
        </P>
        <CopyBlock
          command={`kubectl run dns --rm -it --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 -- nslookup kubernetes.default`}
        />
      </Section>

      <Section>
        <H2>Environment variables</H2>
        <Table
          head={["Variable", "Effect"]}
          rows={[
            ["KR_NET_BACKEND", "vxlan (default) or host-gw."],
            ["KR_POD_FAMILIES", "4, 6 or 4,6."],
            ["KR_CLUSTER_DOMAIN", "The DNS domain, default cluster.local."],
            ["KR_PREFER_IPV6", "Use the host's IPv6 address as the node address when it has both."],
          ]}
        />
      </Section>
    </DocsLayout>
  );
}

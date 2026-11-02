import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Note } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsHa() {
  return (
    <DocsLayout>
      <H1>High availability</H1>
      <Lead>
        Three or more servers replicate the datastore with a built-in Raft. There is no etcd to run.
      </Lead>

      <Section>
        <H2>Start a cluster</H2>
        <CopyBlock
          command={`# first server
kr server --cluster-init --data /var/lib/kr

# additional servers
kr server --server https://FIRST:6443 --token-file F --data /var/lib/kr`}
        />
        <P>
          <IC>--cluster-init</IC> bootstraps a Raft group of one. Further servers join through any existing member
          using a token. With three servers the cluster tolerates the loss of one.
        </P>
      </Section>

      <Section>
        <H2>How it behaves</H2>
        <UL>
          <LI>The replicated log is the datastore's append-only log; Raft ships the same records every server applies.</LI>
          <LI>Writes go through the leader. Reads are linearizable on followers too, by a ReadIndex round trip against the leader's lease.</LI>
          <LI>Reads with an explicit <IC>resourceVersion</IC>, and watches, are served from the local applied state without a barrier.</LI>
          <LI>Agents and kubectl can talk to any server.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Limits to know about</H2>
        <UL>
          <LI>Membership changes are one server at a time, the safe single-server protocol. A server whose IP changes while running needs a restart.</LI>
          <LI>Linearizable reads rely on a leader lease, which assumes bounded clock drift between servers.</LI>
          <LI>Snapshots are sent in one message with a 512 MB frame limit. Chunked snapshots are planned if image state grows.</LI>
        </UL>
        <Note>
          Run <IC>tools/test/ha.sh</IC> to bring up a three-server cluster in containers and exercise failover.
        </Note>
      </Section>
    </DocsLayout>
  );
}

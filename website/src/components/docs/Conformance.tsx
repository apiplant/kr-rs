import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsConformance() {
  return (
    <DocsLayout>
      <H1>Conformance</H1>
      <Lead>
        kr runs the CNCF conformance suite for Kubernetes v1.37 with Sonobuoy, in the{" "}
        <IC>non-disruptive-conformance</IC> mode, in parallel.
      </Lead>

      <Section>
        <H2>Results</H2>
        <Table
          head={["Cluster", "Result"]}
          rows={[
            ["2 nodes (server and agent)", "460 of 460 specs"],
            ["1 node", "458 of 460. The other 2 specs need a second node and cannot pass on one."],
          ]}
        />
        <P>
          This is a passing run, not a certification: the CNCF submission process has not been done. A first image pull
          on a cold image store can take longer than a spec's 300-second timeout. Run once to warm the store, or use a
          registry mirror, before reading failures as real.
        </P>
      </Section>

      <Section>
        <H2>Reproduce it</H2>
        <CopyBlock
          command={`tools/test/conformance.sh run full               # one node, in a throwaway container
KR_NODES=2 tools/test/conformance.sh run full    # server plus agent
tools/test/conformance.sh run focus 'Aggregator.*\\[Conformance\\]'   # a subset
tools/test/conformance.sh status
tools/test/conformance.sh wait
tools/test/conformance.sh results /tmp/out       # failures by area`}
        />
        <UL>
          <LI>It needs Docker, kubectl and sonobuoy on the host, and a release build at <IC>target/release/kr</IC>.</LI>
          <LI>A full run takes about 45 minutes and a few GB of free memory.</LI>
          <LI>Failed test names land in <IC>failed-tests.txt</IC> and the full log in <IC>plugins/e2e/results/global/e2e.log</IC>.</LI>
          <LI>Sonobuoy's progress counter stays at 0 with kr; count passes and failures from the e2e log for a live view.</LI>
        </UL>
      </Section>
    </DocsLayout>
  );
}

import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, IC, Section, Table } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsDevelopment() {
  return (
    <DocsLayout>
      <H1>Development</H1>
      <Lead>Build, test and the scripts that exercise real clusters in containers.</Lead>

      <Section>
        <H2>Build and unit tests</H2>
        <CopyBlock
          command={`cargo build --release
tools/test/unit.sh            # every library crate (the kr binary itself has no unit tests)
cargo test --workspace`}
        />
        <P>
          Use <IC>tools/test/unit.sh</IC>, not summed <IC>cargo test</IC> output: it fails on any crash or abort.
        </P>
      </Section>

      <Section>
        <H2>Cluster tests</H2>
        <P>These start real servers and agents, mostly in privileged Docker containers, and need a release build.</P>
        <Table
          head={["Script", "What it checks"]}
          rows={[
            ["two-node.sh up", "A server (kr1) and an agent (kr2) in Docker."],
            ["conformance.sh", "The Sonobuoy conformance suite."],
            ["ha.sh", "A three-server Raft cluster."],
            ["stress.sh", "Databases, volumes, Services, a third node joining, rolling updates, drain and a frozen node."],
            ["failure.sh", "Binary swap, killed shim, recycled-pid records, a crash loop, a crash mid-creation, a second agent."],
            ["soak.sh", "200 pods, churn with agent crashes, and leak accounting."],
            ["vxlan.sh", "The VXLAN backend."],
            ["dualstack.sh, families.sh, families-change.sh", "Dual-stack pods, Services and DNS; changing families."],
            ["aggregated-watch.sh", "A watch through an aggregated API."],
            ["rootless-*.sh", "Rootless egress, IPv6, families and survival of a restart."],
            ["aarch64.sh", "A cross-build smoke test under qemu-user."],
          ]}
        />
      </Section>

      <Section>
        <H2>Conventions</H2>
        <P>
          Every architecture decision is written down as an ADR in <IC>docs/DECISIONS.md</IC>. Fixed bugs move to{" "}
          <IC>docs/RESOLVED_ISSUES.md</IC> and open items live in <IC>docs/KNOWN_ISSUES.md</IC>. The design and size
          budgets are in <IC>docs/PLAN.md</IC>. Do not change host-global sysctls from a test.
        </P>
      </Section>
    </DocsLayout>
  );
}

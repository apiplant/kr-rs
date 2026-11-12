import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, UL, LI, IC, Section } from "./Prose";

export function DocsLimitations() {
  return (
    <DocsLayout>
      <H1>Limitations</H1>
      <Lead>What kr does not do, or does only partly. The full list is in <IC>docs/KNOWN_ISSUES.md</IC>.</Lead>

      <Section>
        <H2>Scope</H2>
        <UL>
          <LI>Not certified by the CNCF. The suite passes, but the certification process has not been run.</LI>
          <LI>Linux only, on x86_64 and aarch64. The aarch64 build is cross-compiled and runs under qemu-user for tests; the runtime paths (namespaces, cgroups, <IC>clone3</IC>, mounts) need a real aarch64 host and are not yet exercised in CI.</LI>
          <LI>Built-in storage is the local provisioner. There is no network storage driver.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Security</H2>
        <UL>
          <LI>Only ECDSA P-256 keys for pod certificates; RSA is verify-only.</LI>
          <LI>P-256 scalar multiplication costs about 0.5 ms to sign and 0.95 ms to verify. Fast enough for current handshake rates; revisited if that changes.</LI>
        </UL>
      </Section>

      <Section>
        <H2>High availability</H2>
        <UL>
          <LI>One membership change at a time; a server whose IP changes while running needs a restart.</LI>
          <LI>Linearizable reads rely on a leader lease and assume bounded clock drift between servers.</LI>
          <LI>Snapshots are sent whole, within a 512 MB frame limit.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Rootless and restarts</H2>
        <UL>
          <LI>In rootless mode the host cannot reach pod IPs directly: use port-forward or the API server's pod proxy.</LI>
          <LI>A running <IC>kubectl exec</IC> or <IC>attach</IC> session ends when the kubelet process restarts.</LI>
          <LI>The first upgrade onto a build that supports surviving restarts needs a drain; see <a class="text-accent hover:text-accent-dim" href="/docs/operations">Operations</a>.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Footprint</H2>
        <UL>
          <LI>The binary is about 4.9 MB on x86_64; size is measured before large features are added.</LI>
          <LI>With very small pods the 32 MiB watch history keeps about 4,000 events; a client that falls behind gets <IC>410 Expired</IC>.</LI>
          <LI>Each running container has a shim of about 1 MB.</LI>
        </UL>
      </Section>
    </DocsLayout>
  );
}

import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, FlagTable } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsCtr() {
  return (
    <DocsLayout>
      <H1>kr ctr</H1>
      <Lead>Run containers without Kubernetes, using the same image store and runtime the kubelet uses.</Lead>

      <Section>
        <H2>Examples</H2>
        <CopyBlock
          command={`kr ctr pull docker.io/library/busybox
kr ctr run --memory 64Mi --cpus 500m docker.io/library/busybox -- echo hello
kr ctr run --pids 64 --user 1000:1000 docker.io/library/busybox -- id`}
        />
        <P>
          <IC>kr ctr run</IC> pulls the image if it is not already in the store, unpacks it, applies the limits and
          runs the command in new namespaces. It exits with the container's exit code.
        </P>
      </Section>

      <Section>
        <H2>Commands</H2>
        <FlagTable
          rows={[
            { flag: "kr ctr pull IMAGE", meaning: "Pull an image into the local store." },
            { flag: "kr ctr run [limits] IMAGE [--] CMD...", meaning: "Run a command in a container made from the image." },
            { flag: "kr ctr run-dir [limits] ROOTFS STATE-DIR [--] CMD...", meaning: "Run a command in an already unpacked root filesystem." },
          ]}
        />
        <H2>Limits and options</H2>
        <FlagTable
          rows={[
            { flag: "--memory 64Mi", meaning: "Memory limit (cgroup v2 memory.max)." },
            { flag: "--cpus 500m", meaning: "CPU limit, in cores or millicores." },
            { flag: "--pids 64", meaning: "Maximum number of processes." },
            { flag: "--user uid[:gid]", meaning: "Run as this user." },
          ]}
        />
      </Section>

      <Section>
        <H2>Notes</H2>
        <UL>
          <LI>Images and state live under <IC>KR_ROOT</IC>, shared with the kubelet on the same machine.</LI>
          <LI>As root, containers get a veth and egress NAT. As a normal user they run <a class="text-accent hover:text-accent-dim" href="/docs/rootless">rootless</a>, with egress through a userspace NAT.</LI>
          <LI>Registry mirrors are set with <IC>KR_REGISTRY_MIRRORS</IC>.</LI>
          <LI>Unlike pods, a <IC>kr ctr run</IC> container is tied to the command that started it and does not outlive it.</LI>
        </UL>
      </Section>
    </DocsLayout>
  );
}

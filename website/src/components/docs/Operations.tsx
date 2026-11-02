import { DocsLayout } from "./DocsLayout";
import { H1, H2, H3, Lead, P, UL, LI, IC, Section, Note, Table } from "./Prose";
import { CopyBlock } from "../Code";

const link = "text-accent hover:text-accent-dim";

export function DocsOperations() {
  return (
    <DocsLayout>
      <H1>Operations</H1>
      <Lead>
        Run kr under systemd, upgrade the binary without stopping pods, and know what happens when things fail.
      </Lead>

      <Section>
        <H2>systemd</H2>
        <P>Unit files are in <IC>tools/systemd</IC>: <IC>kr-server.service</IC> and <IC>kr-agent.service</IC>.</P>
        <CopyBlock
         
          command={`[Service]
ExecStart=/usr/local/bin/kr server --data /var/lib/kr
Restart=always
RestartSec=2
KillMode=process      # pods survive a stop or restart (ADR-036)
Delegate=yes          # let kr create the pod cgroups under this unit
TasksMax=infinity
LimitNOFILE=1048576
OOMScoreAdjust=-999`}
        />
        <Note title="KillMode=process is required">
          Containers, their shims and pod sandboxes are children of the unit's cgroup. With systemd's default{" "}
          <IC>control-group</IC>, stopping the service kills all of them. This is the same setting k3s uses.
        </Note>
      </Section>

      <Section>
        <H2>Pods keep running while kr is replaced</H2>
        <P>
          Restarting, crashing or replacing <IC>kr server</IC> or <IC>kr agent</IC> does not stop the pods on the
          node. Each container has a small <IC>kr shim</IC> parent process. It reaps the container, writes its exit
          status to a file, copies a terminal's output into the log, and hands the terminal or stdin descriptor to a
          restarted kubelet over a unix socket. The pod sandbox is its own process. A restarted kubelet reads the{" "}
          <IC>.adopt</IC> record in each pod directory and takes the pod over.
        </P>
        <Table
          head={["Carried over", "How"]}
          rows={[
            ["IP address and network namespace", "The lease and the sandbox are re-claimed."],
            ["Processes and open connections", "Nothing restarts; pids are checked against their start times so a recycled pid is never taken over."],
            ["Exit code of a container that ended meanwhile", "Read from the shim's exit file. Only a killed shim gives the unknown code 255."],
            ["Terminal output and stdin", "Fetched from the shim's socket; `attach -i` works again right away."],
            ["Restart counts, init containers, readiness", "Rebuilt from the pod's status in the API."],
          ]}
        />
        <P>
          A one-minute crash loop, a <IC>kill -9</IC> of the agent, a binary swap with SIGTERM, a crash in the middle
          of creating twelve pods and a second agent started on the same root were all tested. Adopting 200 pods after
          a <IC>kill -9</IC> takes about 9 seconds, and each shim is about 1 MB resident.
        </P>
        <H3>Guard rails</H3>
        <UL>
          <LI>One kubelet per root: a <IC>kubelet.lock</IC> file lock makes a second <IC>kr agent</IC> or <IC>kr server</IC> on the same root exit.</LI>
          <LI>At start kr checks the kernel for <IC>pidfd_open</IC>, <IC>clone3</IC> and <IC>close_range</IC> (Linux 5.9). If one is missing it says so and runs containers as its own children, as before; pods then die with the process.</LI>
          <LI>A pod directory with no record has whatever runs in its cgroup killed before it starts. Directories and leases of pods deleted while the node was down are removed after the first sync.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Upgrading kr</H2>
        <CopyBlock
          command={`install -m755 kr.new /usr/local/bin/kr     # running processes keep the old file open
systemctl restart kr-agent                  # or kr-server
journalctl -u kr-agent | grep adopted
# kubelet: adopted N pods (M running containers) left by the previous run`}
        />
        <UL>
          <LI>Rolling back is the same procedure. The <IC>.adopt</IC> record format is versioned and only ever extended: older readers ignore new trailing fields and record kinds.</LI>
          <LI>Shims and <IC>kr egress</IC> helpers keep running the binary they were started from until their container ends. They speak no protocol with the kubelet beyond a unix socket that hands out one descriptor, so mixing versions is safe.</LI>
        </UL>
        <Note title="The first upgrade onto a build with this feature needs a drain">
          Earlier builds start containers with a kernel death signal tied to the agent, set inside the container, which
          nothing can clear from outside. Once, drain the node, replace the binary, restart and uncordon:
          <CopyBlock command={`kubectl drain NODE --ignore-daemonsets --delete-emptydir-data\n# replace the binary and restart the service\nkubectl uncordon NODE`} />
          Every later upgrade can skip the drain.
        </Note>
        <H3>What is not preserved</H3>
        <UL>
          <LI>A running <IC>kubectl exec</IC> or <IC>attach</IC> session ends with the old process. Reconnect.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Node failure</H2>
        <P>
          See <a class={link} href="/docs/nodes">Nodes and tokens</a> for the timings: Unknown after 40 s, taints at
          once, evictions after 300 s unless a pod says otherwise. A frozen node was tested: it goes NotReady, its
          pods are evicted and rescheduled, and when it returns it becomes Ready, its taints are removed and its pods
          are Ready again.
        </P>
      </Section>

      <Section>
        <H2>Environment variables</H2>
        <Table
          head={["Variable", "Effect"]}
          rows={[
            ["KR_ROOT", "Where images, pod state and IP leases live. Default /var/lib/kr as root."],
            ["KR_TOKEN", "The join token for kr agent, instead of --token."],
            ["KR_REGISTRY_MIRRORS", "Pull-through mirrors: registry=URL pairs, comma-separated."],
            ["KR_NET_BACKEND", "vxlan or host-gw."],
            ["KR_POD_FAMILIES", "4, 6 or 4,6."],
            ["KR_CLUSTER_DOMAIN", "DNS domain, default cluster.local."],
            ["KR_NODE_CERT_SECONDS", "Lifetime of node certificates the server issues."],
            ["KR_EVICTION_MEMORY_AVAILABLE", "Memory-pressure eviction threshold."],
            ["KR_CA_BUNDLE", "A PEM file of trust anchors for registries, instead of the system bundle."],
          ]}
        />
      </Section>
    </DocsLayout>
  );
}

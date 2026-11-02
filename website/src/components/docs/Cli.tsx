import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, IC, Section, FlagTable, Table } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsCli() {
  return (
    <DocsLayout>
      <H1>CLI reference</H1>
      <Lead>
        <IC>kr</IC> is one multicall binary. The first argument chooses the role.
      </Lead>

      <Section>
        <Table
          head={["Command", "Purpose"]}
          rows={[
            ["kr server", "Control plane, and the first node."],
            ["kr agent", "A worker node."],
            ["kr token create", "Create a bootstrap token for a new node."],
            ["kr ctr", "Pull and run containers without Kubernetes."],
            ["kr pki", "Create a CA and issue certificates."],
            ["kr version", "Print the version."],
          ]}
        />
        <P>
          Running <IC>kr</IC> with no arguments prints the usage line. <IC>kr shim</IC>, <IC>kr egress</IC> and{" "}
          <IC>kr pause</IC> are internal helper roles that kr starts itself; do not run them by hand.
        </P>
      </Section>

      <Section>
        <H2 id="server">kr server</H2>
        <CopyBlock command={`kr server [--port 6443] [--data DIR] [--cluster-init | --server https://HOST:6443 [--token-file FILE | --token TOKEN]]`} />
        <FlagTable
          rows={[
            { flag: "--port", meaning: <>API port, default <IC>6443</IC>.</> },
            { flag: "--data DIR", meaning: <>Cluster state: <IC>pki/</IC>, <IC>db/</IC>, <IC>admin.kubeconfig</IC>. Default <IC>$KR_ROOT/server</IC>, else <IC>/var/lib/kr/server</IC>.</> },
            { flag: "--cluster-init", meaning: "Start a Raft-replicated cluster of one, ready for more servers to join." },
            { flag: "--server URL", meaning: "Join an existing cluster as an additional server." },
            { flag: "--token-file FILE, --token TOKEN", meaning: "The join token for --server." },
          ]}
        />
        <P>
          On first start it creates the cluster CA, the API server certificate and the admin credentials. The server
          also runs the kubelet and service proxy for its own node.
        </P>
      </Section>

      <Section>
        <H2 id="agent">kr agent</H2>
        <CopyBlock command={`kr agent --server https://HOST:6443 [--token-file FILE | --token TOKEN] [--data DIR]`} />
        <FlagTable
          rows={[
            { flag: "--server URL", meaning: "The API server to join (required)." },
            { flag: "--token-file FILE", meaning: "Read the join token from a file. Preferred." },
            { flag: "--token TOKEN", meaning: "The token on the command line. Visible in /proc/PID/cmdline; kr warns." },
            { flag: "KR_TOKEN", meaning: "The token in the environment." },
            { flag: "--data DIR", meaning: <>Agent state. Default <IC>$KR_ROOT/agent</IC>, else <IC>/var/lib/kr/agent</IC>.</> },
          ]}
        />
      </Section>

      <Section>
        <H2 id="token">kr token</H2>
        <CopyBlock command={`kr token create [--ttl DURATION] [--data DIR] [--server https://127.0.0.1:6443]`} />
        <FlagTable
          rows={[
            { flag: "--ttl", meaning: <>Lifetime, default <IC>24h</IC>. <IC>0</IC> never expires.</> },
            { flag: "--data DIR", meaning: "The server's data directory, to read its admin credentials." },
            { flag: "--server URL", meaning: "The API server to ask." },
          ]}
        />
      </Section>

      <Section>
        <H2 id="ctr">kr ctr</H2>
        <CopyBlock
          command={`kr ctr pull <image>
kr ctr run [--memory 64Mi] [--cpus 500m] [--pids 64] [--user uid[:gid]] <image> [--] [cmd args...]
kr ctr run-dir [limits...] <rootfs> <state-dir> [--] <cmd> [args...]`}
        />
        <P>See <a class="text-accent hover:text-accent-dim" href="/docs/ctr">kr ctr</a>.</P>
      </Section>

      <Section>
        <H2 id="pki">kr pki</H2>
        <CopyBlock
          command={`kr pki ca <dir> [--cn name] [--days 3650]
kr pki issue <dir> <name> [--cn cn] [--org o]... [--dns name]... [--ip addr]... [--server] [--client] [--days 365]`}
        />
        <P>
          Create a certificate authority in a directory, then issue server or client certificates from it, with
          subject alternative names. The server uses the same code to build its own PKI.
        </P>
      </Section>

      <Section>
        <H2>Environment</H2>
        <P>
          See <a class="text-accent hover:text-accent-dim" href="/docs/operations">Operations</a> for the full list of{" "}
          <IC>KR_*</IC> variables.
        </P>
      </Section>
    </DocsLayout>
  );
}

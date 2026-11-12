import { DocsLayout } from "./DocsLayout";
import { H1, H2, H3, Lead, P, UL, LI, IC, Section, Note } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsQuickstart() {
  return (
    <DocsLayout>
      <H1>Quick start</H1>
      <Lead>Build the binary, start a server, and run a workload.</Lead>

      <Section>
        <H2>Requirements</H2>
        <UL>
          <LI>Linux 5.10 or newer, x86_64 or aarch64.</LI>
          <LI>cgroup v2 and overlayfs.</LI>
          <LI>Root, for pod networking and cgroup limits. Without it, see <a class="text-accent hover:text-accent-dim" href="/docs/rootless">rootless mode</a>.</LI>
          <LI>To build: a Rust nightly toolchain. There are no other build dependencies.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Install</H2>
        <P>
          Packages for Debian and Ubuntu (amd64, arm64), Arch Linux (x86_64) and Homebrew on Linux come from the
          apiplant repositories. They install <IC>/usr/bin/kr</IC> and the systemd units, without enabling them.
        </P>
        <CopyBlock
          command={`# Debian / Ubuntu
curl -sSfL https://apt.apiplant.com/apiplant-archive-keyring.gpg | sudo tee /usr/share/keyrings/apiplant.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/apiplant.gpg] https://apt.apiplant.com stable main" | sudo tee /etc/apt/sources.list.d/apiplant.list > /dev/null
sudo apt update && sudo apt install kr-rs

# Homebrew on Linux
brew tap apiplant/tap && brew install apiplant/tap/kr-rs`}
        />
        <P>
          Or take a static archive from the{" "}
          <a class="text-accent hover:text-accent-dim" href="https://github.com/apiplant/kr-rs/releases">releases page</a>:{" "}
          <IC>kr-rs-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz</IC> or{" "}
          <IC>kr-rs-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz</IC>. Each has a <IC>.sha256</IC> file. The{" "}
          <a class="text-accent hover:text-accent-dim" href="/#install">home page</a> has the Arch setup.
        </P>
        <Note title="Apple Silicon">
          kr needs a Linux kernel, so there is no macOS build. On an Apple Silicon Mac, run the aarch64 Linux package
          or archive inside a Linux VM (Lima, Colima, UTM, or the VM behind Docker Desktop). Inside the VM it is an
          ordinary aarch64 Linux install.
        </Note>
      </Section>

      <Section>
        <H2>Or build from source</H2>
        <CopyBlock command={`cargo build --release          # produces target/release/kr (about 4.9 MB)`} />
      </Section>

      <Section>
        <H2>A single node</H2>
        <CopyBlock
          command={`sudo target/release/kr server --data /var/lib/kr &      # API on :6443; the node registers itself
export KUBECONFIG=/var/lib/kr/admin.kubeconfig   # the admin credentials, mode 0600
kubectl get nodes
kubectl run hello --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 -- netexec
kubectl get pods -o wide`}
        />
        <P>
          The server is also the first node: it runs the kubelet and the service proxy in-process, so a single
          command gives you a cluster you can schedule onto. The control-plane node carries the
          <IC>control-plane</IC> role label; agents have none.
        </P>
        <P>
          <IC>--data</IC> holds the cluster PKI (<IC>pki/</IC>), the datastore (<IC>db/</IC>) and{" "}
          <IC>admin.kubeconfig</IC>. It defaults to <IC>$KR_ROOT/server</IC>, else <IC>/var/lib/kr/server</IC> as
          root. Container images, pod state and IP leases are stored under <IC>KR_ROOT</IC> (default{" "}
          <IC>/var/lib/kr</IC> as root, else <IC>~/.local/share/kr</IC>).
        </P>
      </Section>

      <Section>
        <H2>A first workload</H2>
        <CopyBlock
          command={`kubectl create deployment web --image=registry.k8s.io/e2e-test-images/agnhost:2.66.1 --replicas=3 -- /agnhost netexec
kubectl expose deployment web --port=80 --target-port=8080
kubectl get pods,svc -o wide
kubectl scale deployment web --replicas=10
kubectl rollout status deployment web`}
        />
        <P>
          With images already pulled, a 100-pod Deployment reaches Running in about two seconds on one node. The first
          use of an image pulls it from its registry; see{" "}
          <a class="text-accent hover:text-accent-dim" href="/docs/runtime#images">images and mirrors</a>.
        </P>
        <H3>Look inside</H3>
        <CopyBlock
          command={`kubectl logs deploy/web
kubectl exec -it deploy/web -- /bin/sh
kubectl port-forward svc/web 8080:80`}
        />
        <P><IC>exec</IC>, <IC>attach</IC>, <IC>logs</IC> and <IC>port-forward</IC> work over WebSocket and SPDY.</P>
      </Section>

      <Section>
        <H2>Add a second node</H2>
        <CopyBlock
          command={`# on the server
kr token create --ttl 24h --data /var/lib/kr

# on the new machine
sudo kr agent --server https://SERVER:6443 --token TOKEN`}
        />
        <P>
          Continue with <a class="text-accent hover:text-accent-dim" href="/docs/nodes">nodes and tokens</a>.
        </P>
      </Section>

      <Section>
        <H2>Run it as a service</H2>
        <P>
          Do not leave the server in a shell. Install the unit files from <IC>tools/systemd</IC>; they set{" "}
          <IC>KillMode=process</IC>, which is required for pods to keep running across restarts.
        </P>
        <Note title="Do not skip KillMode=process">
          systemd's default, <IC>control-group</IC>, kills every process in the unit's cgroup when the service
          stops, including the containers. See <a class="text-accent hover:text-accent-dim" href="/docs/operations">Operations</a>.
        </Note>
      </Section>
    </DocsLayout>
  );
}

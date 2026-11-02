import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section, Table, Note } from "./Prose";
import { CopyBlock } from "../Code";

export function DocsRuntime() {
  return (
    <DocsLayout>
      <H1>Containers and pods</H1>
      <Lead>
        The kubelet calls the container runtime in-process. There is no CRI, no containerd and no runc.
      </Lead>

      <Section>
        <H2 id="images">Images</H2>
        <UL>
          <LI>OCI image pull over the registry v2 protocol, with gzip layers and a content-addressed store.</LI>
          <LI>Layers are unpacked safely using <IC>openat2</IC>, with whiteouts handled and paths sanitized.</LI>
          <LI>Each image has a flattened rootfs; each container gets a per-container overlayfs on top.</LI>
        </UL>
        <P>Pull-through mirrors are opt-in, per registry:</P>
        <CopyBlock command={`KR_REGISTRY_MIRRORS=registry.k8s.io=http://host:5000,docker.io=https://cache:5000 kr server`} />
        <P>
          Pods that need an image that is still being pulled stay in <IC>ContainerCreating</IC> with a "pulling image"
          reason. A big image on a slow link can take minutes; probes and timeouts start after the pull.
        </P>
      </Section>

      <Section>
        <H2>Isolation</H2>
        <UL>
          <LI>User, mount, PID, network, IPC, UTS and cgroup namespaces; <IC>pivot_root</IC> into the rootfs.</LI>
          <LI>seccomp filter and capability dropping, with the securityContext honoured.</LI>
          <LI>cgroup v2 limits for CPU, memory and PIDs, per pod and per container, with in-place pod resize.</LI>
          <LI>A pod's cgroup is killed as a unit with <IC>cgroup.kill</IC>, so nothing outlives it.</LI>
          <LI>Memory-pressure eviction (<IC>KR_EVICTION_MEMORY_AVAILABLE</IC>) and OOM kills are reported with the right exit reason.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Pod features</H2>
        <UL>
          <LI>Probes: HTTP, TCP, exec and gRPC. Lifecycle hooks, init containers, sidecars and ephemeral containers.</LI>
          <LI><IC>exec</IC>, <IC>attach</IC>, <IC>logs</IC> and <IC>port-forward</IC> over WebSocket and SPDY, relayed through the API server to the node.</LI>
          <LI>Standard <IC>/dev</IC> entries, including <IC>/dev/fd</IC>, <IC>/dev/stdin</IC> and <IC>/dev/ptmx</IC>, so tools such as PostgreSQL's <IC>initdb</IC> work.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Volumes</H2>
        <Table
          head={["Volume", "Notes"]}
          rows={[
            ["emptyDir", "Scratch space for the life of the pod."],
            ["hostPath", "A path on the node."],
            ["configMap, secret", "Mounted from the API; secrets include stringData."],
            ["downwardAPI", "Pod and container fields."],
            ["projected", "ServiceAccount token, configMap, secret, ClusterTrustBundle and pod certificate."],
            ["persistentVolumeClaim", "Provisioned by the built-in local provisioner, or bound to a pre-created PV."],
            ["image", "An OCI image mounted as a volume."],
          ]}
        />
        <Note>
          The built-in provisioner stores data on the node's disk. A PVC bound to a volume on one node pins its pod
          to that node. There is no network storage driver.
        </Note>
      </Section>

      <Section>
        <H2>Pods keep running while kr restarts</H2>
        <P>
          Every container runs under a tiny <IC>kr shim</IC> parent, and the pod sandbox is its own process. When
          the kubelet restarts, crashes or is replaced by a newer binary, the pods stay up and the new process adopts
          them: IP address, processes, open connections, the container's exit status and its terminal log all carry
          over. Details, the guard rails and how to upgrade are in{" "}
          <a class="text-accent hover:text-accent-dim" href="/docs/operations">Operations</a>.
        </P>
      </Section>
    </DocsLayout>
  );
}

import { DocsLayout } from "./DocsLayout";
import { H1, H2, Lead, P, UL, LI, IC, Section } from "./Prose";

const link = "text-accent hover:text-accent-dim";

export function DocsApi() {
  return (
    <DocsLayout>
      <H1>Kubernetes API</H1>
      <Lead>
        What <IC>kr server</IC> serves: Kubernetes API v1.37, as JSON and protobuf, with watches, chunked lists,
        Tables and aggregated discovery.
      </Lead>

      <Section>
        <H2>API groups</H2>
        <P>
          Core, apps, batch, autoscaling, policy, networking, storage, RBAC, certificates, coordination, discovery,
          flowcontrol, scheduling, resource (DRA), events and more. The protobuf schema tables are generated from
          the upstream <IC>.proto</IC> files and compiled into the binary, so clients that negotiate protobuf get it.
        </P>
      </Section>

      <Section>
        <H2>Datastore</H2>
        <UL>
          <LI>An embedded append-only log with MVCC revisions and compaction, in place of etcd. Writes are group-committed with the fsync off the event loop.</LI>
          <LI>Optional Raft replication for three or more servers: see <a class={link} href="/docs/ha">High availability</a>.</LI>
          <LI>The watch history, the recent writes kept so a watch can resume, is capped at 32 MiB. Memory under sustained writes levels off instead of growing. A watch that falls behind gets <IC>410 Expired</IC>, as on upstream.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Writing objects</H2>
        <UL>
          <LI>Server-side apply with managed fields and conflicts, strategic merge patch, JSON patch and merge patch.</LI>
          <LI>Strict field validation and defaulting.</LI>
          <LI>Secret <IC>stringData</IC> is folded into base64 <IC>data</IC> on create and update.</LI>
        </UL>
      </Section>

      <Section>
        <H2>CustomResourceDefinitions</H2>
        <P>
          Structural schemas, CEL validation rules, defaulting, pruning, selectable fields, the status and scale
          subresources, and conversion with strategy <IC>None</IC> or a webhook. Objects written before a storage
          version change keep their stored version until a <IC>StorageVersionMigration</IC> rewrites them.
        </P>
      </Section>

      <Section>
        <H2>Admission</H2>
        <UL>
          <LI>Validating and mutating admission webhooks, called over TLS with failure policy, selectors and timeouts.</LI>
          <LI>ValidatingAdmissionPolicy and MutatingAdmissionPolicy, written in CEL.</LI>
          <LI>Pod Security admission, built in.</LI>
          <LI>ResourceQuota, LimitRange, priority classes and ServiceAccount.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Authentication and authorization</H2>
        <UL>
          <LI>Client certificates, bootstrap tokens, signed ServiceAccount tokens (TokenRequest, projected, audience-bound), TokenReview and impersonation.</LI>
          <LI>RBAC and the Node authorizer, with SubjectAccessReview and the self-service review APIs.</LI>
          <LI>Pod certificates (<IC>PodCertificateRequest</IC> and projected <IC>podCertificate</IC> volumes) and ClusterTrustBundles. Only ECDSA P-256 keys are issued.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Aggregation and flow control</H2>
        <UL>
          <LI>APIServices backed by a Service, with front-proxy authentication. Watches are relayed as streams.</LI>
          <LI>API priority and fairness: FlowSchemas classify requests into priority levels with concurrency limits and per-flow fair queues. A full queue returns 429 with <IC>Retry-After</IC>.</LI>
        </UL>
      </Section>

      <Section>
        <H2>Controllers and scheduler</H2>
        <UL>
          <LI>Deployment (rolling update with proportional scaling, rollback, history), ReplicaSet, ReplicationController, StatefulSet, DaemonSet, CronJob.</LI>
          <LI>Job, with success policies, indexed jobs, backoff per index and pod failure policy.</LI>
          <LI>Endpoints, EndpointSlice and mirroring; namespace lifecycle and garbage collection (orphan and foreground).</LI>
          <LI>PersistentVolume and claim provisioning with a built-in local provisioner; PodDisruptionBudget and eviction.</LI>
          <LI>Node lifecycle: NotReady detection, taints and eviction. See <a class={link} href="/docs/nodes">Nodes and tokens</a>.</LI>
          <LI>Scheduler: resource fit, node selectors and affinity, taints and tolerations, topology spread, extended resources and priority preemption.</LI>
        </UL>
      </Section>

      <Section>
        <H2>kubectl output</H2>
        <P>
          Server-side Tables give <IC>kubectl get</IC> proper columns for nodes (status and roles), pods (including
          waiting reasons such as <IC>ContainerCreating</IC>), Jobs, CronJobs, DaemonSets, PVCs, PVs and
          StorageClasses.
        </P>
      </Section>
    </DocsLayout>
  );
}

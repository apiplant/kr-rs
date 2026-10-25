# Conformance known issues

Failures of the Kubernetes v1.37 conformance suite (Sonobuoy `non-disruptive-conformance`, `E2E_PARALLEL=true`) against a single-node `kr server`, from `tools/test/conformance.sh`. Tracked overall as KNOWN_ISSUES #70; root causes found and fixed are recorded there with their own numbers.

**Round 7 (2026-10-25): 460 specs, 308 passed, 152 failed** (149 listed below; ginkgo reports 3 more without a failure block), 43 minutes, no hangs.

Regenerate the list after a run: `tools/test/conformance.sh results DIR`, then the failed-test names are in `DIR/failed-tests.txt`. Each entry below is the spec and the first failure message, shortened.

## Summary

| Area | Failures |
|---|---|
| Pod behaviour (kubelet) | 29 |
| API connectivity from pods (10.96.0.1 timeouts) | 14 |
| Workload controllers | 35 |
| Admission webhooks and CRDs | 15 |
| Networking and DNS | 14 |
| Missing or partial APIs | 23 |
| Validation and immutability | 4 |
| kubectl | 5 |
| Cluster shape (single-node test environment) | 2 |
| ClusterTrustBundle (fixed in 2cc219a, after this run) | 7 |
| Other | 1 |

## Pod behaviour (kubelet) (29)

All addressed since round 7 (KNOWN_ISSUES #104); to be confirmed by the next run.

- [sig-node] Container Lifecycle Hook when create a pod with lifecycle hook should execute poststart exec hook properly — `Timed out after 300.001s.`
- [sig-node] Container Lifecycle Hook when create a pod with lifecycle hook should execute poststart http hook properly — `Timed out after 300.000s.`
- [sig-node] Container Lifecycle Hook when create a pod with lifecycle hook should execute prestop exec hook properly — `Timed out after 300.001s.`
- [sig-node] Container Lifecycle Hook when create a pod with lifecycle hook should execute prestop http hook properly — `Timed out after 300.001s.`
- [sig-node] Container Runtime blackbox test on terminated container should report termination message from file when pod succeeds and TerminationMessagePolicy FallbackToLogsOnError is set — `Expected`
- [sig-node] Container Runtime blackbox test on terminated container should report termination message from log output if TerminationMessagePolicy FallbackToLogsOnError is set — `Expected`
- [sig-node] Container Runtime blackbox test on terminated container should report termination message if TerminationMessagePath is set as non-root user and at a non-default path — `Timed out after 500.847s.`
- [sig-node] ImageVolume should succeed with pod and pull policy of Always — `failed to execute command in pod test-pod, container test-container: command terminated with exit code 1: command terminated with exit code 1`
- [sig-node] InitContainer should not start app containers if init containers fail on a RestartAlways pod — `second init container should have reason PodInitializing: {"name":"init2","state":{"waiting":{"reason":"ContainerCreating"}},"lastState":{},"ready":false,"resta…`
- [sig-node] Kubelet when scheduling an agnhost Pod with hostAliases should write entries to /etc/hosts — `expected hosts file to contain entries from HostAliases. Got:`
- [sig-node] KubeletManagedEtcHosts should test kubelet managed /etc/hosts file — `/etc/hosts file should be kubelet managed (name: busybox-1, retries: 138). /etc/hosts contains "# Kubernetes-managed hosts file (kr).\n127.0.0.1\tlocalhost\n::1…`
- [sig-node] Pods Extended (pod generation) Pod Generation custom-set generation on new pods and graceful delete — `Expected`
- [sig-node] Pods Extended (pod generation) Pod Generation issue 500 podspec updates and verify generation and observedGeneration eventually converge — `failed to get pod "pod-generation-bc699d23-c1aa-4de6-af52-3589265dcff8": Get "https://10.96.0.1:443/api/v1/namespaces/pods-9080/pods/pod-generation-bc699d23-c1a…`
- [sig-node] Pods Extended (pod generation) Pod Generation pod generation should start at 1 and increment per update — `Expected`
- [sig-node] Pods should allow activeDeadlineSeconds to be updated — `Timed out after 300.001s.`
- [sig-node] Pods should support remote command execution over websockets — `Failed to open websocket to wss://10.96.0.1:443/api/v1/namespaces/pods-7852/pods/pod-exec-websocket-a1e23b7e-802c-4816-b59c-eef8901a87e8/exec?command=echo&comma…`
- [sig-node] PreStop should call prestop when killing a pod — `validating pre-stop.: timed out waiting for the condition`
- [sig-node] Probing container should *not* be restarted with a GRPC liveness probe — `pod container-probe-1665/test-grpc-04c83066-846c-4e32-a8d4-a323b1c0e05a - expected number of restarts: 0, found restarts: 4. Pod status: &PodStatus{Phase:Runnin…`
- [sig-node] Probing container with readiness probe should not be ready before initial delay and never restart — `Pod became ready before it's 15s initial delay`
- [sig-node] RuntimeClass should reject a Pod requesting a deleted RuntimeClass — `Timed out after 300.001s.`
- [sig-node] RuntimeClass should reject a Pod requesting a non-existent RuntimeClass — `unexpected error for pod rejection: should get forbidden error`
- [sig-node] RuntimeClass should schedule a Pod requesting a RuntimeClass and initialize its Overhead — `Expected`
- [sig-node] Sysctls should reject invalid sysctls — `Expected an error, got nil`
- [sig-node] Variable Expansion should allow substituting values in a volume subpath — `expected "0" in container output: Expected`
- [sig-node] Variable Expansion should fail substituting values in a volume subpath with absolute path — `while waiting for the pod container to fail: Timed out after 167.788s.`
- [sig-node] Variable Expansion should fail substituting values in a volume subpath with backticks — `while waiting for the pod container to fail: Timed out after 120.001s.`
- [sig-node] Variable Expansion should succeed in writing subpaths in container — `expected to be able to write to subpath`
- [sig-node] Variable Expansion should verify that a failing subpath expansion can be modified during the lifecycle of a container — `Failed after 0.216s.`
- [sig-scheduling] LimitRange should create a LimitRange with defaults and ensure pod has those defaults applied. — `resource memory expected 200Mi actual 0`

## API connectivity from pods (10.96.0.1 timeouts) (14)

- [sig-api-machinery] CustomResourceFieldSelectors (setup) CustomResourceFieldSelectors MUST list and watch custom resources matching the field selector — `context deadline exceeded`
- [sig-api-machinery] Garbage collector (setup) should not delete dependents that have both valid owner and owner that's waiting for dependents to be deleted — `context deadline exceeded`
- [sig-api-machinery] ResourceQuota should create a ResourceQuota and capture the life of a pod. — `Get "https://10.96.0.1:443/api/v1/namespaces/resourcequota-937/resourcequotas": context deadline exceeded`
- [sig-apps] CronJob (setup) should replace jobs when ReplaceConcurrent — `context deadline exceeded`
- [sig-apps] CronJob should schedule multiple jobs concurrently — `Failed to wait for active jobs in CronJob concurrent in namespace cronjob-1811: Get "https://10.96.0.1:443/apis/batch/v1/namespaces/cronjob-1811/cronjobs/concur…`
- [sig-apps] Deployment deployment should support proportional scaling — `Post "https://10.96.0.1:443/apis/apps/v1/namespaces/deployment-9212/deployments": dial tcp 10.96.0.1:443: i/o timeout`
- [sig-network] DNS should provide DNS for ExternalName services — `context deadline exceeded`
- [sig-network] DNS should provide DNS for services — `context deadline exceeded`
- [sig-node] Sysctls should support sysctls — `context deadline exceeded`
- [sig-scheduling] SchedulerPredicates validates resource limits of pods that are allowed to run — `context deadline exceeded`
- [sig-scheduling] SchedulerPredicates validates that NodeSelector is respected if not matching — `context deadline exceeded`
- [sig-storage] Projected configMap should be consumable from pods in volume with defaultMode set — `unable to create test configMap : Post "https://10.96.0.1:443/api/v1/namespaces/projected-1496/configmaps": dial tcp 10.96.0.1:443: i/o timeout`
- [sig-storage] Subpath Atomic writer volumes (setup) should support subpaths with projected pod — `while creating secret: Post "https://10.96.0.1:443/api/v1/namespaces/subpath-4888/secrets": dial tcp 10.96.0.1:443: i/o timeout`
- [sig-storage] Subpath (setup) Atomic writer volumes should support subpaths with downward pod — `wait for service account "default" in namespace "subpath-5296": timed out waiting for the condition`

## Workload controllers (35)

- [sig-api-machinery] Garbage collector should keep the rc around until all its pods are deleted if the deleteOptions says so — `expected no pods, got &v1.PodList{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ListMeta:v1.ListMeta{SelfLink:"", ResourceVersion:"16814", Continue:"", Remainin…`
- [sig-api-machinery] Garbage collector should orphan RS created by deployment when deleteOptions.PropagationPolicy is Orphan — `Failed to verify remaining deployments, rs, and pods: [remaining rs post mortem: &v1.ReplicaSetList{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ListMeta:v1.Li…`
- [sig-api-machinery] Garbage collector should orphan pods created by rc if delete options say so — `expect 50 pods, got 0 pods`
- [sig-apps] CronJob should support CronJob API operations — `patched object should have the applied annotation`
- [sig-apps] Daemon set should update pod when spec was updated and update strategy is RollingUpdate — `Expected`
- [sig-apps] Deployment RollingUpdateDeployment should delete old pods and create new ones — `error waiting for deployment "test-rolling-update-deployment" (got 1 / registry.k8s.io/e2e-test-images/agnhost:2.66.1) and new replica set "test-rolling-update-…`
- [sig-apps] Deployment deployment should support rollover
- [sig-apps] Job should adopt matching orphans and release non-matching pods — `wait for pod "adopt-release-ggt6w" to be readopted`
- [sig-apps] Job should allow to use a pod failure policy to ignore failure matching on DisruptionTarget condition — `failed to await for all pods to be ready for job: evicted-pod-ignore-on-disruption-condition/job-3080: Timed out after 900.000s.`
- [sig-apps] Job should allow to use the pod failure policy on exit code to fail the job early — `failed to ensure job failure in namespace: job-4656: Told to stop trying after 12.030s.`
- [sig-apps] Job should apply changes to a job status — `patched object should have the applied annotation`
- [sig-apps] Job should create pods for an Indexed job with completion indexes and specified hostname — `failed to ensure job completion in namespace: job-3001: Timed out after 908.134s.`
- [sig-apps] Job should execute all indexes despite some failing when using backoffLimitPerIndex — `Expected`
- [sig-apps] Job should manage the lifecycle of a job — `failed to ensure job completion in namespace: job-1408: Timed out after 900.000s.`
- [sig-apps] Job should mark indexes as failed when the FailIndex action is matched in podFailurePolicy — `Expected`
- [sig-apps] Job should run a job to completion when tasks sometimes fail and are locally restarted — `failed to ensure job completion in namespace: job-6462: Timed out after 900.001s.`
- [sig-apps] Job should terminate job execution when the number of failed indexes exceeds maxFailedIndexes — `Expected`
- [sig-apps] Job with successPolicy should succeeded when all indexes succeeded — `failed to ensure that job has SuccessCriteriaMet with SuccessPolicy reason condition: Timed out after 900.001s.`
- [sig-apps] Job with successPolicy succeededCount rule should succeeded even when some indexes remain pending — `failed to ensure that the job has SuccessCriteriaMet condition with SuccessPolicy rule: Timed out after 900.001s.`
- [sig-apps] Job with successPolicy succeededIndexes rule should succeeded even when some indexes remain pending — `failed to ensure that job has SuccessCriteriaMet with SuccessPolicy reason condition: Timed out after 900.001s.`
- [sig-apps] ReplicaSet Replace and Patch tests — `failed to see replicas of test-rs in namespace replicaset-9402 scale to requested amount of 3: timed out waiting for the condition`
- [sig-apps] ReplicaSet should adopt matching pods on creation and release no longer matching pods — `timed out waiting for the condition`
- [sig-apps] ReplicaSet should serve a basic image on each replica with a public image — `checking pod responses: Told to stop trying after 0.003s.`
- [sig-apps] ReplicationController should release no longer matching pods — `timed out waiting for the condition`
- [sig-apps] ReplicationController should serve a basic image on each replica with a public image — `checking pod responses: Told to stop trying after 0.025s.`
- [sig-apps] ReplicationController should surface a failure condition on a common issue like exceeded quota — `rc manager never added the failure condition for rc "condition-test": []v1.ReplicationControllerCondition(nil)`
- [sig-apps] StatefulSet Basic StatefulSet functionality [StatefulSetBasic] Scaling should happen in predictable order and halt if any stateful pod is unhealthy — `StatefulSet ss scaled unexpectedly scaled to 3 -> 0 replicas`
- [sig-apps] StatefulSet Basic StatefulSet functionality [StatefulSetBasic] Should recreate evicted statefulset — `Pod ss-0 expected to be re-created at least once`
- [sig-apps] StatefulSet Basic StatefulSet functionality [StatefulSetBasic] should list, patch and delete a collection of StatefulSets — `statefulset not using ssPatchImage. Is using registry.k8s.io/e2e-test-images/agnhost:2.55`
- [sig-scheduling] SchedulerPredicates validates that NodeSelector is respected if matching — `Expected`
- [sig-scheduling] SchedulerPreemption PreemptionExecutionPath runs ReplicaSets to verify preemption running path — `failed pod observation expectations: context deadline exceeded`
- [sig-scheduling] SchedulerPreemption PriorityClass endpoints verify PriorityClass endpoints can be operated with different HTTP methods — `expect a patch error on an immutable field`
- [sig-scheduling] SchedulerPreemption validates basic preemption works — `expected pod to be preempted, instead got pod &Pod{ObjectMeta:{pod0-0-sched-preemption-low-priority  sched-preemption-5196  476e1835-c46a-411f-8b99-194f3181b368…`
- [sig-scheduling] SchedulerPreemption validates lower priority pod preemption by critical pod — `expected pod to be preempted, instead got pod &Pod{ObjectMeta:{pod0-0-sched-preemption-low-priority  sched-preemption-2404  fe748ec3-a0f2-40cc-a9a0-91f842de8599…`
- [sig-scheduling] SchedulerPreemption validates pod disruption condition is added to the preempted pod — `Timed out after 300.001s.`

## Admission webhooks and CRDs (15)

- [sig-api-machinery] AdmissionWebhook should be able to deny attaching pod — `unexpected 'kubectl attach' error message. expected to contain "attaching to pod 'to-be-attached-pod' is not allowed", got "timed out waiting for command /usr/l…`
- [sig-api-machinery] AdmissionWebhook should honor timeout — `expect an HTTP/dial timeout error querying the slow webhook, got: "Internal error occurred: failed calling webhook \"allow-configmap-with-delay-webhook.k8s.io\"…`
- [sig-api-machinery] AdmissionWebhook should mutate custom resource with different stored version — `failed to patch custom resource cr-instance-1 in namespace: webhook-3661: the body is webhook.example.com/v1/e2e-test-webhook-3661-5563-crd but the URL addresse…`
- [sig-api-machinery] AdmissionWebhook should reject mutating webhook configurations with invalid match conditions — `create mutatingwebhookconfiguration should have been denied by the api-server`
- [sig-api-machinery] AdmissionWebhook should reject validating webhook configurations with invalid match conditions — `create validatingwebhookconfiguration should have been denied by the api-server`
- [sig-api-machinery] CustomResourceConversionWebhook should be able to convert a non homogeneous list of CRs — `HostPort should not have been declared.`
- [sig-api-machinery] CustomResourceConversionWebhook should be able to convert from CR v1 to CR v2 — `HostPort should not have been declared.`
- [sig-api-machinery] CustomResourceDefinition resources Simple CustomResourceDefinition getting/updating/patching custom resource definition status sub-resource works — `Condition v1.CustomResourceDefinitionCondition{Type:"", Status:"", LastTransitionTime:time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), Reason:"", Message:"u…`
- [sig-api-machinery] CustomResourceDefinition resources Simple CustomResourceDefinition listing custom resource definition objects works — `deleting CustomResourceDefinitions: context deadline exceeded`
- [sig-api-machinery] CustomResourceDefinition resources custom resource defaulting for requests and from storage works — `waiting for CR to be defaulted on read: timed out waiting for the condition`
- [sig-api-machinery] CustomResourcePublishOpenAPI works for CRD without validation schema — `failed to wait for definition "com.example.crd-publish-openapi-test-empty.v1.e2e-test-crd-publish-openapi-3821-7242-crd" to be served with the right OpenAPI sch…`
- [sig-api-machinery] FieldValidation should create/apply an invalid CR with extra properties for CRD with validation schema — `error missing unknown field: the server rejected our request for an unknown reason:`
- [sig-api-machinery] FieldValidation should detect duplicates in a CR when preserving unknown fields — `error missing duplicate field: the server rejected our request for an unknown reason:`
- [sig-api-machinery] FieldValidation should detect unknown and duplicate fields of a typed object — `error missing unknown/duplicate field field, got: strict decoding error: duplicate field "spec.replicas"`
- [sig-api-machinery] FieldValidation should detect unknown metadata fields in both the root and embedded object of a CR — `error missing duplicate field: the server rejected our request for an unknown reason:`

## Networking and DNS (14)

- [sig-network] API Server should have Endpoints and EndpointSlices pointing to API Server — `Expected at least 1 EndpointSlice, got 1: []v1.EndpointSubset{v1.EndpointSubset{Addresses:[]v1.EndpointAddress{v1.EndpointAddress{IP:"172.17.0.3", Hostname:"", …`
- [sig-network] DNS should provide /etc/hosts entries for the cluster — `Unable to read musl_hosts@dns-querier-1.dns-test-service.dns-4467.svc.cluster.local from pod dns-4467/dns-test-a34286d9-09b4-46a9-87e5-0527c227b54a: client rate…`
- [sig-network] DNS should provide DNS for pods for Hostname — `Unable to read musl_hosts@dns-querier-2.dns-test-service-2.dns-7745.svc.cluster.local from pod dns-7745/dns-test-fab306ca-b8f2-4a22-a2a3-34d0d81c4515: client ra…`
- [sig-network] DNS should provide DNS for pods for Subdomain — `Unable to read musl_udp@dns-querier-2.dns-test-service-2.dns-1687.svc.cluster.local from pod dns-1687/dns-test-a5bc78a3-bc0a-4d5d-a171-451602125a69: Get "https:…`
- [sig-network] DNS should provide DNS for the cluster — `Unable to read musl_udp@kubernetes.default.svc.cluster.local from pod dns-266/dns-test-cb6cd73a-19dd-4e33-b26e-05792f1afdfd: Get "https://10.96.0.1:443/api/v1/n…`
- [sig-network] DNS should resolve DNS of partial qualified names for services
- [sig-network] EndpointSlice should support a Service with multiple endpoint IPs specified in multiple EndpointSlices — `error running /usr/local/bin/kubectl --kubeconfig=/tmp/kubeconfig-1160854716 --namespace=endpointslice-4966 exec pause-pod-0 -- /bin/sh -x -c curl -q -s --max-t…`
- [sig-network] EndpointSlice should support a Service with multiple ports specified in multiple EndpointSlices — `error running /usr/local/bin/kubectl --kubeconfig=/tmp/kubeconfig-3426416296 --namespace=endpointslice-3268 exec pause-pod-0 -- /bin/sh -x -c curl -q -s --max-t…`
- [sig-network] EndpointSliceMirroring should mirror a custom Endpoints resource through create update and delete — `Did not find matching EndpointSlice for endpointslicemirroring-9177/example-custom-endpoints: timed out waiting for the condition`
- [sig-network] HostPort validates that there is no conflict between pods with same hostPort but different hostIP and protocol — `Failed to connect to exposed host ports`
- [sig-network] Ingress API should support creating Ingress API operations — `patched object should have the applied annotation`
- [sig-network] Proxy version v1 A set of valid responses are returned for both pod and service Proxy — `Pod didn't start within time out period. timed out waiting for the condition: timed out waiting for the condition`
- [sig-network] Proxy version v1 should proxy through a service and a pod — `Unable to reach service through proxy: context deadline exceeded`
- [sig-network] Services should complete a service status lifecycle — `failed to locate Service test-service-vgjvv in namespace services-5067: timed out waiting for the condition`

## Missing or partial APIs (23)

- [sig-api-machinery] AggregatedDiscovery should support aggregated discovery interface — `Expected apiregistration.k8s.io/v1, Resource=apiservices to be present`
- [sig-api-machinery] AggregatedDiscovery should support raw aggregated discovery endpoint Accept headers — `Expected gvr apiregistration.k8s.io v1 apiservices to exist in discovery`
- [sig-api-machinery] Aggregator Should be able to support the 1.17 Sample API Server using the current Aggregator — `deploying extension apiserver in namespace aggregator-395: error waiting for deployment "sample-apiserver-deployment" status to match expectation: deployment st…`
- [sig-api-machinery] Discovery should locate the groupVersion and a resource within each APIGroup — `Fail to access: /apis/apiregistration.k8s.io/v1: groupVersion "v1" not found`
- [sig-api-machinery] Servers with support for API chunking should return chunks of results for list calls — `Expected`
- [sig-api-machinery] Servers with support for API chunking should support continue listing from the last key if the original version has been compacted away, though the list is inconsistent — `Expected`
- [sig-api-machinery] Servers with support for Table transformation should return a 406 for a backend which does not implement metadata — `failed to return error when posting self subject access review: &SelfSubjectAccessReview{ObjectMeta:{      0 0001-01-01 00:00:00 +0000 UTC <nil> <nil> map[] map…`
- [sig-api-machinery] StorageVersionMigration CRUD Tests storagemigration.k8s.io/v1 StorageVersionMigration — `get resource API: groupVersion "v1" not found`
- [sig-auth] Certificates API should support CSR API operations — `field label not supported: spec.signerName`
- [sig-auth] PodCertificateRequest API should support PodCertificateRequest API operations — `API for certificates.k8s.io/v1 does not include entry for podcertificaterequests, got:`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should issue certificate with default life time (24h) when MaxExpirationSeconds is not set — `failed to parse certificate: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should issue certificate with specified duration (1h) when MaxExpirationSeconds is set — `failed to parse certificate: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should reject pod creation when MaxExpirationSeconds exceeds maximum (91d) — `Expected pod creation to fail due to too long MaxExpirationSeconds, but it succeeded`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should reject pod creation when MaxExpirationSeconds is less than minimum (1h) — `Expected pod creation to fail due to too short MaxExpirationSeconds, but it succeeded`
- [sig-auth] Projected PodCertificate should allow server and client pods to establish an mTLS connection — `error waiting for deployment "server" status to match expectation: deployment status: v1.DeploymentStatus{ObservedGeneration:1, Replicas:1, UpdatedReplicas:1, R…`
- [sig-auth] Projected PodCertificate should honor UserAnnotations for SPIFFE URI path — `failed to parse certificate chain from PEM block: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] ServiceAccounts should create a serviceAccountToken and ensure a successful TokenReview — `failed to create a TokenReview: path "/apis/authentication.k8s.io/v1/tokenreviews" not found`
- [sig-auth] ServiceAccounts should guarantee kube-root-ca.crt exist in any namespace — `timed out waiting for the condition`
- [sig-auth] ServiceAccounts should mount an API token into pods — `path "/apis/authentication.k8s.io/v1/tokenreviews" not found`
- [sig-auth] SubjectReview should support SubjectReview API operations — `Unable to create a SubjectAccessReview, &errors.StatusError{ErrStatus:v1.Status{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ListMeta:v1.ListMeta{SelfLink:"", …`
- [sig-instrumentation] Events API should delete a collection of events — `failed to create event: User "system:serviceaccount:sonobuoy:sonobuoy-serviceaccount" cannot post path "/apis/events.k8s.io/v1/namespaces/events-2451/events"`
- [sig-instrumentation] Events API should ensure that an event can be fetched, patched, deleted, and listed — `failed to create test event: User "system:serviceaccount:sonobuoy:sonobuoy-serviceaccount" cannot post path "/apis/events.k8s.io/v1/namespaces/events-5649/event…`
- [sig-node] [DRA] CRUD Tests resource.k8s.io/v1 DeviceTaintRule — `API for resource.k8s.io/v1 does not include entry for devicetaintrules, got:`

## Validation and immutability (4)

- [sig-api-machinery] Namespaces should apply changes to a namespace status — `patched object should have the applied annotation`
- [sig-node] Secrets should fail to create secret due to empty secret key — `created secret "secret-emptykey-test-7aa773b4-3808-46dc-a608-dae569fa116f" with empty key in namespace "secrets-9535"`
- [sig-storage] ConfigMap should be immutable if `immutable` field is set — `expected 'invalid' as error, got instead: <nil>`
- [sig-storage] Secrets should be immutable if `immutable` field is set — `expected 'invalid' as error, got instead: <nil>`

## kubectl (5)

- [sig-cli] Kubectl client Guestbook application should create and stop a working application — `Frontend service did not start serving content in 600 seconds.`
- [sig-cli] Kubectl client Kubectl describe should check if kubectl describe prints relevant information for rc and pods — `error running /usr/local/bin/kubectl --kubeconfig=/tmp/kubeconfig-2164501684 --namespace=kubectl-2997 describe service agnhost-primary:`
- [sig-cli] Kubectl client Update Demo should create and stop a replication controller — `error running /usr/local/bin/kubectl --kubeconfig=/tmp/kubeconfig-2164501684 --namespace=kubectl-6873 get pods -o template --template={{range.items}}{{.metadata…`
- [sig-cli] Kubectl client Update Demo should scale a replication controller — `error running /usr/local/bin/kubectl --kubeconfig=/tmp/kubeconfig-1160854716 --namespace=kubectl-8023 get pods -o template --template={{range.items}}{{.metadata…`
- [sig-cli] Kubectl logs logs should be able to retrieve and filter logs — `expected "I1025" to be RFC3339 or RFC3339Nano`

## Cluster shape (single-node test environment) (2)

- [sig-apps] Daemon set should rollback without unnecessary restarts — `Conformance test suite needs a cluster with at least 2 nodes.`
- [sig-architecture] Conformance Tests should have at least two untainted nodes — `Conformance requires at least two nodes`

## ClusterTrustBundle (fixed in 2cc219a, after this run) (7)

- [sig-auth] should be able to mount a big number (>100) of CTBs — `expected "-----BEGIN CERTIFICATE-----\nMIIBBjCBuaADAgECAgEAMAUGAytlcDARMQ8wDQYDVQQDEwZyb290NjcwIhgPMDAw\nMTAxMDEwMDAwMDBaGA8wMDAxMDEwMTAwMDAwMFowETEPMA0GA1UEAxM…`
- [sig-auth] should be able to mount a single ClusterTrustBundle by name — `expected "-----BEGIN CERTIFICATE-----\nMIIBBDCBt6ADAgECAgEAMAUGAytlcDAQMQ4wDAYDVQQDEwVyb290NDAiGA8wMDAx\nMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDEwV…`
- [sig-auth] should be able to specify multiple CTB volumes — `expected "-----BEGIN CERTIFICATE-----\nMIIBBDCBt6ADAgECAgEAMAUGAytlcDAQMQ4wDAYDVQQDEwVyb290NDAiGA8wMDAx\nMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDEwV…`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels can combine all signer CTBs with an empty label selector — `expected "-----BEGIN CERTIFICATE-----\nMIIBBDCBt6ADAgECAgEAMAUGAytlcDAQMQ4wDAYDVQQDEwVyb290MDAiGA8wMDAx\nMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDEwV…`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels can combine multiple CTBs with signer name and label selector — `expected "-----BEGIN CERTIFICATE-----\nMIIBBDCBt6ADAgECAgEAMAUGAytlcDAQMQ4wDAYDVQQDEwVyb290MjAiGA8wMDAx\nMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDEwV…`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels should start if only signer name and explicit label selector matches nothing + optional=true — `expected pod "pod-projected-ctb-caf0564a-7552-44bc-94db-9e3e297de7cd" success: Told to stop trying after 2.080s.`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels should start if only signer name and nil label selector + optional=true — `expected pod "pod-projected-ctb-84b3cc43-faeb-4564-9991-08b4f4625169" success: Told to stop trying after 2.035s.`

## Other (1)

- [sig-api-machinery] OrderedNamespaceDeletion namespace deletion should delete pod first — `namespace nsdeletetest-372 has not been processed by namespace controller: context deadline exceeded`

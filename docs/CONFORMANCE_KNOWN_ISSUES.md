# Conformance known issues

Failures of the Kubernetes v1.37 conformance suite (Sonobuoy `non-disruptive-conformance`, `E2E_PARALLEL=true`) against a single-node `kr server`, from `tools/test/conformance.sh`. Tracked overall as KNOWN_ISSUES #70; root causes found and fixed are recorded there with their own numbers.

**Round 8 (2026-10-26): 460 specs, 406 passed, 54 failed**, 23 minutes, no hangs (round 7: 308 passed, 152 failed).

Regenerate the list after a run: `tools/test/conformance.sh results DIR`, then the failed-test names are in `DIR/failed-tests.txt`. A subset runs with `tools/test/conformance.sh run focus REGEX`. Each entry below is the spec and the first failure message, shortened.

## Summary

| Group | Failures |
|---|---|
| Fixed after the run (KNOWN_ISSUES #112), to be confirmed by the next run | 34 |
| API unreachable or slow under the parallel load (10.96.0.1 timeouts, polling timeouts) | 16 |
| Open | 2 |
| Single-node test environment | 2 |

## Fixed after the run (34)

Addressed in KNOWN_ISSUES #112 (review APIs in discovery, impersonation, events protobuf, multi-version apply, selectableFields, pod certificates, pod resize and status fields, graceful deletion, proportional scaling, ControllerRevision data, watch history, and more).

- [sig-api-machinery] AggregatedDiscovery should support aggregated discovery interface — `Expected authentication.k8s.io/v1, Resource=tokenreviews to be present`
- [sig-api-machinery] AggregatedDiscovery should support raw aggregated discovery endpoint Accept headers — `Expected gvr authentication.k8s.io v1 tokenreviews to exist in discovery`
- [sig-api-machinery] CustomResourceFieldSelectors CustomResourceFieldSelectors MUST list and watch custom resources matching the field selector — `watching custom resources with field selector: field label not supported: host`
- [sig-api-machinery] CustomResourcePublishOpenAPI works for CRD without validation schema — `failed to wait for definition "com.example.crd-publish-openapi-test-empty.v1.e2e-test-crd-publish-openapi-557-1945-crd" to be served with the right Op`
- [sig-api-machinery] Discovery should locate the groupVersion and a resource within each APIGroup — `Fail to access: /apis/authentication.k8s.io/v1: groupVersion "v1" not found`
- [sig-api-machinery] FieldValidation should create/apply a CR with unknown fields for CRD with no validation schema — `the server rejected our request for an unknown reason`
- [sig-api-machinery] FieldValidation should create/apply a valid CR for CRD with validation schema — `the server rejected our request for an unknown reason`
- [sig-api-machinery] FieldValidation should create/apply an invalid CR with extra properties for CRD with validation schema — `error missing unknown field: the server rejected our request for an unknown reason:`
- [sig-api-machinery] FieldValidation should detect unknown metadata fields in both the root and embedded object of a CR — `error missing duplicate field: the server rejected our request for an unknown reason:`
- [sig-apps] Daemon set should update pod when spec was updated and update strategy is RollingUpdate — `Expected`
- [sig-apps] Deployment deployment should support proportional scaling — `replicaset "webserver-deployment-567f579575" never had desired number of .spec.replicas`
- [sig-apps] ReplicationController should surface a failure condition on a common issue like exceeded quota — `couldn't apply the provided updated to rc "condition-test": Operation cannot be fulfilled on ReplicationController "condition-test": the object has be`
- [sig-apps] StatefulSet Basic StatefulSet functionality [StatefulSetBasic] should validate Statefulset Status endpoints — `failed to locate Statefulset ss in namespace statefulset-4750: watch closed before UntilWithoutRetry timeout`
- [sig-auth] Certificates API should support CSR API operations — `patched object should have the applied condition`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should issue certificate with default life time (24h) when MaxExpirationSeconds is not set — `failed to parse certificate: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should issue certificate with specified duration (1h) when MaxExpirationSeconds is set — `failed to parse certificate: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should reject pod creation when MaxExpirationSeconds exceeds maximum (91d) — `Expected pod creation to fail due to too long MaxExpirationSeconds, but it succeeded`
- [sig-auth] Projected PodCertificate MaxExpirationSeconds validations should reject pod creation when MaxExpirationSeconds is less than minimum (1h) — `Expected pod creation to fail due to too short MaxExpirationSeconds, but it succeeded`
- [sig-auth] Projected PodCertificate should allow server and client pods to establish an mTLS connection — `error waiting for deployment "server" status to match expectation: deployment status: v1.DeploymentStatus{ObservedGeneration:1, Replicas:1, UpdatedRep`
- [sig-auth] Projected PodCertificate should honor UserAnnotations for SPIFFE URI path — `failed to parse certificate chain from PEM block: data does not contain any valid RSA or ECDSA certificates`
- [sig-auth] SubjectReview should support SubjectReview API operations — `Could not verify SubjectAccessReview for "system:serviceaccount:subjectreview-3839:e2e" in namespace "subjectreview-3839": SubjectAccessReview allowed`
- [sig-auth] should be able to mount a single ClusterTrustBundle by name — `expected pod "pod-projected-ctb-45c5085d-5e8e-480b-8191-793fbe91fba8" success: Told to stop trying after 2.048s.`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels should start if only signer name and explicit label selector matches nothing + optional=true — `expected pod "pod-projected-ctb-e7e71d94-f0b8-4e50-b6ff-b3d6321c9f12" success: Told to stop trying after 2.050s.`
- [sig-auth] should be capable to mount multiple trust bundles by signer+labels should start if only signer name and nil label selector + optional=true — `expected pod "pod-projected-ctb-9a110101-a733-4b38-844e-618175207118" success: Told to stop trying after 2.061s.`
- [sig-instrumentation] Events API should delete a collection of events — `failed to create event: protobuf is not supported for this kind; use application/json`
- [sig-instrumentation] Events API should ensure that an event can be fetched, patched, deleted, and listed — `failed to create test event: protobuf is not supported for this kind; use application/json`
- [sig-network] Proxy version v1 A set of valid responses are returned for both pod and service Proxy — `The resp.StatusCode returned: 200`
- [sig-node] KubeletManagedEtcHosts should test kubelet managed /etc/hosts file — `/etc/hosts file should be kubelet managed (name: busybox-1, retries: 108). /etc/hosts contains "# Kubernetes-managed hosts file (kr).\n127.0.0.1\tloca`
- [sig-node] Pod InPlace Resize Container burstable pods - extended 6 containers - various operations performed (including adding limits and requests) — `Test Panicked`
- [sig-node] Pod InPlace Resize Container burstable pods - extended resize with equivalents — `Test Panicked`
- [sig-node] Pod InPlace Resize Container resize pod via the replace endpoint — `Test Panicked`
- [sig-node] Pods Extended (pod generation) Pod Generation custom-set generation on new pods and graceful delete — `failed to query for pod: pod "pod-generation-24e0813d-18e9-4742-aa45-8414e8f4e575" not found`
- [sig-node] Pods Extended Pods Set QOS Class should be set on Pods with matching resource requests and limits for memory and cpu — `Expected`
- [sig-scheduling] SchedulerPreemption validates pod disruption condition is added to the preempted pod — `pod "victim-pod" should have the condition: "DisruptionTarget", pod status: {2 Succeeded [{PodScheduled 0 True 0001-01-01 00:00:00 +0000 UTC 2026-10-2`

## API unreachable or slow under the parallel load (16)

Calls from the test pods to the API (through the service proxy on 10.96.0.1:443) or the specs' own polls time out while about 30 specs run in parallel on one single-threaded server. The listen backlogs were raised (API server and service proxy: 4096) and the watch history grown tenfold (a restarted watch no longer gets 410 after a busy minute); the rest needs profiling under load. Several of these also cover volume updates (the kubelet refreshes volumes every 20 s) and probes.

- [sig-api-machinery] CustomResourceDefinition resources Simple CustomResourceDefinition listing custom resource definition objects works — `deleting CustomResourceDefinitions: Get "https://10.96.0.1:443/apis/mygroup.example.com/v1beta1": dial tcp 10.96.0.1:443: i/o timeout`
- [sig-api-machinery] ResourceQuota should create a ResourceQuota and capture the life of a pod. — `Timed out after 300.000s.`
- [sig-apps] CronJob should not schedule jobs when suspended — `Told to stop trying after 351.342s.`
- [sig-apps] Job with successPolicy succeededIndexes rule should succeeded even when some indexes remain pending — `failed to ensure that job has SuccessCriteriaMet with SuccessPolicy reason condition: Told to stop trying after 330.013s.`
- [sig-apps] StatefulSet Basic StatefulSet functionality [StatefulSetBasic] Burst scaling should run to completion even with unhealthy pods — `Get "https://10.96.0.1:443/api/v1/namespaces/statefulset-3967/pods?labelSelector=baz%3Dblah%2Cfoo%3Dbar": dial tcp 10.96.0.1:443: i/o timeout`
- [sig-network] Networking Granular Checks: Pods should function for intra-pod communication: udp — `Told to stop trying after 330.046s.`
- [sig-network] Services should have session affinity work for NodePort service — `failed to create deployment with service in the namespace: services-5831: Post "https://10.96.0.1:443/api/v1/namespaces/services-5831/services": EOF`
- [sig-node] Pods Extended (pod generation) Pod Generation issue 500 podspec updates and verify generation and observedGeneration eventually converge — `failed to update pod "pod-generation-8d2e9620-fd4e-49b6-a267-78045534ee3d": Put "https://10.96.0.1:443/api/v1/namespaces/pods-9959/pods/pod-generation`
- [sig-node] Probing container should *not* be restarted with a GRPC liveness probe — `getting pod : Get "https://10.96.0.1:443/api/v1/namespaces/container-probe-8927/pods/test-grpc-1e386a5b-3688-4726-8bdd-477eafb5775d": dial tcp 10.96.0`
- [sig-node] Probing container with readiness probe that fails should never be ready and never restart — `Failed after 342.329s.`
- [sig-node] Sysctls should support sysctls — `context deadline exceeded`
- [sig-storage] ConfigMap should be consumable from pods in volume as non-root — `expected pod "pod-configmaps-e288352a-45d8-40ad-91dd-77c100b94975" success: Told to stop trying after 330.043s.`
- [sig-storage] Projected configMap optional updates should be reflected in volume — `Timed out after 339.377s.`
- [sig-storage] Projected downwardAPI should update annotations on modification — `Timed out after 345.115s.`
- [sig-storage] Projected secret optional updates should be reflected in volume — `Timed out after 338.974s.`
- [sig-storage] Subpath Atomic writer volumes should support subpaths with downward pod — `expected pod "pod-subpath-test-downwardapi-qk4k" success: Told to stop trying after 350.195s.`

## Open (2)



- [sig-api-machinery] AdmissionWebhook should be able to deny attaching pod — `unexpected 'kubectl attach' error message. expected to contain "attaching to pod 'to-be-attached-pod' is not allowed", got "timed out waiting for comm`
- [sig-api-machinery] Aggregator Should be able to support the 1.17 Sample API Server using the current Aggregator — `deploying extension apiserver in namespace aggregator-9781: error waiting for deployment "sample-apiserver-deployment" status to match expectation: de`

## Single-node test environment (2)



- [sig-apps] Daemon set should rollback without unnecessary restarts — `Conformance test suite needs a cluster with at least 2 nodes.`
- [sig-architecture] Conformance Tests should have at least two untainted nodes — `Conformance requires at least two nodes`


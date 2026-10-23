// Golden-vector generator for kr-apiserver's protobuf request-body decoder.
//
// Encodes a fixed set of Kubernetes objects with the real k8s.io protobuf serializer (the one
// kubectl uses) and with encoding/json, writing <name>.pb.hex and <name>.json pairs.
// Dev tooling only; the shipped code has no dependencies. Run via tools/gen_k8s_proto_vectors.sh.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ptr[T any](v T) *T { return &v }

func tm(gv, kind string) metav1.TypeMeta { return metav1.TypeMeta{APIVersion: gv, Kind: kind} }

func main() {
	out := os.Args[1]
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, batchv1.AddToScheme, coordv1.AddToScheme,
		netv1.AddToScheme, policyv1.AddToScheme, rbacv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			panic(err)
		}
	}
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	ser := protobuf.NewSerializer(scheme, scheme)

	ts := metav1.NewTime(time.Date(2024, 5, 17, 13, 4, 5, 999, time.UTC))
	mts := metav1.NewMicroTime(time.Date(2024, 5, 17, 13, 4, 5, 123456000, time.UTC))
	labels := map[string]string{"app": "web", "tier": "front"}
	probe := func(port intstr.IntOrString) *corev1.Probe {
		return &corev1.Probe{
			ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: port, Scheme: corev1.URISchemeHTTP}},
			InitialDelaySeconds: 5, PeriodSeconds: 10, FailureThreshold: 3,
		}
	}
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{{
			Name: "web", Image: "nginx:1.27", Args: []string{"-g", "daemon off;"},
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 80, Protocol: corev1.ProtocolTCP}},
			Env: []corev1.EnvVar{
				{Name: "PLAIN", Value: "x"},
				{Name: "FROM_FIELD", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
				{Name: "FROM_CM", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}, Key: "k", Optional: ptr(true)}}},
				{Name: "FROM_SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "sec"}, Key: "k"}}},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("128Mi")},
			},
			LivenessProbe:  probe(intstr.FromInt32(80)),
			ReadinessProbe: probe(intstr.FromString("http")),
			VolumeMounts:   []corev1.VolumeMount{{Name: "cfgvol", MountPath: "/etc/cfg", ReadOnly: true}},
			SecurityContext: &corev1.SecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(1000)), AllowPrivilegeEscalation: ptr(false)},
		}},
		Volumes: []corev1.Volume{
			{Name: "cfgvol", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}, DefaultMode: ptr(int32(0o644))}}},
			{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		},
		TerminationGracePeriodSeconds: ptr(int64(0)),
		NodeSelector:                  map[string]string{"disk": "ssd"},
		Tolerations:                   []corev1.Toleration{{Key: "k", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule, TolerationSeconds: ptr(int64(30))}},
	}

	objs := map[string]runtime.Object{
		"configmap": &corev1.ConfigMap{
			TypeMeta:   tm("v1", "ConfigMap"),
			ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "default", Labels: labels, Annotations: map[string]string{"note": "héllo \"q\""}, CreationTimestamp: ts},
			Data:       map[string]string{"a": "b", "multi": "line1\nline2"},
			BinaryData: map[string][]byte{"bin": {0, 1, 2, 0xff, 0xfe}},
		},
		"secret": &corev1.Secret{
			TypeMeta:   tm("v1", "Secret"),
			ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"password": []byte("hunter2"), "empty": {}},
			Immutable:  ptr(false),
		},
		"namespace": &corev1.Namespace{
			TypeMeta:   tm("v1", "Namespace"),
			ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"env": "dev"}},
		},
		"serviceaccount": &corev1.ServiceAccount{
			TypeMeta:                     tm("v1", "ServiceAccount"),
			ObjectMeta:                   metav1.ObjectMeta{Name: "builder", Namespace: "default"},
			ImagePullSecrets:             []corev1.LocalObjectReference{{Name: "reg"}},
			AutomountServiceAccountToken: ptr(false),
		},
		"deployment": &appsv1.Deployment{
			TypeMeta:   tm("apps/v1", "Deployment"),
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: labels, Generation: 3, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "o", UID: types.UID("u-1"), Controller: ptr(true)}}},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr(int32(0)),
				Selector: &metav1.LabelSelector{MatchLabels: labels, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}}},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: podSpec},
				Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: ptr(intstr.FromString("25%")), MaxSurge: ptr(intstr.FromInt32(1))}},
				MinReadySeconds: 2, RevisionHistoryLimit: ptr(int32(10)), ProgressDeadlineSeconds: ptr(int32(600)),
			},
		},
		"service": &corev1.Service{
			TypeMeta:   tm("v1", "Service"),
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort, Selector: labels,
				Ports: []corev1.ServicePort{
					{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(8080), NodePort: 30080},
					{Name: "named", Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")},
				},
				ClusterIP: "10.0.0.5", SessionAffinity: corev1.ServiceAffinityNone,
			},
		},
		"job": &batchv1.Job{
			TypeMeta:   tm("batch/v1", "Job"),
			ObjectMeta: metav1.ObjectMeta{Name: "pi", Namespace: "default"},
			Spec: batchv1.JobSpec{
				Parallelism: ptr(int32(2)), Completions: ptr(int32(4)), BackoffLimit: ptr(int32(0)), ActiveDeadlineSeconds: ptr(int64(3600)),
				TTLSecondsAfterFinished: ptr(int32(60)),
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers:    []corev1.Container{{Name: "pi", Image: "perl", Command: []string{"perl", "-Mbignum=bpi", "-wle", "print bpi(2000)"}}},
				}},
			},
		},
		"pod": &corev1.Pod{
			TypeMeta:   tm("v1", "Pod"),
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default", DeletionGracePeriodSeconds: ptr(int64(30)), DeletionTimestamp: &ts, Finalizers: []string{"f/1"}},
			Spec:       podSpec,
		},
		"deleteoptions": &metav1.DeleteOptions{
			TypeMeta: tm("v1", "DeleteOptions"), GracePeriodSeconds: ptr(int64(0)), PropagationPolicy: ptr(metav1.DeletePropagationForeground),
			Preconditions: &metav1.Preconditions{UID: ptr(types.UID("abc")), ResourceVersion: ptr("12")}, DryRun: []string{"All"},
		},
		"lease": &coordv1.Lease{
			TypeMeta: tm("coordination.k8s.io/v1", "Lease"), ObjectMeta: metav1.ObjectMeta{Name: "l", Namespace: "kube-system"},
			Spec: coordv1.LeaseSpec{HolderIdentity: ptr("me"), LeaseDurationSeconds: ptr(int32(15)), AcquireTime: &mts, RenewTime: &mts, LeaseTransitions: ptr(int32(2))},
		},
		"role": &rbacv1.Role{
			TypeMeta: tm("rbac.authorization.k8s.io/v1", "Role"), ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "pods/log"}, Verbs: []string{"get", "list"}, ResourceNames: []string{"a"}}},
		},
		"rolebinding": &rbacv1.RoleBinding{
			TypeMeta: tm("rbac.authorization.k8s.io/v1", "RoleBinding"), ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "default"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "builder", Namespace: "default"}, {Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "bob"}},
			RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "r"},
		},
		"ingress": &netv1.Ingress{
			TypeMeta: tm("networking.k8s.io/v1", "Ingress"), ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "default"},
			Spec: netv1.IngressSpec{
				IngressClassName: ptr("nginx"),
				Rules: []netv1.IngressRule{{Host: "a.example.com", IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{Paths: []netv1.HTTPIngressPath{{
					Path: "/", PathType: ptr(netv1.PathTypePrefix),
					Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{Name: "web", Port: netv1.ServiceBackendPort{Number: 80}}},
				}}}}}},
			},
		},
		"pdb": &policyv1.PodDisruptionBudget{
			TypeMeta: tm("policy/v1", "PodDisruptionBudget"), ObjectMeta: metav1.ObjectMeta{Name: "pdb", Namespace: "default"},
			Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptr(intstr.FromString("50%")), Selector: &metav1.LabelSelector{MatchLabels: labels}},
		},
		"pvc": &corev1.PersistentVolumeClaim{
			TypeMeta: tm("v1", "PersistentVolumeClaim"), ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default"},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
			},
		},
	}
	for name, obj := range objs {
		var buf bytes.Buffer
		if err := ser.Encode(obj, &buf); err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		js, err := json.Marshal(obj)
		if err != nil {
			panic(err)
		}
		must(os.WriteFile(filepath.Join(out, name+".pb.hex"), []byte(hex.EncodeToString(buf.Bytes())+"\n"), 0o644))
		must(os.WriteFile(filepath.Join(out, name+".json"), append(js, '\n'), 0o644))
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

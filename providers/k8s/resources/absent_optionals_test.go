// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
)

// An optional field the object does not set has not been measured, so it must
// read null. Returning the zero value instead states a fact that is usually the
// opposite of the truth: terminationGracePeriodSeconds 0 means "SIGKILL
// immediately" where absent means 30s, ttlSecondsAfterFinished 0 means "delete
// the Job the moment it finishes" where absent means never, and an empty
// storageClassName means "bind only to a PV with no class" where absent means
// "use the default StorageClass".
//
// Each case pairs a "-bare" object (field omitted) with a "-set" object (field
// present) so the test pins both branches: a fix that made every field null
// would fail the -set half.

func loadAbsentOptionalsRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{}},
		},
	}, manifest.WithManifestFile("testdata/absent_optionals.yaml"))
	require.NoError(t, err)
	require.NotNil(t, conn)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func absentOptionalsK8s(t *testing.T) *mqlK8s {
	t.Helper()
	obj, err := CreateResource(loadAbsentOptionalsRuntime(t), "k8s", nil)
	require.NoError(t, err)
	return obj.(*mqlK8s)
}

// findByName pulls one named object out of a list accessor's result.
func findByName[T any](t *testing.T, tv *plugin.TValue[[]any], name string, nameOf func(T) string) T {
	t.Helper()
	require.NoError(t, tv.Error)
	for _, it := range tv.Data {
		if v, ok := it.(T); ok && nameOf(v) == name {
			return v
		}
	}
	var zero T
	t.Fatalf("no object named %q in list", name)
	return zero
}

// assertNull fails unless the field resolved AND resolved to null. Checking only
// Data would pass on an unresolved field, and checking only State would pass on
// a field that reported a zero value.
func assertNull[T comparable](t *testing.T, tv *plugin.TValue[T], field string) {
	t.Helper()
	require.NoError(t, tv.Error, field)
	assert.NotZero(t, tv.State&plugin.StateIsSet, "%s must be resolved", field)
	assert.NotZero(t, tv.State&plugin.StateIsNull,
		"%s is absent from the object and must read null, not %v", field, tv.Data)
}

func assertValue[T comparable](t *testing.T, tv *plugin.TValue[T], want T, field string) {
	t.Helper()
	require.NoError(t, tv.Error, field)
	assert.Zero(t, tv.State&plugin.StateIsNull, "%s is set on the object and must not read null", field)
	assert.Equal(t, want, tv.Data, field)
}

func TestPodAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	pods := k8s.GetPods()
	name := func(p *mqlK8sPod) string { return p.Name.Data }

	bare := findByName(t, pods, "pod-bare", name)
	assertNull(t, bare.GetTerminationGracePeriodSeconds(), "pod.terminationGracePeriodSeconds")
	assertNull(t, bare.GetActiveDeadlineSeconds(), "pod.activeDeadlineSeconds")
	assertNull(t, bare.GetPreemptionPolicy(), "pod.preemptionPolicy")

	set := findByName(t, pods, "pod-set", name)
	assertValue(t, set.GetTerminationGracePeriodSeconds(), int64(45), "pod.terminationGracePeriodSeconds")
	assertValue(t, set.GetActiveDeadlineSeconds(), int64(120), "pod.activeDeadlineSeconds")
	assertValue(t, set.GetPreemptionPolicy(), "Never", "pod.preemptionPolicy")
}

func TestJobAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	jobs := k8s.GetJobs()
	name := func(j *mqlK8sJob) string { return j.Name.Data }

	bare := findByName(t, jobs, "job-bare", name)
	assertNull(t, bare.GetActiveDeadlineSeconds(), "job.activeDeadlineSeconds")
	assertNull(t, bare.GetTtlSecondsAfterFinished(), "job.ttlSecondsAfterFinished")
	assertNull(t, bare.GetBackoffLimitPerIndex(), "job.backoffLimitPerIndex")
	assertNull(t, bare.GetMaxFailedIndexes(), "job.maxFailedIndexes")
	assertNull(t, bare.GetPodReplacementPolicy(), "job.podReplacementPolicy")
	assertNull(t, bare.GetReady(), "job.ready")
	assertNull(t, bare.GetTerminating(), "job.terminating")
	assertNull(t, bare.GetFailedIndexes(), "job.failedIndexes")

	set := findByName(t, jobs, "job-set", name)
	assertValue(t, set.GetActiveDeadlineSeconds(), int64(300), "job.activeDeadlineSeconds")
	assertValue(t, set.GetTtlSecondsAfterFinished(), int64(600), "job.ttlSecondsAfterFinished")
	assertValue(t, set.GetBackoffLimitPerIndex(), int64(2), "job.backoffLimitPerIndex")
	assertValue(t, set.GetMaxFailedIndexes(), int64(3), "job.maxFailedIndexes")
	assertValue(t, set.GetPodReplacementPolicy(), "Failed", "job.podReplacementPolicy")
	assertValue(t, set.GetReady(), int64(1), "job.ready")
	assertValue(t, set.GetTerminating(), int64(2), "job.terminating")
	assertValue(t, set.GetFailedIndexes(), "1,3", "job.failedIndexes")
}

func TestCronJobAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	cronjobs := k8s.GetCronjobs()
	name := func(c *mqlK8sCronjob) string { return c.Name.Data }

	bare := findByName(t, cronjobs, "cj-bare", name)
	assertNull(t, bare.GetStartingDeadlineSeconds(), "cronjob.startingDeadlineSeconds")

	set := findByName(t, cronjobs, "cj-set", name)
	assertValue(t, set.GetStartingDeadlineSeconds(), int64(90), "cronjob.startingDeadlineSeconds")
}

func TestDeploymentAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	deployments := k8s.GetDeployments()
	name := func(d *mqlK8sDeployment) string { return d.Name.Data }

	bare := findByName(t, deployments, "deploy-bare", name)
	assertNull(t, bare.GetRevisionHistoryLimit(), "deployment.revisionHistoryLimit")
	assertNull(t, bare.GetProgressDeadlineSeconds(), "deployment.progressDeadlineSeconds")
	assertNull(t, bare.GetCollisionCount(), "deployment.collisionCount")

	set := findByName(t, deployments, "deploy-set", name)
	assertValue(t, set.GetRevisionHistoryLimit(), int64(7), "deployment.revisionHistoryLimit")
	assertValue(t, set.GetProgressDeadlineSeconds(), int64(450), "deployment.progressDeadlineSeconds")
	assertValue(t, set.GetCollisionCount(), int64(2), "deployment.collisionCount")
}

func TestDaemonSetAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	daemonsets := k8s.GetDaemonsets()
	name := func(d *mqlK8sDaemonset) string { return d.Name.Data }

	bare := findByName(t, daemonsets, "ds-bare", name)
	assertNull(t, bare.GetRevisionHistoryLimit(), "daemonset.revisionHistoryLimit")
	assertNull(t, bare.GetCollisionCount(), "daemonset.collisionCount")

	set := findByName(t, daemonsets, "ds-set", name)
	assertValue(t, set.GetRevisionHistoryLimit(), int64(5), "daemonset.revisionHistoryLimit")
	assertValue(t, set.GetCollisionCount(), int64(1), "daemonset.collisionCount")
}

func TestStatefulSetAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	statefulsets := k8s.GetStatefulsets()
	name := func(s *mqlK8sStatefulset) string { return s.Name.Data }

	bare := findByName(t, statefulsets, "sts-bare", name)
	assertNull(t, bare.GetRevisionHistoryLimit(), "statefulset.revisionHistoryLimit")
	assertNull(t, bare.GetCollisionCount(), "statefulset.collisionCount")

	set := findByName(t, statefulsets, "sts-set", name)
	assertValue(t, set.GetRevisionHistoryLimit(), int64(4), "statefulset.revisionHistoryLimit")
	assertValue(t, set.GetCollisionCount(), int64(3), "statefulset.collisionCount")
}

func TestHPAAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	hpas := k8s.GetHorizontalPodAutoscalers()
	name := func(h *mqlK8sHorizontalpodautoscaler) string { return h.Name.Data }

	bare := findByName(t, hpas, "hpa-bare", name)
	assertNull(t, bare.GetObservedGeneration(), "horizontalpodautoscaler.observedGeneration")

	set := findByName(t, hpas, "hpa-set", name)
	assertValue(t, set.GetObservedGeneration(), int64(9), "horizontalpodautoscaler.observedGeneration")
}

func TestIngressAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	ingresses := k8s.GetIngresses()
	name := func(i *mqlK8sIngress) string { return i.Name.Data }

	bare := findByName(t, ingresses, "ing-bare", name)
	assertNull(t, bare.GetIngressClassName(), "ingress.ingressClassName")

	set := findByName(t, ingresses, "ing-set", name)
	assertValue(t, set.GetIngressClassName(), "nginx", "ingress.ingressClassName")
}

func TestPersistentVolumeAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	pvs := k8s.GetPersistentVolumes()
	name := func(p *mqlK8sPersistentvolume) string { return p.Name.Data }

	// An unbound PV has no claimRef at all; "" would read as a claim whose name
	// happens to be empty.
	bare := findByName(t, pvs, "pv-bare", name)
	assertNull(t, bare.GetClaimName(), "persistentvolume.claimName")
	assertNull(t, bare.GetClaimNamespace(), "persistentvolume.claimNamespace")

	set := findByName(t, pvs, "pv-set", name)
	assertValue(t, set.GetClaimName(), "pvc-set", "persistentvolume.claimName")
	assertValue(t, set.GetClaimNamespace(), "demo", "persistentvolume.claimNamespace")
}

func TestPersistentVolumeClaimAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	pvcs := k8s.GetPersistentVolumeClaims()
	name := func(p *mqlK8sPersistentvolumeclaim) string { return p.Name.Data }

	// nil storageClassName means "use the default StorageClass"; an explicit ""
	// means the opposite ("bind only to a PV with no class"), so the zero value
	// inverts the meaning here.
	bare := findByName(t, pvcs, "pvc-bare", name)
	assertNull(t, bare.GetStorageClassName(), "persistentvolumeclaim.storageClassName")

	set := findByName(t, pvcs, "pvc-set", name)
	assertValue(t, set.GetStorageClassName(), "fast", "persistentvolumeclaim.storageClassName")
}

func TestServiceAbsentOptionals(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	services := k8s.GetServices()
	name := func(s *mqlK8sService) string { return s.Name.Data }

	bare := findByName(t, services, "svc-bare", name)
	assertNull(t, bare.GetInternalTrafficPolicy(), "service.internalTrafficPolicy")
	assertNull(t, bare.GetIpFamilyPolicy(), "service.ipFamilyPolicy")
	assertNull(t, bare.GetLoadBalancerClass(), "service.loadBalancerClass")
	assertNull(t, bare.GetExternalTrafficPolicy(), "service.externalTrafficPolicy")
	assertNull(t, bare.GetHealthCheckNodePort(), "service.healthCheckNodePort")

	set := findByName(t, services, "svc-set", name)
	assertValue(t, set.GetInternalTrafficPolicy(), "Local", "service.internalTrafficPolicy")
	assertValue(t, set.GetIpFamilyPolicy(), "SingleStack", "service.ipFamilyPolicy")
	assertValue(t, set.GetLoadBalancerClass(), "example.com/lb", "service.loadBalancerClass")
	assertValue(t, set.GetExternalTrafficPolicy(), "Local", "service.externalTrafficPolicy")
	assertValue(t, set.GetHealthCheckNodePort(), int64(32000), "service.healthCheckNodePort")
}

func TestServiceSessionAffinityConfigAbsentIsNull(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	services := k8s.GetServices()
	name := func(s *mqlK8sService) string { return s.Name.Data }

	// convert.JsonToDict(nil) yields {}, which is indistinguishable from an
	// affinity config that was configured and is empty.
	bare := findByName(t, services, "svc-bare", name)
	cfg := bare.GetSessionAffinityConfig()
	require.NoError(t, cfg.Error)
	assert.NotZero(t, cfg.State&plugin.StateIsNull,
		"service.sessionAffinityConfig is absent and must read null, not %v", cfg.Data)

	set := findByName(t, services, "svc-set", name)
	setCfg := set.GetSessionAffinityConfig()
	require.NoError(t, setCfg.Error)
	assert.Zero(t, setCfg.State&plugin.StateIsNull)
	assert.Contains(t, setCfg.Data, "clientIP")
}

// allocateLoadBalancerNodePorts only has meaning for type LoadBalancer. The API
// server leaves it unset on every other type, so defaulting it to true reported
// an allocation decision that was never made — including on ExternalName.
func TestServiceAllocateLoadBalancerNodePortsIsScopedToLoadBalancer(t *testing.T) {
	k8s := absentOptionalsK8s(t)
	services := k8s.GetServices()
	name := func(s *mqlK8sService) string { return s.Name.Data }

	for _, svc := range []string{"svc-bare", "svc-extname"} {
		s := findByName(t, services, svc, name)
		assertNull(t, s.GetAllocateLoadBalancerNodePorts(),
			svc+".allocateLoadBalancerNodePorts")
	}

	// A LoadBalancer that omits the field really does default to true.
	lbDefault := findByName(t, services, "svc-lb-default", name)
	assertValue(t, lbDefault.GetAllocateLoadBalancerNodePorts(), true,
		"svc-lb-default.allocateLoadBalancerNodePorts")

	// ...and an explicit false is still read as false, not as absent.
	set := findByName(t, services, "svc-set", name)
	assertValue(t, set.GetAllocateLoadBalancerNodePorts(), false,
		"svc-set.allocateLoadBalancerNodePorts")
}

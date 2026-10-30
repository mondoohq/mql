// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sPodInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sPod) getPod() (*corev1.Pod, error) {
	p, ok := k.obj.(*corev1.Pod)
	if ok {
		return p, nil
	}
	return nil, errors.New("invalid k8s pod")
}

func (k *mqlK8s) pods() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("pods")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.pod", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"apiVersion":      llx.StringData(objT.GetAPIVersion()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sPod).obj = resource
		return r, nil
	})
}

func (k *mqlK8sPod) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sPod) podSpec() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	podSpec, err := resources.GetPodSpec(pod)
	if err != nil {
		return nil, err
	}
	dict, err := convert.JsonToDict(podSpec)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (k *mqlK8sPod) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sPod(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sPod](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPods() })
}

func (k *mqlK8sPod) initContainers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sPod) ephemeralContainers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, EphemeralContainerType)
}

func (k *mqlK8sPod) containers() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return getContainers(pod, &pod.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sPod) containerStatuses() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}

	resp := []any{}
	// A pod's runtime state lives in three separate status slices. Reading only
	// the first one hid every sidecar (init containers with restartPolicy
	// Always, GA since 1.29) and every attached ephemeral debug container, so
	// "no container has restarted" passed without ever looking at them.
	statusGroups := []struct {
		kind     string
		statuses []corev1.ContainerStatus
	}{
		{"containerstatus", pod.Status.ContainerStatuses},
		{"initcontainerstatus", pod.Status.InitContainerStatuses},
		{"ephemeralcontainerstatus", pod.Status.EphemeralContainerStatuses},
	}
	for _, group := range statusGroups {
		for _, c := range group.statuses {
			state, err := convert.JsonToDict(c.State)
			if err != nil {
				return nil, err
			}
			lastState, err := convert.JsonToDict(c.LastTerminationState)
			if err != nil {
				return nil, err
			}
			statusResources, err := convert.JsonToDict(c.Resources)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				// The status kind is part of the key: a sidecar and a regular
				// container may share a name across the two slices.
				"__id":         llx.StringData(string(pod.GetUID()) + "-" + group.kind + "-" + c.Name),
				"name":         llx.StringData(c.Name),
				"ready":        llx.BoolData(c.Ready),
				"started":      llx.BoolDataPtr(c.Started),
				"restartCount": llx.IntData(int64(c.RestartCount)),
				"image":        llx.StringData(c.Image),
				"imageId":      llx.StringData(c.ImageID),
				"containerId":  llx.StringData(c.ContainerID),
				"state":        llx.DictData(state),
				"lastState":    llx.DictData(lastState),
				"resources":    llx.DictData(statusResources),
			}
			mqlContainer, err := CreateResource(k.MqlRuntime, ResourceK8sContainerStatus, args)
			if err != nil {
				return nil, err
			}
			resp = append(resp, mqlContainer)
		}
	}
	return resp, nil
}

func (k *mqlK8sPod) annotations() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(pod.GetAnnotations()), nil
}

func (k *mqlK8sPod) labels() (map[string]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(pod.GetLabels()), nil
}

func (k *mqlK8sPod) node() (*mqlK8sNode, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	podSpec, err := resources.GetPodSpec(pod)
	if err != nil {
		return nil, err
	}

	// Unscheduled pods have no node assigned yet.
	if podSpec.NodeName == "" {
		k.Node.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	node, err := NewResource(k.MqlRuntime, "k8s.node", map[string]*llx.RawData{
		"name": llx.StringData(podSpec.NodeName),
	})
	if err != nil {
		// Nodes are cluster-scoped, so they aren't loaded when queried
		// from a namespace-scoped asset, and a scheduled node can also be
		// drained or removed. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Node.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	return node.(*mqlK8sNode), nil
}

func (k *mqlK8sPod) podSpecTyped() (*corev1.PodSpec, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return &pod.Spec, nil
}

func (k *mqlK8sPod) nodeName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.NodeName, nil
}

func (k *mqlK8sPod) nodeSelector() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(spec.NodeSelector), nil
}

func (k *mqlK8sPod) tolerations() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.Tolerations)
}

func (k *mqlK8sPod) topologySpreadConstraints() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.TopologySpreadConstraints)
}

func (k *mqlK8sPod) affinity() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.Affinity)
}

func (k *mqlK8sPod) priorityClassName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.PriorityClassName, nil
}

func (k *mqlK8sPod) priorityClass() (*mqlK8sPriorityclass, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	if spec.PriorityClassName == "" {
		k.PriorityClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pc, err := NewResource(k.MqlRuntime, "k8s.priorityclass", map[string]*llx.RawData{
		"name": llx.StringData(spec.PriorityClassName),
	})
	if err != nil {
		// PriorityClass is cluster-scoped, so it isn't loaded when queried
		// from a namespace-scoped asset, and a referenced PriorityClass
		// may have been deleted. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.PriorityClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return pc.(*mqlK8sPriorityclass), nil
}

func (k *mqlK8sPod) preemptionPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	if spec.PreemptionPolicy == nil {
		k.PreemptionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*spec.PreemptionPolicy), nil
}

func (k *mqlK8sPod) schedulerName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.SchedulerName, nil
}

func (k *mqlK8sPod) runtimeClassName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	if spec.RuntimeClassName == nil {
		return "", nil
	}
	return *spec.RuntimeClassName, nil
}

// runtimeClass resolves the pod's runtimeClassName to the RuntimeClass
// object. It scans the already-fetched class list rather than calling
// NewResource per pod, which would run the target's init before the runtime
// cache is consulted and turn one list call into one per pod.
func (k *mqlK8sPod) runtimeClass() (*mqlK8sRuntimeclass, error) {
	name := k.GetRuntimeClassName()
	if name.Error != nil {
		return nil, name.Error
	}
	if name.Data == "" {
		k.RuntimeClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	classes := o.(*mqlK8s).GetRuntimeClasses()
	if classes.Error != nil {
		return nil, classes.Error
	}

	for i := range classes.Data {
		rc, ok := classes.Data[i].(*mqlK8sRuntimeclass)
		if !ok {
			continue
		}
		if rc.Name.Data == name.Data {
			return rc, nil
		}
	}

	// The pod names a class the cluster does not have (it was deleted, or the
	// scan cannot read the kind). That is a real state, not an error.
	k.RuntimeClass.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (k *mqlK8sPod) serviceAccountName() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.ServiceAccountName, nil
}

func (k *mqlK8sPod) serviceAccount() (*mqlK8sServiceaccount, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	if pod.Spec.ServiceAccountName == "" {
		k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	sa, err := NewResource(k.MqlRuntime, "k8s.serviceaccount", map[string]*llx.RawData{
		"name":      llx.StringData(pod.Spec.ServiceAccountName),
		"namespace": llx.StringData(pod.Namespace),
	})
	if err != nil {
		// A referenced ServiceAccount may have been deleted. Resolve to
		// null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return sa.(*mqlK8sServiceaccount), nil
}

func (k *mqlK8sPod) automountServiceAccountToken() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sPod) hostNetwork() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostNetwork, nil
}

func (k *mqlK8sPod) hostPID() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostPID, nil
}

func (k *mqlK8sPod) hostIPC() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostIPC, nil
}

func (k *mqlK8sPod) shareProcessNamespace() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	if spec.ShareProcessNamespace == nil {
		return false, nil
	}
	return *spec.ShareProcessNamespace, nil
}

func (k *mqlK8sPod) securityContext() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.SecurityContext)
}

func (k *mqlK8sPod) dnsPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return string(spec.DNSPolicy), nil
}

func (k *mqlK8sPod) dnsConfig() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.DNSConfig)
}

func (k *mqlK8sPod) hostname() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.Hostname, nil
}

func (k *mqlK8sPod) subdomain() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return spec.Subdomain, nil
}

func (k *mqlK8sPod) hostAliases() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.HostAliases)
}

func (k *mqlK8sPod) restartPolicy() (string, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return "", err
	}
	return string(spec.RestartPolicy), nil
}

func (k *mqlK8sPod) terminationGracePeriodSeconds() (int64, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return 0, err
	}
	if spec.TerminationGracePeriodSeconds == nil {
		k.TerminationGracePeriodSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *spec.TerminationGracePeriodSeconds, nil
}

func (k *mqlK8sPod) activeDeadlineSeconds() (int64, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return 0, err
	}
	if spec.ActiveDeadlineSeconds == nil {
		k.ActiveDeadlineSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *spec.ActiveDeadlineSeconds, nil
}

func (k *mqlK8sPod) readinessGates() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.ReadinessGates)
}

func (k *mqlK8sPod) enableServiceLinks() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	if spec.EnableServiceLinks == nil {
		// Defaults to true when unset.
		return true, nil
	}
	return *spec.EnableServiceLinks, nil
}

func (k *mqlK8sPod) imagePullSecrets() ([]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(spec.ImagePullSecrets)
}

func (k *mqlK8sPod) overhead() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	if spec.Overhead == nil {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(spec.Overhead))
	for name, qty := range spec.Overhead {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sPod) os() (map[string]any, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(spec.OS)
}

func (k *mqlK8sPod) phase() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return string(pod.Status.Phase), nil
}

func (k *mqlK8sPod) qosClass() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return string(pod.Status.QOSClass), nil
}

func (k *mqlK8sPod) podIP() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.PodIP, nil
}

func (k *mqlK8sPod) podIPs() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	out := make([]any, len(pod.Status.PodIPs))
	for i, ip := range pod.Status.PodIPs {
		out[i] = ip.IP
	}
	return out, nil
}

func (k *mqlK8sPod) hostIP() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.HostIP, nil
}

func (k *mqlK8sPod) nominatedNodeName() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.NominatedNodeName, nil
}

func (k *mqlK8sPod) startTime() (*time.Time, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	if pod.Status.StartTime == nil {
		k.StartTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := pod.Status.StartTime.Time
	return &t, nil
}

func (k *mqlK8sPod) conditions() ([]any, error) {
	pod, err := k.getPod()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(pod.Status.Conditions)
}

func (k *mqlK8sPod) reason() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.Reason, nil
}

func (k *mqlK8sPod) message() (string, error) {
	pod, err := k.getPod()
	if err != nil {
		return "", err
	}
	return pod.Status.Message, nil
}

func (k *mqlK8sPod) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPod) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// ownerOfKind looks up the first owner reference matching kind and returns the
// (namespace, name) pair, or empty strings if not found.
func (k *mqlK8sPod) ownerOfKind(kind string) (string, string, bool) {
	pod, err := k.getPod()
	if err != nil {
		return "", "", false
	}
	for _, o := range pod.OwnerReferences {
		if o.Kind == kind {
			return pod.Namespace, o.Name, true
		}
	}
	return "", "", false
}

func (k *mqlK8sPod) replicaSet() (*mqlK8sReplicaset, error) {
	ns, name, ok := k.ownerOfKind("ReplicaSet")
	if !ok {
		k.ReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.replicaset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		// Pods can survive their owner mid-deletion or be re-parented to a
		// new ReplicaSet. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ReplicaSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sReplicaset), nil
}

func (k *mqlK8sPod) statefulSet() (*mqlK8sStatefulset, error) {
	ns, name, ok := k.ownerOfKind("StatefulSet")
	if !ok {
		k.StatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.statefulset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.StatefulSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sStatefulset), nil
}

func (k *mqlK8sPod) daemonSet() (*mqlK8sDaemonset, error) {
	ns, name, ok := k.ownerOfKind("DaemonSet")
	if !ok {
		k.DaemonSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.daemonset", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.DaemonSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sDaemonset), nil
}

func (k *mqlK8sPod) job() (*mqlK8sJob, error) {
	ns, name, ok := k.ownerOfKind("Job")
	if !ok {
		k.Job.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.job", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData(ns),
	})
	if err != nil {
		if errors.Is(err, ErrResourceNotFound) {
			k.Job.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sJob), nil
}

func (k *mqlK8sPod) deployment() (*mqlK8sDeployment, error) {
	// Pods are owned by a ReplicaSet, which is owned by a Deployment.
	rs, err := k.replicaSet()
	if err != nil || rs == nil {
		k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, err
	}
	rsTyped, err := rs.getReplicaSet()
	if err != nil {
		return nil, err
	}
	for _, o := range rsTyped.OwnerReferences {
		if o.Kind == "Deployment" {
			r, err := NewResource(k.MqlRuntime, "k8s.deployment", map[string]*llx.RawData{
				"name":      llx.StringData(o.Name),
				"namespace": llx.StringData(rsTyped.Namespace),
			})
			if err != nil {
				// A Deployment can be deleted while its ReplicaSet and
				// pods are still mid-cleanup. Resolve to null; surface
				// other errors (per PR #7884, type-assertion failures
				// inside getReplicaSet() above still propagate).
				if errors.Is(err, ErrResourceNotFound) {
					k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
					return nil, nil
				}
				return nil, err
			}
			return r.(*mqlK8sDeployment), nil
		}
	}
	k.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/utils/multierr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sNodeInternal struct {
	lock sync.Mutex
	obj  *corev1.Node
}

func initK8sNode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the node, if we have been supplied by its name and nothing else
	raw, ok := args["name"]
	if !ok || len(args) != 1 {
		return args, nil, nil
	}
	name := raw.Value.(string)

	k8sRaw, err := CreateResource(runtime, "k8s", nil)
	if err != nil {
		return nil, nil, multierr.Wrap(err, "cannot get list of nodes")
	}
	k8s := k8sRaw.(*mqlK8s)

	// k8s.lock here only protects against reading a half-populated nodesByName
	// while nodes() is mid-reset. It does NOT dedup concurrent GetNodes()
	// calls — two cold initK8sNode goroutines can both see empty == true and
	// both invoke GetNodes(); the MQL runtime's GetOrCompute handles that
	// dedup so only one nodes() body actually runs.
	k8s.lock.Lock()
	empty := len(k8s.nodesByName) == 0
	k8s.lock.Unlock()
	if empty {
		list := k8s.GetNodes()
		if list.Error != nil {
			return nil, nil, list.Error
		}
	}

	k8s.lock.Lock()
	x, found := k8s.nodesByName[name]
	k8s.lock.Unlock()
	if !found {
		// Wrap ErrResourceNotFound so callers can distinguish "node was
		// deleted" from a transient error via errors.Is — the existing
		// pod.node() accessor relies on this to resolve to null instead
		// of failing the query.
		return nil, nil, fmt.Errorf("cannot find node %s: %w", name, ErrResourceNotFound)
	}

	return nil, x, nil
}

func (k *mqlK8s) nodes() ([]any, error) {
	// Hold k.lock across the reset *and* the full population so a concurrent
	// initK8sNode cannot observe a half-populated nodesByName map. The MQL
	// runtime already deduplicates nodes() calls via the framework's TValue,
	// so the only readers blocked behind this lock are the ones whose result
	// depends on this evaluation finishing anyway.
	k.lock.Lock()
	defer k.lock.Unlock()
	k.nodesByName = make(map[string]*mqlK8sNode)
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("nodes")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		n, ok := obj.(*corev1.Node)
		if !ok {
			return nil, errors.New("not a k8s node")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.node", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"kubeletPort":     llx.IntData(n.Status.DaemonEndpoints.KubeletEndpoint.Port),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sNode).obj = n
		// k.lock is already held by the enclosing nodes() call.
		k.nodesByName[obj.GetName()] = r.(*mqlK8sNode)

		return r, nil
	})
}

func (k *mqlK8sNode) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sNode) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sNode) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sNode) nodeInfo() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status.NodeInfo)
}

func (k *mqlK8sNode) capacity() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status.Capacity)
}

func (k *mqlK8sNode) allocatable() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status.Allocatable)
}

func (k *mqlK8sNode) taints() ([]any, error) {
	uid := string(k.obj.GetUID())
	res := make([]any, 0, len(k.obj.Spec.Taints))
	for _, t := range k.obj.Spec.Taints {
		var timeAdded *time.Time
		if t.TimeAdded != nil {
			ta := t.TimeAdded.Time
			timeAdded = &ta
		}
		r, err := CreateResource(k.MqlRuntime, "k8s.nodeTaint", map[string]*llx.RawData{
			"__id":      llx.StringData(fmt.Sprintf("%s/taint/%s/%s", uid, t.Key, t.Effect)),
			"key":       llx.StringData(t.Key),
			"value":     llx.StringData(t.Value),
			"effect":    llx.StringData(string(t.Effect)),
			"timeAdded": llx.TimeDataPtr(timeAdded),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (k *mqlK8sNode) conditions() ([]any, error) {
	uid := string(k.obj.GetUID())
	res := make([]any, 0, len(k.obj.Status.Conditions))
	for _, c := range k.obj.Status.Conditions {
		r, err := CreateResource(k.MqlRuntime, "k8s.nodeCondition", map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("%s/condition/%s", uid, c.Type)),
			"type":               llx.StringData(string(c.Type)),
			"status":             llx.StringData(string(c.Status)),
			"lastHeartbeatTime":  llx.TimeData(c.LastHeartbeatTime.Time),
			"lastTransitionTime": llx.TimeData(c.LastTransitionTime.Time),
			"reason":             llx.StringData(c.Reason),
			"message":            llx.StringData(c.Message),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (k *mqlK8sNode) addresses() ([]any, error) {
	uid := string(k.obj.GetUID())
	res := make([]any, 0, len(k.obj.Status.Addresses))
	for _, a := range k.obj.Status.Addresses {
		r, err := CreateResource(k.MqlRuntime, "k8s.nodeAddress", map[string]*llx.RawData{
			"__id":    llx.StringData(fmt.Sprintf("%s/address/%s", uid, a.Type)),
			"type":    llx.StringData(string(a.Type)),
			"address": llx.StringData(a.Address),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (k *mqlK8sNode) providerID() (string, error) {
	return k.obj.Spec.ProviderID, nil
}

func (k *mqlK8sNode) unschedulable() (bool, error) {
	return k.obj.Spec.Unschedulable, nil
}

func (k *mqlK8sNode) podCIDR() (string, error) {
	return k.obj.Spec.PodCIDR, nil
}

func (k *mqlK8sNode) podCIDRs() ([]any, error) {
	return convert.SliceAnyToInterface(k.obj.Spec.PodCIDRs), nil
}

func (k *mqlK8sNode) osImage() (string, error) {
	return k.obj.Status.NodeInfo.OSImage, nil
}

func (k *mqlK8sNode) operatingSystem() (string, error) {
	return k.obj.Status.NodeInfo.OperatingSystem, nil
}

func (k *mqlK8sNode) architecture() (string, error) {
	return k.obj.Status.NodeInfo.Architecture, nil
}

func (k *mqlK8sNode) kernelVersion() (string, error) {
	return k.obj.Status.NodeInfo.KernelVersion, nil
}

func (k *mqlK8sNode) kubeletVersion() (string, error) {
	return k.obj.Status.NodeInfo.KubeletVersion, nil
}

func (k *mqlK8sNode) containerRuntimeVersion() (string, error) {
	return k.obj.Status.NodeInfo.ContainerRuntimeVersion, nil
}

func (k *mqlK8sNode) runtimeDelegates() ([]any, error) {
	runtimeKind := runtimeKindFromVersion(k.obj.Status.NodeInfo.ContainerRuntimeVersion)
	if runtimeKind == "" {
		return []any{}, nil
	}
	if settings, err := runtimeCacheSettingsFromRuntime(k.MqlRuntime); err != nil {
		return nil, err
	} else if settings != nil {
		delegatesByKind := runtimeCacheDelegatesByKind(settings.Delegates)
		delegates := delegatesByKind[runtimeKind]
		out := make([]any, 0, len(delegates))
		for _, delegate := range delegates {
			r, err := createSharedRuntimeResource(k.MqlRuntime, "container.runtimeDelegate", runtimeDelegateArgsFromRuntimeCacheDelegate(k.obj.GetName(), settings, delegate))
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	delegate, err := createSharedRuntimeResource(k.MqlRuntime, "container.runtimeDelegate", runtimeDelegateArgsFromK8sNode(k.obj.GetName(), runtimeKind))
	if err != nil {
		return nil, err
	}
	return []any{delegate}, nil
}

func (k *mqlK8sNode) images() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.Images)
}

func (k *mqlK8sNode) runtimeImages() ([]any, error) {
	out := make([]any, 0, len(k.obj.Status.Images))
	runtimeKind := runtimeKindFromVersion(k.obj.Status.NodeInfo.ContainerRuntimeVersion)
	for _, image := range k.obj.Status.Images {
		args := runtimeImageArgsFromK8sNames(k.obj.GetName(), runtimeKind, image.Names, image.SizeBytes, nil, "pending")
		img, err := createSharedRuntimeResource(k.MqlRuntime, "container.runtimeImage", args)
		if err != nil {
			return nil, err
		}
		out = append(out, img)
	}
	return out, nil
}

func createSharedRuntimeResource(runtime *plugin.Runtime, name string, args map[string]*llx.RawData) (plugin.Resource, error) {
	if runtime == nil || runtime.Callback == nil {
		return nil, errors.New("shared container runtime resources require provider callback")
	}
	return runtime.CreateSharedResource(name, args)
}

func (k *mqlK8sNode) volumesAttached() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.VolumesAttached)
}

func (k *mqlK8sNode) volumesInUse() ([]any, error) {
	out := make([]any, len(k.obj.Status.VolumesInUse))
	for i, v := range k.obj.Status.VolumesInUse {
		out[i] = string(v)
	}
	return out, nil
}

func (k *mqlK8sNode) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sNode) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// nodeRuntimeHandlerFeatures reports whether any advertised runtime handler
// supports the named feature. It returns (value, true) only when at least one
// handler carries a features block; a kubelet that advertises no features at
// all yields (false, false), which the accessors report as null. Reporting
// false there would claim the node cannot do something it never spoke about.
func nodeRuntimeHandlerFeatures(handlers []corev1.NodeRuntimeHandler, pick func(*corev1.NodeRuntimeHandlerFeatures) *bool) (bool, bool) {
	reported := false
	supported := false
	for i := range handlers {
		f := handlers[i].Features
		if f == nil {
			continue
		}
		v := pick(f)
		if v == nil {
			continue
		}
		reported = true
		if *v {
			supported = true
		}
	}
	return supported, reported
}

func (k *mqlK8sNode) runtimeHandlers() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.RuntimeHandlers)
}

func (k *mqlK8sNode) supportsUserNamespaces() (bool, error) {
	supported, reported := nodeRuntimeHandlerFeatures(k.obj.Status.RuntimeHandlers,
		func(f *corev1.NodeRuntimeHandlerFeatures) *bool { return f.UserNamespaces })
	if !reported {
		k.SupportsUserNamespaces.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return supported, nil
}

func (k *mqlK8sNode) supportsSupplementalGroupsPolicy() (bool, error) {
	features := k.obj.Status.Features
	if features == nil || features.SupplementalGroupsPolicy == nil {
		k.SupportsSupplementalGroupsPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *features.SupplementalGroupsPolicy, nil
}

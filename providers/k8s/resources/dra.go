// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/resources/dra"
	"go.mondoo.com/mql/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// The DRA kinds are looked up by their plural name without a group or version.
// Discovery reports one preferred version per group, so the plural name
// resolves to whichever of v1beta1, v1beta2 or v1 the cluster serves.
const (
	deviceClassKind           = "deviceclasses"
	resourceSliceKind         = "resourceslices"
	resourceClaimKind         = "resourceclaims"
	resourceClaimTemplateKind = "resourceclaimtemplates"
)

type mqlK8sDeviceclassInternal struct {
	obj metav1.Object
}

type mqlK8sResourcesliceInternal struct {
	obj metav1.Object
}

type mqlK8sResourceclaimInternal struct {
	obj              metav1.Object
	reservedPodNames []string
}

type mqlK8sResourceclaimtemplateInternal struct {
	obj metav1.Object
}

func (k *mqlK8s) deviceClasses() ([]any, error) {
	return k8sOptionalResourceToMql(k.MqlRuntime, deviceClassKind, func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		class, err := dra.Decode[dra.DeviceClass](resource)
		if err != nil {
			return nil, err
		}

		selectors, err := convert.JsonToDictSlice(class.Spec.Selectors)
		if err != nil {
			return nil, err
		}
		config, err := convert.JsonToDictSlice(class.Spec.Config)
		if err != nil {
			return nil, err
		}

		ts := obj.GetCreationTimestamp()
		r, err := CreateResource(k.MqlRuntime, "k8s.deviceclass", map[string]*llx.RawData{
			"id":                   llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                  llx.StringData(string(obj.GetUID())),
			"resourceVersion":      llx.StringData(obj.GetResourceVersion()),
			"name":                 llx.StringData(obj.GetName()),
			"kind":                 llx.StringData(objT.GetKind()),
			"created":              llx.TimeData(ts.Time),
			"selectors":            llx.ArrayData(selectors, types.Dict),
			"config":               llx.ArrayData(config, types.Dict),
			"extendedResourceName": llx.StringData(class.Spec.ExtendedResourceName),
			"selectsAllDevices":    llx.BoolData(len(class.Spec.Selectors) == 0),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sDeviceclass).obj = obj
		return r, nil
	})
}

func (k *mqlK8s) resourceSlices() ([]any, error) {
	return k8sOptionalResourceToMql(k.MqlRuntime, resourceSliceKind, func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		slice, err := dra.Decode[dra.ResourceSlice](resource)
		if err != nil {
			return nil, err
		}

		devices, err := convert.JsonToDictSlice(draDeviceDicts(slice.Spec.Devices))
		if err != nil {
			return nil, err
		}
		nodeSelector, err := convert.JsonToDict(slice.Spec.NodeSelector)
		if err != nil {
			return nil, err
		}

		ts := obj.GetCreationTimestamp()
		r, err := CreateResource(k.MqlRuntime, "k8s.resourceslice", map[string]*llx.RawData{
			"id":                     llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                    llx.StringData(string(obj.GetUID())),
			"resourceVersion":        llx.StringData(obj.GetResourceVersion()),
			"name":                   llx.StringData(obj.GetName()),
			"kind":                   llx.StringData(objT.GetKind()),
			"created":                llx.TimeData(ts.Time),
			"driver":                 llx.StringData(slice.Spec.Driver),
			"poolName":               llx.StringData(slice.Spec.Pool.Name),
			"poolGeneration":         llx.IntData(slice.Spec.Pool.Generation),
			"poolResourceSliceCount": llx.IntData(slice.Spec.Pool.ResourceSliceCount),
			"nodeName":               llx.StringData(slice.Spec.NodeName),
			"allNodes":               llx.BoolData(slice.Spec.AllNodes),
			"perDeviceNodeSelection": llx.BoolData(slice.Spec.PerDeviceNodeSelection),
			"nodeSelector":           llx.DictData(nodeSelector),
			"devices":                llx.ArrayData(devices, types.Dict),
			"deviceNames":            llx.ArrayData(convert.SliceAnyToInterface(slice.Spec.DeviceNames()), types.String),
			"deviceCount":            llx.IntData(int64(len(slice.Spec.Devices))),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sResourceslice).obj = obj
		return r, nil
	})
}

func (k *mqlK8s) resourceClaims() ([]any, error) {
	return k8sOptionalResourceToMql(k.MqlRuntime, resourceClaimKind, func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		claim, err := dra.Decode[dra.ResourceClaim](resource)
		if err != nil {
			return nil, err
		}

		args, err := draClaimSpecArgs(claim.Spec.Devices)
		if err != nil {
			return nil, err
		}

		allocatedDevices, err := convert.JsonToDictSlice(claim.Status.AllocatedDevices())
		if err != nil {
			return nil, err
		}
		reservedFor, err := convert.JsonToDictSlice(claim.Status.ReservedFor)
		if err != nil {
			return nil, err
		}
		deviceStatuses, err := convert.JsonToDictSlice(claim.Status.Devices)
		if err != nil {
			return nil, err
		}
		var allocationNodeSelector map[string]any
		if claim.Status.Allocation != nil {
			allocationNodeSelector, err = convert.JsonToDict(claim.Status.Allocation.NodeSelector)
			if err != nil {
				return nil, err
			}
		}

		ts := obj.GetCreationTimestamp()
		args["id"] = llx.StringData(objIdFromK8sObj(obj, objT))
		args["uid"] = llx.StringData(string(obj.GetUID()))
		args["resourceVersion"] = llx.StringData(obj.GetResourceVersion())
		args["name"] = llx.StringData(obj.GetName())
		args["namespace"] = llx.StringData(obj.GetNamespace())
		args["kind"] = llx.StringData(objT.GetKind())
		args["created"] = llx.TimeData(ts.Time)
		args["allocated"] = llx.BoolData(claim.Status.Allocated())
		args["allocatedDevices"] = llx.ArrayData(allocatedDevices, types.Dict)
		args["allocationNodeSelector"] = llx.DictData(allocationNodeSelector)
		args["reservedFor"] = llx.ArrayData(reservedFor, types.Dict)
		args["deviceStatuses"] = llx.ArrayData(deviceStatuses, types.Dict)
		args["usesAdminAccess"] = llx.BoolData(claim.Status.UsesAdminAccess())

		r, err := CreateResource(k.MqlRuntime, "k8s.resourceclaim", args)
		if err != nil {
			return nil, err
		}
		mqlClaim := r.(*mqlK8sResourceclaim)
		mqlClaim.obj = obj
		mqlClaim.reservedPodNames = claim.Status.ReservedPodNames()
		return r, nil
	})
}

func (k *mqlK8s) resourceClaimTemplates() ([]any, error) {
	return k8sOptionalResourceToMql(k.MqlRuntime, resourceClaimTemplateKind, func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		template, err := dra.Decode[dra.ResourceClaimTemplate](resource)
		if err != nil {
			return nil, err
		}

		args, err := draClaimSpecArgs(template.Spec.Spec.Devices)
		if err != nil {
			return nil, err
		}

		ts := obj.GetCreationTimestamp()
		args["id"] = llx.StringData(objIdFromK8sObj(obj, objT))
		args["uid"] = llx.StringData(string(obj.GetUID()))
		args["resourceVersion"] = llx.StringData(obj.GetResourceVersion())
		args["name"] = llx.StringData(obj.GetName())
		args["namespace"] = llx.StringData(obj.GetNamespace())
		args["kind"] = llx.StringData(objT.GetKind())
		args["created"] = llx.TimeData(ts.Time)
		args["usesAdminAccess"] = llx.BoolData(template.Spec.Spec.Devices.UsesAdminAccess())
		args["templateLabels"] = llx.MapData(convert.MapToInterfaceMap(template.Spec.Metadata.Labels), types.String)
		args["templateAnnotations"] = llx.MapData(convert.MapToInterfaceMap(template.Spec.Metadata.Annotations), types.String)

		r, err := CreateResource(k.MqlRuntime, "k8s.resourceclaimtemplate", args)
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sResourceclaimtemplate).obj = obj
		return r, nil
	})
}

// draClaimSpecArgs maps the request side of a claim or a claim template.
//
// A ResourceClaimTemplate embeds the same DeviceClaim a ResourceClaim carries,
// so both resources report the intent through the same fields.
func draClaimSpecArgs(claim dra.DeviceClaim) (map[string]*llx.RawData, error) {
	requests, err := convert.JsonToDictSlice(claim.Requests)
	if err != nil {
		return nil, err
	}
	constraints, err := convert.JsonToDictSlice(claim.Constraints)
	if err != nil {
		return nil, err
	}
	return map[string]*llx.RawData{
		"requests":         llx.ArrayData(requests, types.Dict),
		"requestNames":     llx.ArrayData(convert.SliceAnyToInterface(claim.DeviceRequestNames()), types.String),
		"deviceClassNames": llx.ArrayData(convert.SliceAnyToInterface(claim.DeviceClassNames()), types.String),
		"constraints":      llx.ArrayData(constraints, types.Dict),
	}, nil
}

// draDeviceDicts renders the devices of a slice with their attributes and
// capacities flattened to strings, so a policy can read `pciAddress` without
// having to know which value member the driver used.
func draDeviceDicts(devices []dra.Device) []map[string]any {
	out := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		out = append(out, map[string]any{
			"name":                     device.Name,
			"attributes":               device.StringAttributes(),
			"capacity":                 device.Capacities(),
			"allowMultipleAllocations": device.AllowMultipleAllocations,
			"nodeName":                 device.NodeName,
			"allNodes":                 device.AllNodes,
			"taints":                   device.Taints,
			"bindingConditions":        device.BindingConditions,
		})
	}
	return out
}

func (k *mqlK8sDeviceclass) id() (string, error) { return k.Id.Data, nil }

func (k *mqlK8sDeviceclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sDeviceclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sDeviceclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sDeviceclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sDeviceclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceslice) id() (string, error) { return k.Id.Data, nil }

func (k *mqlK8sResourceslice) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sResourceslice) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sResourceslice) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sResourceslice) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceslice) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceslice) node() (*mqlK8sNode, error) {
	// A pool that spans nodes has no single owning node.
	if k.NodeName.Data == "" {
		k.Node.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	node, err := NewResource(k.MqlRuntime, "k8s.node", map[string]*llx.RawData{
		"name": llx.StringData(k.NodeName.Data),
	})
	if err != nil {
		// Nodes are cluster-scoped, so they aren't loaded when queried from a
		// namespace-scoped asset, and a node can be removed while its slices
		// are still being garbage collected. Resolve to null; surface other
		// errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Node.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return node.(*mqlK8sNode), nil
}

func (k *mqlK8sResourceclaim) id() (string, error) { return k.Id.Data, nil }

func (k *mqlK8sResourceclaim) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sResourceclaim) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sResourceclaim) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sResourceclaim) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceclaim) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceclaim) reservedForPods() ([]any, error) {
	pods := []any{}
	for _, name := range k.reservedPodNames {
		pod, err := NewResource(k.MqlRuntime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData(name),
			"namespace": llx.StringData(k.Namespace.Data),
		})
		if err != nil {
			// A pod can be deleted while the kubelet still holds the
			// reservation, and pods are not loaded for a cluster-scoped
			// manifest scan. Skip the entry; surface other errors.
			if errors.Is(err, ErrResourceNotFound) {
				continue
			}
			return nil, err
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

func initK8sResourceclaim(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sResourceclaim](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] {
		return k.GetResourceClaims()
	})
}

func (k *mqlK8sResourceclaimtemplate) id() (string, error) { return k.Id.Data, nil }

func (k *mqlK8sResourceclaimtemplate) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sResourceclaimtemplate) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sResourceclaimtemplate) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sResourceclaimtemplate) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourceclaimtemplate) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func initK8sResourceclaimtemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sResourceclaimtemplate](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] {
		return k.GetResourceClaimTemplates()
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sRuntimeclassInternal struct {
	lock sync.Mutex
	obj  *nodev1.RuntimeClass
}

func (k *mqlK8s) runtimeClasses() ([]any, error) {
	// node.k8s.io/v1 has been GA since 1.20, but a cluster can still hide the
	// kind behind RBAC, so an unavailable kind degrades to an empty list
	// rather than failing every query that touches it.
	return k8sOptionalResourceToMql(k.MqlRuntime, gvkString(nodev1.SchemeGroupVersion.WithKind("runtimeclasses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		rc, ok := resource.(*nodev1.RuntimeClass)
		if !ok {
			return nil, errors.New("not a k8s runtimeclass")
		}

		overhead := map[string]any{}
		if rc.Overhead != nil {
			for name, quantity := range rc.Overhead.PodFixed {
				overhead[string(name)] = quantity.String()
			}
		}

		args := map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"handler":         llx.StringData(rc.Handler),
			"overhead":        llx.MapData(overhead, types.String),
			"scheduling":      llx.NilData,
		}

		// A RuntimeClass with no scheduling block places no restriction on
		// which nodes run its pods. Report that as null rather than as an
		// empty selector, which would read as "restricted to nothing".
		if rc.Scheduling != nil {
			scheduling, err := convert.JsonToDict(rc.Scheduling)
			if err != nil {
				return nil, err
			}
			args["scheduling"] = llx.DictData(scheduling)
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.runtimeclass", args)
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sRuntimeclass).obj = rc
		return r, nil
	})
}

func (k *mqlK8sRuntimeclass) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sRuntimeclass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sRuntimeclass](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetRuntimeClasses() })
}

func (k *mqlK8sRuntimeclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sRuntimeclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sRuntimeclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sRuntimeclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sRuntimeclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// pods returns the pods that name this RuntimeClass. This is the edge that
// answers which workloads actually land on a sandboxed runtime, rather than
// which classes merely exist.
func (k *mqlK8sRuntimeclass) pods() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	pods := o.(*mqlK8s).GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	out := []any{}
	for i := range pods.Data {
		p, ok := pods.Data[i].(*mqlK8sPod)
		if !ok {
			continue
		}
		name := p.GetRuntimeClassName()
		if name.Error != nil || name.Data != k.Name.Data {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

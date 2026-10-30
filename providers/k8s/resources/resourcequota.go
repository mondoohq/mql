// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sResourcequotaInternal struct {
	lock sync.Mutex
	obj  *corev1.ResourceQuota
}

func (k *mqlK8s) resourceQuotas() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("resourcequotas")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		rq, ok := resource.(*corev1.ResourceQuota)
		if !ok {
			return nil, errors.New("not a k8s resourcequota")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.resourcequota", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sResourcequota).obj = rq
		return r, nil
	})
}

func (k *mqlK8sResourcequota) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sResourcequota) spec() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec)
}

func (k *mqlK8sResourcequota) status() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status)
}

func (k *mqlK8sResourcequota) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sResourcequota(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sResourcequota](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetResourceQuotas() })
}

func (k *mqlK8sResourcequota) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sResourcequota) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sResourcequota) hard() (map[string]any, error) {
	out := make(map[string]any, len(k.obj.Spec.Hard))
	for name, qty := range k.obj.Spec.Hard {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sResourcequota) used() (map[string]any, error) {
	out := make(map[string]any, len(k.obj.Status.Used))
	for name, qty := range k.obj.Status.Used {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sResourcequota) scopes() ([]any, error) {
	out := make([]any, len(k.obj.Spec.Scopes))
	for i, s := range k.obj.Spec.Scopes {
		out[i] = string(s)
	}
	return out, nil
}

func (k *mqlK8sResourcequota) scopeSelector() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.ScopeSelector)
}

func (k *mqlK8sResourcequota) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sResourcequota) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

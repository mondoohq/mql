// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sIngressclassInternal struct {
	lock sync.Mutex
	obj  *networkingv1.IngressClass
}

func (k *mqlK8s) ingressClasses() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(networkingv1.SchemeGroupVersion.WithKind("ingressclasses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		ic, ok := resource.(*networkingv1.IngressClass)
		if !ok {
			return nil, errors.New("not a k8s ingressclass")
		}

		// convert.JsonToDict(nil) yields {}, which reads as a configured but
		// empty parameters reference rather than an absent one.
		parametersData := llx.NilData
		if ic.Spec.Parameters != nil {
			parameters, err := convert.JsonToDict(ic.Spec.Parameters)
			if err != nil {
				return nil, err
			}
			parametersData = llx.DictData(parameters)
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.ingressclass", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"controller":      llx.StringData(ic.Spec.Controller),
			"parameters":      parametersData,
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sIngressclass).obj = ic
		return r, nil
	})
}

func (k *mqlK8sIngressclass) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sIngressclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sIngressclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sIngressclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sIngressclass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sIngressclass](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetIngressClasses() })
}

func (k *mqlK8sIngressclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sIngressclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

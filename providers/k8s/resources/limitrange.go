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

type mqlK8sLimitrangeInternal struct {
	lock sync.Mutex
	obj  *corev1.LimitRange
}

func (k *mqlK8s) limitRanges() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("limitranges")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		lr, ok := resource.(*corev1.LimitRange)
		if !ok {
			return nil, errors.New("not a k8s limitrange")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.limitrange", map[string]*llx.RawData{
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
		r.(*mqlK8sLimitrange).obj = lr
		return r, nil
	})
}

func (k *mqlK8sLimitrange) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sLimitrange) spec() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec)
}

func (k *mqlK8sLimitrange) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sLimitrange(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sLimitrange](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetLimitRanges() })
}

func (k *mqlK8sLimitrange) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sLimitrange) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sLimitrange) limits() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Spec.Limits)
}

func (k *mqlK8sLimitrange) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sLimitrange) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	schedulingv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sPriorityclassInternal struct {
	lock sync.Mutex
	obj  *schedulingv1.PriorityClass
}

func (k *mqlK8s) priorityClasses() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(schedulingv1.SchemeGroupVersion.WithKind("priorityclasses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		pc, ok := resource.(*schedulingv1.PriorityClass)
		if !ok {
			return nil, errors.New("not a k8s priorityclass")
		}

		var preemptionPolicy string
		if pc.PreemptionPolicy != nil {
			preemptionPolicy = string(*pc.PreemptionPolicy)
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.priorityclass", map[string]*llx.RawData{
			"id":               llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":              llx.StringData(string(obj.GetUID())),
			"resourceVersion":  llx.StringData(obj.GetResourceVersion()),
			"name":             llx.StringData(obj.GetName()),
			"kind":             llx.StringData(objT.GetKind()),
			"created":          llx.TimeData(ts.Time),
			"value":            llx.IntData(int64(pc.Value)),
			"globalDefault":    llx.BoolData(pc.GlobalDefault),
			"preemptionPolicy": llx.StringData(preemptionPolicy),
			"description":      llx.StringData(pc.Description),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sPriorityclass).obj = pc
		return r, nil
	})
}

func (k *mqlK8sPriorityclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sPriorityclass) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sPriorityclass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sPriorityclass](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPriorityClasses() })
}

func (k *mqlK8sPriorityclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sPriorityclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sPriorityclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPriorityclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

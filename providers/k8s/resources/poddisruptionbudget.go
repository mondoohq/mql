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
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// intOrStringToAny returns the IntOrString's underlying scalar so it can be
// stored in a `dict` field (which may legitimately be an int or a string).
func intOrStringToAny(v *intstr.IntOrString) any {
	if v == nil {
		return nil
	}
	if v.Type == intstr.Int {
		return int64(v.IntVal)
	}
	return v.StrVal
}

type mqlK8sPoddisruptionbudgetInternal struct {
	lock sync.Mutex
	obj  *policyv1.PodDisruptionBudget
}

func (k *mqlK8s) podDisruptionBudgets() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(policyv1.SchemeGroupVersion.WithKind("PodDisruptionBudget")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		pdb, ok := resource.(*policyv1.PodDisruptionBudget)
		if !ok {
			return nil, errors.New("not a k8s poddisruptionbudget")
		}

		minAvailable := intOrStringToAny(pdb.Spec.MinAvailable)
		maxUnavailable := intOrStringToAny(pdb.Spec.MaxUnavailable)
		selector, err := convert.JsonToDict(pdb.Spec.Selector)
		if err != nil {
			return nil, err
		}
		// The API server does not default this field. nil means "IfHealthyBudget
		// applies by default", which is a different statement from the object
		// setting the empty string, and "" is not one of the enum's values.
		unhealthyPolicy := stringPtrFromTypedPtr(pdb.Spec.UnhealthyPodEvictionPolicy)
		conditions, err := convert.JsonToDictSlice(pdb.Status.Conditions)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.poddisruptionbudget", map[string]*llx.RawData{
			"id":                         llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                        llx.StringData(string(obj.GetUID())),
			"resourceVersion":            llx.StringData(obj.GetResourceVersion()),
			"name":                       llx.StringData(obj.GetName()),
			"namespace":                  llx.StringData(obj.GetNamespace()),
			"kind":                       llx.StringData(objT.GetKind()),
			"created":                    llx.TimeData(ts.Time),
			"minAvailable":               llx.DictData(minAvailable),
			"maxUnavailable":             llx.DictData(maxUnavailable),
			"selector":                   llx.DictData(selector),
			"unhealthyPodEvictionPolicy": llx.StringDataPtr(unhealthyPolicy),
			"currentHealthy":             llx.IntData(int64(pdb.Status.CurrentHealthy)),
			"desiredHealthy":             llx.IntData(int64(pdb.Status.DesiredHealthy)),
			"expectedPods":               llx.IntData(int64(pdb.Status.ExpectedPods)),
			"disruptionsAllowed":         llx.IntData(int64(pdb.Status.DisruptionsAllowed)),
			"observedGeneration":         llx.IntData(pdb.Status.ObservedGeneration),
			"conditions":                 llx.ArrayData(conditions, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sPoddisruptionbudget).obj = pdb
		return r, nil
	})
}

func (k *mqlK8sPoddisruptionbudget) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sPoddisruptionbudget) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sPoddisruptionbudget) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sPoddisruptionbudget) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sPoddisruptionbudget(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sPoddisruptionbudget](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPodDisruptionBudgets() })
}

func (k *mqlK8sPoddisruptionbudget) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPoddisruptionbudget) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type mqlK8sHttprouteInternal struct {
	lock sync.Mutex
	obj  *gatewayv1.HTTPRoute
}

func (k *mqlK8s) httpRoutes() ([]any, error) {
	// Gateway API ships as CRDs, so a cluster that never installed them has no
	// such kind. That is a cluster with no Gateways, not a failed scan, so the
	// list degrades to empty rather than erroring.
	return k8sOptionalResourceToMql(k.MqlRuntime, gvkString(gatewayv1.SchemeGroupVersion.WithKind("httproutes")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		hr, ok := resource.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil, errors.New("not a k8s httproute")
		}

		parentRefs, err := convert.JsonToDictSlice(hr.Spec.ParentRefs)
		if err != nil {
			return nil, err
		}

		hostnames := make([]any, len(hr.Spec.Hostnames))
		for i, h := range hr.Spec.Hostnames {
			hostnames[i] = string(h)
		}

		rules, err := convert.JsonToDictSlice(hr.Spec.Rules)
		if err != nil {
			return nil, err
		}

		parentStatus, err := convert.JsonToDictSlice(hr.Status.Parents)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.httproute", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"parentRefs":      llx.ArrayData(parentRefs, types.Dict),
			"hostnames":       llx.ArrayData(hostnames, types.String),
			"rules":           llx.ArrayData(rules, types.Dict),
			"parentStatus":    llx.ArrayData(parentStatus, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sHttproute).obj = hr
		return r, nil
	})
}

func (k *mqlK8sHttproute) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sHttproute) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sHttproute) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sHttproute) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sHttproute(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sHttproute](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetHttpRoutes() })
}

func (k *mqlK8sHttproute) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sHttproute) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

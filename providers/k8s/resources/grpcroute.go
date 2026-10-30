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

type mqlK8sGrpcrouteInternal struct {
	lock sync.Mutex
	obj  *gatewayv1.GRPCRoute
}

func (k *mqlK8s) grpcRoutes() ([]any, error) {
	// Gateway API ships as CRDs, so a cluster that never installed them has no
	// such kind. That is a cluster with no Gateways, not a failed scan, so the
	// list degrades to empty rather than erroring.
	return k8sOptionalResourceToMql(k.MqlRuntime, gvkString(gatewayv1.SchemeGroupVersion.WithKind("grpcroutes")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		gr, ok := resource.(*gatewayv1.GRPCRoute)
		if !ok {
			return nil, errors.New("not a k8s grpcroute")
		}

		parentRefs, err := convert.JsonToDictSlice(gr.Spec.ParentRefs)
		if err != nil {
			return nil, err
		}

		hostnames := make([]any, len(gr.Spec.Hostnames))
		for i, h := range gr.Spec.Hostnames {
			hostnames[i] = string(h)
		}

		rules, err := convert.JsonToDictSlice(gr.Spec.Rules)
		if err != nil {
			return nil, err
		}

		parentStatus, err := convert.JsonToDictSlice(gr.Status.Parents)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.grpcroute", map[string]*llx.RawData{
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
		r.(*mqlK8sGrpcroute).obj = gr
		return r, nil
	})
}

func (k *mqlK8sGrpcroute) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sGrpcroute) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sGrpcroute) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sGrpcroute) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sGrpcroute(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sGrpcroute](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetGrpcRoutes() })
}

func (k *mqlK8sGrpcroute) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sGrpcroute) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

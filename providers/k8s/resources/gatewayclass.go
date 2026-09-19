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

type mqlK8sGatewayclassInternal struct {
	lock sync.Mutex
	obj  *gatewayv1.GatewayClass
}

func (k *mqlK8s) gatewayClasses() ([]any, error) {
	// Gateway API ships as CRDs, so a cluster that never installed them has no
	// such kind. That is a cluster with no Gateways, not a failed scan, so the
	// list degrades to empty rather than erroring.
	return k8sOptionalResourceToMql(k.MqlRuntime, gvkString(gatewayv1.SchemeGroupVersion.WithKind("gatewayclasses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		gc, ok := resource.(*gatewayv1.GatewayClass)
		if !ok {
			return nil, errors.New("not a k8s gatewayclass")
		}

		// A GatewayClass that takes no parameters has no parametersRef at
		// all; {} would claim the controller was handed an empty one.
		parametersRefData := llx.NilData
		if gc.Spec.ParametersRef != nil {
			parametersRef, err := convert.JsonToDict(gc.Spec.ParametersRef)
			if err != nil {
				return nil, err
			}
			parametersRefData = llx.DictData(parametersRef)
		}

		conditions, err := convert.JsonToDictSlice(gc.Status.Conditions)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.gatewayclass", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"controllerName":  llx.StringData(string(gc.Spec.ControllerName)),
			"description":     llx.StringDataPtr(gc.Spec.Description),
			"parametersRef":   parametersRefData,
			"conditions":      llx.ArrayData(conditions, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sGatewayclass).obj = gc
		return r, nil
	})
}

func (k *mqlK8sGatewayclass) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sGatewayclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sGatewayclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sGatewayclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sGatewayclass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sGatewayclass](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetGatewayClasses() })
}

func (k *mqlK8sGatewayclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sGatewayclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

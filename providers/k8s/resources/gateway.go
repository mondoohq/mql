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

type mqlK8sGatewayInternal struct {
	lock sync.Mutex
	obj  *gatewayv1.Gateway
}

func (k *mqlK8s) gateways() ([]any, error) {
	// Gateway API ships as CRDs, so a cluster that never installed them has no
	// such kind. That is a cluster with no Gateways, not a failed scan, so the
	// list degrades to empty rather than erroring.
	return k8sOptionalResourceToMql(k.MqlRuntime, gvkString(gatewayv1.SchemeGroupVersion.WithKind("gateways")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		gw, ok := resource.(*gatewayv1.Gateway)
		if !ok {
			return nil, errors.New("not a k8s gateway")
		}

		listeners, err := convert.JsonToDictSlice(gw.Spec.Listeners)
		if err != nil {
			return nil, err
		}

		addresses, err := convert.JsonToDictSlice(gw.Spec.Addresses)
		if err != nil {
			return nil, err
		}

		// A Gateway with no infrastructure block has none; {} would claim the
		// controller was handed an empty one.
		infrastructureData := llx.NilData
		if gw.Spec.Infrastructure != nil {
			infrastructure, err := convert.JsonToDict(gw.Spec.Infrastructure)
			if err != nil {
				return nil, err
			}
			infrastructureData = llx.DictData(infrastructure)
		}

		statusAddresses, err := convert.JsonToDictSlice(gw.Status.Addresses)
		if err != nil {
			return nil, err
		}

		listenerStatus, err := convert.JsonToDictSlice(gw.Status.Listeners)
		if err != nil {
			return nil, err
		}

		conditions, err := convert.JsonToDictSlice(gw.Status.Conditions)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.gateway", map[string]*llx.RawData{
			"id":               llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":              llx.StringData(string(obj.GetUID())),
			"resourceVersion":  llx.StringData(obj.GetResourceVersion()),
			"name":             llx.StringData(obj.GetName()),
			"namespace":        llx.StringData(obj.GetNamespace()),
			"kind":             llx.StringData(objT.GetKind()),
			"created":          llx.TimeData(ts.Time),
			"gatewayClassName": llx.StringData(string(gw.Spec.GatewayClassName)),
			"listeners":        llx.ArrayData(listeners, types.Dict),
			"addresses":        llx.ArrayData(addresses, types.Dict),
			"infrastructure":   infrastructureData,
			"statusAddresses":  llx.ArrayData(statusAddresses, types.Dict),
			"listenerStatus":   llx.ArrayData(listenerStatus, types.Dict),
			"conditions":       llx.ArrayData(conditions, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sGateway).obj = gw
		return r, nil
	})
}

func (k *mqlK8sGateway) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sGateway) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sGateway) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sGateway) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sGateway) gatewayClass() (*mqlK8sGatewayclass, error) {
	name := k.GatewayClassName.Data
	if name == "" {
		k.GatewayClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	classes := o.(*mqlK8s).GetGatewayClasses()
	if classes.Error != nil {
		return nil, classes.Error
	}

	for i := range classes.Data {
		gc, ok := classes.Data[i].(*mqlK8sGatewayclass)
		if !ok {
			continue
		}
		if gc.Name.Data == name {
			return gc, nil
		}
	}

	k.GatewayClass.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func initK8sGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sGateway](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetGateways() })
}

func (k *mqlK8sGateway) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sGateway) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

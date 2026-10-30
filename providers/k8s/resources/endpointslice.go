// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sEndpointsliceInternal struct {
	lock sync.Mutex
	obj  *discoveryv1.EndpointSlice
}

func (k *mqlK8s) endpointSlices() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(discoveryv1.SchemeGroupVersion.WithKind("endpointslices")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		es, ok := resource.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil, errors.New("not a k8s endpointslice")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.endpointslice", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"addressType":     llx.StringData(string(es.AddressType)),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sEndpointslice).obj = es
		return r, nil
	})
}

func (k *mqlK8sEndpointslice) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sEndpointslice) endpoints() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Endpoints)
}

func (k *mqlK8sEndpointslice) ports() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Ports)
}

func (k *mqlK8sEndpointslice) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sEndpointslice(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sEndpointslice](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetEndpointSlices() })
}

func (k *mqlK8sEndpointslice) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sEndpointslice) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sEndpointslice) service() (*mqlK8sService, error) {
	svcName := k.obj.Labels["kubernetes.io/service-name"]
	if svcName == "" {
		k.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.service", map[string]*llx.RawData{
		"name":      llx.StringData(svcName),
		"namespace": llx.StringData(k.obj.Namespace),
	})
	if err != nil {
		// EndpointSlices may outlive the Service they back (mid-deletion or
		// hand-managed slices). Treat that as null, surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Service.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sService), nil
}

func (k *mqlK8sEndpointslice) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sEndpointslice) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

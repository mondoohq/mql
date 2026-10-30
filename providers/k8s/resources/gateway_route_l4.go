// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type mqlK8sTlsrouteInternal struct {
	obj *unstructured.Unstructured
}

type mqlK8sTcprouteInternal struct {
	obj *unstructured.Unstructured
}

type mqlK8sUdprouteInternal struct {
	obj *unstructured.Unstructured
}

var (
	tlsRouteResourceKinds = []string{
		"tlsroutes.v1.gateway.networking.k8s.io",
		"tlsroutes.v1beta1.gateway.networking.k8s.io",
		"tlsroutes.v1alpha2.gateway.networking.k8s.io",
	}
	tcpRouteResourceKinds = []string{
		"tcproutes.v1.gateway.networking.k8s.io",
		"tcproutes.v1beta1.gateway.networking.k8s.io",
		"tcproutes.v1alpha2.gateway.networking.k8s.io",
	}
	udpRouteResourceKinds = []string{
		"udproutes.v1.gateway.networking.k8s.io",
		"udproutes.v1beta1.gateway.networking.k8s.io",
		"udproutes.v1alpha2.gateway.networking.k8s.io",
	}
)

func (k *mqlK8s) tlsRoutes() ([]any, error) {
	return gatewayRouteResources(k.MqlRuntime, tlsRouteResourceKinds, "k8s.tlsroute")
}

func (k *mqlK8s) tcpRoutes() ([]any, error) {
	return gatewayRouteResources(k.MqlRuntime, tcpRouteResourceKinds, "k8s.tcproute")
}

func (k *mqlK8s) udpRoutes() ([]any, error) {
	return gatewayRouteResources(k.MqlRuntime, udpRouteResourceKinds, "k8s.udproute")
}

func gatewayRouteResources(rt *plugin.Runtime, kinds []string, resourceName string) ([]any, error) {
	objects, err := optionalK8sResources(rt, kinds...)
	if err != nil {
		return nil, err
	}

	resp := make([]any, 0, len(objects))
	for _, resource := range objects {
		obj, err := meta.Accessor(resource)
		if err != nil {
			return nil, err
		}
		objT, err := meta.TypeAccessor(resource)
		if err != nil {
			return nil, err
		}
		u := asUnstructured(resource)
		if u == nil {
			return nil, errors.New("not a Gateway API route")
		}

		spec := nestedMap(u.Object, "spec")
		status := nestedMap(u.Object, "status")
		parentRefs, err := convert.JsonToDictSlice(nestedSlice(spec, "parentRefs"))
		if err != nil {
			return nil, err
		}
		rules, err := convert.JsonToDictSlice(nestedSlice(spec, "rules"))
		if err != nil {
			return nil, err
		}
		parentStatus, err := convert.JsonToDictSlice(nestedSlice(status, "parents"))
		if err != nil {
			return nil, err
		}

		// spec.hostnames must mirror the manifest: stringSlice() sorts and
		// dedups (it is built for exposure classification), which silently
		// rewrites the user's list and breaks hostnames[0].
		hostnames := stringsToAny(orderedStringSlice(spec["hostnames"]))
		ts := obj.GetCreationTimestamp()
		r, err := CreateResource(rt, resourceName, map[string]*llx.RawData{
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

		switch v := r.(type) {
		case *mqlK8sTlsroute:
			v.obj = u
		case *mqlK8sTcproute:
			v.obj = u
		case *mqlK8sUdproute:
			v.obj = u
		}
		resp = append(resp, r)
	}
	return resp, nil
}

func (k *mqlK8sTlsroute) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sTlsroute) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sTlsroute) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sTlsroute) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sTlsroute(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sTlsroute](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetTlsRoutes() })
}

func (k *mqlK8sTlsroute) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sTlsroute) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func (k *mqlK8sTcproute) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sTcproute) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sTcproute) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sTcproute) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sTcproute(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sTcproute](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetTcpRoutes() })
}

func (k *mqlK8sTcproute) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sTcproute) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

func (k *mqlK8sUdproute) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sUdproute) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sUdproute) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sUdproute) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sUdproute(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sUdproute](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetUdpRoutes() })
}

func (k *mqlK8sUdproute) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sUdproute) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// orderedStringSlice reads a string list from an unstructured field, preserving
// the order and any duplicates the manifest declared.
//
// The sibling stringSlice() helper funnels every branch through
// sortedUniqueStrings(), which is correct for exposure classification (where a
// set of addresses is compared) but wrong for a schema field that has to mirror
// the object: sorting rewrites hostnames[0] and deduping loses an entry.
//
// Elements still go through stringValue(), so a value is nil-safe and gets
// TrimSpace'd. That is deliberate: the API server validates a route hostname as
// a DNS name, so it cannot carry surrounding whitespace, and reusing the helper
// keeps the *string and non-string cases handled in one place.
func orderedStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, stringValue(item))
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

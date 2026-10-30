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
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

type mqlK8sReferencegrantInternal struct {
	lock sync.Mutex
	obj  *gatewayv1.ReferenceGrant
}

func (k *mqlK8s) referenceGrants() ([]any, error) {
	// ReferenceGrant is served as v1beta1 on older clusters and v1 on newer ones.
	// Pass the unqualified plural so the server-preferred version is selected.
	// Gateway API ships as CRDs, so a cluster that never installed them has no
	// such kind. That is a cluster with no Gateways, not a failed scan, so the
	// list degrades to empty rather than erroring.
	return k8sOptionalResourceToMql(k.MqlRuntime, "referencegrants", func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		var rg *gatewayv1.ReferenceGrant
		switch v := resource.(type) {
		case *gatewayv1.ReferenceGrant:
			rg = v
		case *gatewayv1beta1.ReferenceGrant:
			conv := gatewayv1.ReferenceGrant(*v)
			rg = &conv
		default:
			return nil, errors.New("not a k8s referencegrant")
		}

		from, err := convert.JsonToDictSlice(rg.Spec.From)
		if err != nil {
			return nil, err
		}

		to, err := convert.JsonToDictSlice(rg.Spec.To)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.referencegrant", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"from":            llx.ArrayData(from, types.Dict),
			"to":              llx.ArrayData(to, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sReferencegrant).obj = rg
		return r, nil
	})
}

func (k *mqlK8sReferencegrant) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sReferencegrant) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sReferencegrant) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sReferencegrant) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func initK8sReferencegrant(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sReferencegrant](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetReferenceGrants() })
}

func (k *mqlK8sReferencegrant) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sReferencegrant) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sRbacClusterroleInternal struct {
	lock sync.Mutex
	obj  *rbacv1.ClusterRole
}

func (k *mqlK8s) clusterroles() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(rbacv1.SchemeGroupVersion.WithKind("clusterroles")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()
		clusterRole, ok := resource.(*rbacv1.ClusterRole)
		if !ok {
			return nil, errors.New("not a k8s clusterrole")
		}

		rules, err := convert.JsonToDictSlice(clusterRole.Rules)
		if err != nil {
			return nil, err
		}

		// A ClusterRole that does not aggregate has no aggregationRule at all.
		// Report that as null, not as an empty selector set, so "this role must
		// not aggregate" is expressible.
		aggregationRuleData := llx.NilData
		if clusterRole.AggregationRule != nil {
			aggregationRule, err := convert.JsonToDict(clusterRole.AggregationRule)
			if err != nil {
				return nil, err
			}
			aggregationRuleData = llx.DictData(aggregationRule)
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.rbac.clusterrole", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"rules":           llx.ArrayData(rules, types.Dict),
			"aggregationRule": aggregationRuleData,
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sRbacClusterrole).obj = clusterRole
		return r, nil
	})
}

func (k *mqlK8sRbacClusterrole) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sRbacClusterrole) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sRbacClusterrole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sRbacClusterrole](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetClusterroles() })
}

func (k *mqlK8sRbacClusterrole) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sRbacClusterrole) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sRbacClusterrole) policyRules() ([]any, error) {
	return rbacPolicyRules(k.MqlRuntime, k.Id.Data, k.obj.Rules)
}

func (k *mqlK8sRbacClusterrole) hasWildcardRule() (bool, error) {
	return rbacHasWildcardRule(k.obj.Rules), nil
}

func (k *mqlK8sRbacClusterrole) allowsPrivilegeEscalation() (bool, error) {
	return rbacAllowsPrivilegeEscalation(k.obj.Rules), nil
}

func (k *mqlK8sRbacClusterrole) canReadSecrets() (bool, error) {
	return rbacCanReadSecrets(k.obj.Rules), nil
}

func (k *mqlK8sRbacClusterrole) grantsClusterAdmin() (bool, error) {
	return rbacGrantsClusterAdmin(k.obj.Rules), nil
}

func (k *mqlK8sRbacClusterrole) boundBy() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	crbs := o.(*mqlK8s).GetClusterrolebindings()
	if crbs.Error != nil {
		return nil, crbs.Error
	}

	roleName := k.Name.Data
	out := []any{}
	for i := range crbs.Data {
		crb, ok := crbs.Data[i].(*mqlK8sRbacClusterrolebinding)
		if !ok {
			continue
		}
		if crb.obj.RoleRef.Name == roleName {
			out = append(out, crb)
		}
	}
	return out, nil
}

func (k *mqlK8sRbacClusterrole) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sRbacClusterrole) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

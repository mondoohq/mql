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

type mqlK8sRbacRoleInternal struct {
	lock sync.Mutex
	obj  *rbacv1.Role
}

func (k *mqlK8s) roles() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(rbacv1.SchemeGroupVersion.WithKind("roles")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		role, ok := resource.(*rbacv1.Role)
		if !ok {
			return nil, errors.New("not a k8s role")
		}

		rules, err := convert.JsonToDictSlice(role.Rules)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.rbac.role", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"rules":           llx.ArrayData(rules, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sRbacRole).obj = role
		return r, nil
	})
}

func (k *mqlK8sRbacRole) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sRbacRole) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sRbacRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sRbacRole](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetRoles() })
}

func (k *mqlK8sRbacRole) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sRbacRole) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sRbacRole) policyRules() ([]any, error) {
	return rbacPolicyRules(k.MqlRuntime, k.Id.Data, k.obj.Rules)
}

func (k *mqlK8sRbacRole) hasWildcardRule() (bool, error) {
	return rbacHasWildcardRule(k.obj.Rules), nil
}

func (k *mqlK8sRbacRole) allowsPrivilegeEscalation() (bool, error) {
	return rbacAllowsPrivilegeEscalation(k.obj.Rules), nil
}

func (k *mqlK8sRbacRole) canReadSecrets() (bool, error) {
	return rbacCanReadSecrets(k.obj.Rules), nil
}

func (k *mqlK8sRbacRole) grantsClusterAdmin() (bool, error) {
	return rbacGrantsClusterAdmin(k.obj.Rules), nil
}

func (k *mqlK8sRbacRole) boundBy() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	rbs := o.(*mqlK8s).GetRolebindings()
	if rbs.Error != nil {
		return nil, rbs.Error
	}

	roleName := k.Name.Data
	namespace := k.Namespace.Data
	out := []any{}
	for i := range rbs.Data {
		rb, ok := rbs.Data[i].(*mqlK8sRbacRolebinding)
		if !ok {
			continue
		}
		if rb.Namespace.Data != namespace {
			continue
		}
		if rb.obj.RoleRef.Kind == "Role" && rb.obj.RoleRef.Name == roleName {
			out = append(out, rb)
		}
	}
	return out, nil
}

func (k *mqlK8sRbacRole) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sRbacRole) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

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

type mqlK8sRbacRolebindingInternal struct {
	lock sync.Mutex
	obj  *rbacv1.RoleBinding
}

func (k *mqlK8s) rolebindings() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(rbacv1.SchemeGroupVersion.WithKind("rolebindings")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		roleBinding, ok := resource.(*rbacv1.RoleBinding)
		if !ok {
			return nil, errors.New("not a k8s rolebinding")
		}

		subjects, err := convert.JsonToDictSlice(roleBinding.Subjects)
		if err != nil {
			return nil, err
		}

		roleRef, err := convert.JsonToDict(roleBinding.RoleRef)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.rbac.rolebinding", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"subjects":        llx.ArrayData(subjects, types.Dict),
			"roleRef":         llx.DictData(roleRef),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sRbacRolebinding).obj = roleBinding
		return r, nil
	})
}

func (k *mqlK8sRbacRolebinding) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sRbacRolebinding) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sRbacRolebinding(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sRbacRolebinding](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetRolebindings() })
}

func (k *mqlK8sRbacRolebinding) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sRbacRolebinding) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sRbacRolebinding) serviceAccounts() ([]any, error) {
	return resolveServiceAccountSubjects(k.MqlRuntime, k.obj.Subjects, k.obj.Namespace)
}

func (k *mqlK8sRbacRolebinding) role() (*mqlK8sRbacRole, error) {
	if k.obj.RoleRef.Kind != "Role" || k.obj.RoleRef.Name == "" {
		k.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.rbac.role", map[string]*llx.RawData{
		"name":      llx.StringData(k.obj.RoleRef.Name),
		"namespace": llx.StringData(k.obj.Namespace),
	})
	if err != nil {
		// A referenced Role can be deleted while the RoleBinding remains.
		// Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Role.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sRbacRole), nil
}

func (k *mqlK8sRbacRolebinding) clusterRole() (*mqlK8sRbacClusterrole, error) {
	if k.obj.RoleRef.Kind != "ClusterRole" || k.obj.RoleRef.Name == "" {
		k.ClusterRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.rbac.clusterrole", map[string]*llx.RawData{
		"name": llx.StringData(k.obj.RoleRef.Name),
	})
	if err != nil {
		// ClusterRole is cluster-scoped, so it isn't loaded when queried
		// from a namespace-scoped asset, and a referenced ClusterRole can
		// have been deleted. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.ClusterRole.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sRbacClusterrole), nil
}

// resolveServiceAccountSubjects resolves the ServiceAccount entries in an RBAC
// subjects list to typed k8s.serviceaccount resources. Subjects with kinds
// other than "ServiceAccount" are skipped. A subject's namespace falls back to
// the binding's namespace when omitted (matches kube-apiserver behavior for
// RoleBindings).
func resolveServiceAccountSubjects(runtime *plugin.Runtime, subjects []rbacv1.Subject, fallbackNamespace string) ([]any, error) {
	out := []any{}
	for _, s := range subjects {
		if s.Kind != "ServiceAccount" {
			continue
		}
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNamespace
		}
		if ns == "" || s.Name == "" {
			continue
		}
		r, err := NewResource(runtime, "k8s.serviceaccount", map[string]*llx.RawData{
			"name":      llx.StringData(s.Name),
			"namespace": llx.StringData(ns),
		})
		if err != nil {
			// Subject points at a SA that doesn't exist (e.g., deleted) — skip.
			// Anything else (transient API error, etc.) must surface; otherwise
			// a connectivity blip silently empties the subject list.
			if errors.Is(err, ErrResourceNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// referencedRules returns the policy rules this binding grants, resolving the
// roleRef to either a namespaced Role or a ClusterRole. It resolves to nil (no
// rules) when the reference is missing or cannot be found (including a
// ClusterRole that isn't loaded for a namespace-scoped asset), so the rollups
// report false rather than erroring on an unresolvable reference.
func (k *mqlK8sRbacRolebinding) referencedRules() ([]rbacv1.PolicyRule, error) {
	role := k.GetRole()
	if role.Error != nil {
		return nil, role.Error
	}
	if role.Data != nil {
		return role.Data.obj.Rules, nil
	}
	cr := k.GetClusterRole()
	if cr.Error != nil {
		return nil, cr.Error
	}
	if cr.Data == nil {
		return nil, nil
	}
	return cr.Data.obj.Rules, nil
}

func (k *mqlK8sRbacRolebinding) grantsClusterAdmin() (bool, error) {
	// A RoleBinding grants inside its own namespace, whatever the referenced
	// role allows, so it can never confer cluster-admin. Binding a wildcard
	// ClusterRole through a RoleBinding is namespace admin — read
	// hasWildcardRule() for that. Reporting true here fired the cluster-admin
	// alarm on every namespace admin in the cluster.
	return false, nil
}

func (k *mqlK8sRbacRolebinding) hasWildcardRule() (bool, error) {
	rules, err := k.referencedRules()
	if err != nil {
		return false, err
	}
	return rbacHasWildcardRule(rules), nil
}

func (k *mqlK8sRbacRolebinding) allowsPrivilegeEscalation() (bool, error) {
	rules, err := k.referencedRules()
	if err != nil {
		return false, err
	}
	return rbacAllowsPrivilegeEscalation(rules), nil
}

func (k *mqlK8sRbacRolebinding) canReadSecrets() (bool, error) {
	rules, err := k.referencedRules()
	if err != nil {
		return false, err
	}
	return rbacCanReadSecrets(rules), nil
}

func (k *mqlK8sRbacRolebinding) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sRbacRolebinding) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

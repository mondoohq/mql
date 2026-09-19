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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sServiceaccountInternal struct {
	lock sync.Mutex
	obj  *corev1.ServiceAccount

	// effectiveRules is aggregated once and shared by the access rollups
	// (isClusterAdmin, canEscalatePrivileges, canReadSecrets,
	// hasWildcardPermissions) so they make a single pass over the bindings.
	effectiveRulesOnce sync.Once
	effectiveRulesData []rbacv1.PolicyRule
	effectiveRulesErr  error
}

func (k *mqlK8s) serviceaccounts() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("serviceaccounts")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		serviceAccount, ok := resource.(*corev1.ServiceAccount)
		if !ok {
			return nil, errors.New("not a k8s serviceaccount")
		}

		secrets, err := convert.JsonToDictSlice(serviceAccount.Secrets)
		if err != nil {
			return nil, err
		}

		imagePullSecrets, err := convert.JsonToDictSlice(serviceAccount.ImagePullSecrets)
		if err != nil {
			return nil, err
		}

		// Implement k8s default of auto-mounting:
		// https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server
		// As discussed here, this behavior will not change for core/v1:
		// https://github.com/kubernetes/kubernetes/issues/57601
		// ServiceAccount only exists in core/v1, so an unset field always
		// defaults to true. Compute the value with a nil-safe local rather than
		// dereferencing the pointer (which is nil whenever TypeMeta isn't
		// populated, e.g. on the manifest path).
		automountServiceAccountToken := true
		if serviceAccount.AutomountServiceAccountToken != nil {
			automountServiceAccountToken = *serviceAccount.AutomountServiceAccountToken
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.serviceaccount", map[string]*llx.RawData{
			"id":                           llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                          llx.StringData(string(obj.GetUID())),
			"resourceVersion":              llx.StringData(obj.GetResourceVersion()),
			"name":                         llx.StringData(obj.GetName()),
			"namespace":                    llx.StringData(obj.GetNamespace()),
			"kind":                         llx.StringData(objT.GetKind()),
			"created":                      llx.TimeData(ts.Time),
			"secrets":                      llx.ArrayData(secrets, types.Dict),
			"imagePullSecrets":             llx.ArrayData(imagePullSecrets, types.Dict),
			"automountServiceAccountToken": llx.BoolData(automountServiceAccountToken),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sServiceaccount).obj = serviceAccount
		return r, nil
	})
}

func (k *mqlK8sServiceaccount) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sServiceaccount) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sServiceaccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sServiceaccount](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetServiceaccounts() })
}

func (k *mqlK8sServiceaccount) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sServiceaccount) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

// subjectsIncludeServiceAccount reports whether subjects lists the given
// ServiceAccount. A subject's namespace falls back to fallbackNamespace when
// omitted (kube-apiserver behavior for RoleBindings; pass "" for the
// cluster-scoped ClusterRoleBinding, which requires an explicit namespace).
func subjectsIncludeServiceAccount(subjects []rbacv1.Subject, saName, saNamespace, fallbackNamespace string) bool {
	for _, s := range subjects {
		if s.Kind != "ServiceAccount" || s.Name != saName {
			continue
		}
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNamespace
		}
		if ns == saNamespace {
			return true
		}
	}
	return false
}

func (k *mqlK8sServiceaccount) k8sResource() (*mqlK8s, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return o.(*mqlK8s), nil
}

// roleBindings returns the RoleBindings (in this ServiceAccount's namespace)
// that list it as a subject.
func (k *mqlK8sServiceaccount) roleBindings() ([]any, error) {
	o, err := k.k8sResource()
	if err != nil {
		return nil, err
	}
	rbs := o.GetRolebindings()
	if rbs.Error != nil {
		return nil, rbs.Error
	}
	out := []any{}
	for i := range rbs.Data {
		rb, ok := rbs.Data[i].(*mqlK8sRbacRolebinding)
		if !ok {
			continue
		}
		if subjectsIncludeServiceAccount(rb.obj.Subjects, k.Name.Data, k.Namespace.Data, rb.obj.Namespace) {
			out = append(out, rb)
		}
	}
	return out, nil
}

// clusterRoleBindings returns the ClusterRoleBindings that list this
// ServiceAccount as a subject.
func (k *mqlK8sServiceaccount) clusterRoleBindings() ([]any, error) {
	o, err := k.k8sResource()
	if err != nil {
		return nil, err
	}
	crbs := o.GetClusterrolebindings()
	if crbs.Error != nil {
		return nil, crbs.Error
	}
	out := []any{}
	for i := range crbs.Data {
		crb, ok := crbs.Data[i].(*mqlK8sRbacClusterrolebinding)
		if !ok {
			continue
		}
		if subjectsIncludeServiceAccount(crb.obj.Subjects, k.Name.Data, k.Namespace.Data, "") {
			out = append(out, crb)
		}
	}
	return out, nil
}

// effectiveRules aggregates the policy rules of every Role and ClusterRole bound
// to this ServiceAccount, the union of what the account is permitted to do. The
// result is computed once and reused by the four access rollups.
func (k *mqlK8sServiceaccount) effectiveRules() ([]rbacv1.PolicyRule, error) {
	k.effectiveRulesOnce.Do(func() {
		k.effectiveRulesData, k.effectiveRulesErr = k.computeEffectiveRules()
	})
	return k.effectiveRulesData, k.effectiveRulesErr
}

func (k *mqlK8sServiceaccount) computeEffectiveRules() ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule

	rbs := k.GetRoleBindings()
	if rbs.Error != nil {
		return nil, rbs.Error
	}
	for i := range rbs.Data {
		rr, err := rbs.Data[i].(*mqlK8sRbacRolebinding).referencedRules()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rr...)
	}

	crbs := k.GetClusterRoleBindings()
	if crbs.Error != nil {
		return nil, crbs.Error
	}
	for i := range crbs.Data {
		rr, err := crbs.Data[i].(*mqlK8sRbacClusterrolebinding).referencedRules()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rr...)
	}

	return rules, nil
}

func (k *mqlK8sServiceaccount) isClusterAdmin() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacGrantsClusterAdmin(rules), nil
}

func (k *mqlK8sServiceaccount) canEscalatePrivileges() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacAllowsPrivilegeEscalation(rules), nil
}

func (k *mqlK8sServiceaccount) canReadSecrets() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacCanReadSecrets(rules), nil
}

func (k *mqlK8sServiceaccount) hasWildcardPermissions() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacHasWildcardRule(rules), nil
}

func (k *mqlK8sServiceaccount) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sServiceaccount) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}

// secretRefs resolves the ObjectReferences in the account's secrets list to
// the Secret objects themselves. This is the join a "no static ServiceAccount
// tokens" audit needs: a service account that still lists a Secret here holds
// a long-lived token that nothing rotates.
func (k *mqlK8sServiceaccount) secretRefs() ([]any, error) {
	names := make([]string, 0, len(k.obj.Secrets))
	for _, ref := range k.obj.Secrets {
		names = append(names, ref.Name)
	}
	return resolveNamespaced[*mqlK8sSecret](
		k.MqlRuntime, k.obj.GetNamespace(), names,
		func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetSecrets() })
}

// imagePullSecretRefs resolves the LocalObjectReferences in the account's
// imagePullSecrets list to the Secret objects themselves.
func (k *mqlK8sServiceaccount) imagePullSecretRefs() ([]any, error) {
	names := make([]string, 0, len(k.obj.ImagePullSecrets))
	for _, ref := range k.obj.ImagePullSecrets {
		names = append(names, ref.Name)
	}
	return resolveNamespaced[*mqlK8sSecret](
		k.MqlRuntime, k.obj.GetNamespace(), names,
		func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetSecrets() })
}

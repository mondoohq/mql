// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	rbacv1 "k8s.io/api/rbac/v1"
)

type mqlK8sRbacSubjectInternal struct {
	effectiveRulesOnce sync.Once
	effectiveRulesData []rbacv1.PolicyRule
	// clusterRulesData holds only the rules reached through ClusterRoleBindings;
	// a RoleBinding's grants stop at its namespace.
	clusterRulesData  []rbacv1.PolicyRule
	effectiveRulesErr error
}

// subjectID builds the stable, unique cache key for an RBAC subject. The fields
// are NUL-joined because a NUL byte cannot appear in a Kubernetes identifier, so
// names containing other separators can never collide.
func subjectID(kind, namespace, name string) string {
	return fmt.Sprintf("k8s.rbac.subject\x00%s\x00%s\x00%s", kind, namespace, name)
}

// subjectNamespace resolves the effective namespace of a binding subject. For a
// ServiceAccount it applies the binding's namespace as a fallback and reports
// false when neither is set (an invalid subject to skip). Users and groups are
// cluster-scoped and carry no namespace.
func subjectNamespace(s rbacv1.Subject, fallbackNamespace string) (string, bool) {
	if s.Kind == "ServiceAccount" {
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNamespace
		}
		if ns == "" {
			return "", false
		}
		return ns, true
	}
	return "", true
}

func newK8sRbacSubject(runtime *plugin.Runtime, kind, namespace, name string) (plugin.Resource, error) {
	return CreateResource(runtime, "k8s.rbac.subject", map[string]*llx.RawData{
		"__id":      llx.StringData(subjectID(kind, namespace, name)),
		"kind":      llx.StringData(kind),
		"namespace": llx.StringData(namespace),
		"name":      llx.StringData(name),
	})
}

// appendSubject adds a distinct subject resource to out, deduplicating by cache
// key. Empty kind or name entries are ignored.
func appendSubject(runtime *plugin.Runtime, out []any, seen map[string]struct{}, kind, namespace, name string) ([]any, error) {
	if kind == "" || name == "" {
		return out, nil
	}
	id := subjectID(kind, namespace, name)
	if _, ok := seen[id]; ok {
		return out, nil
	}
	seen[id] = struct{}{}
	r, err := newK8sRbacSubject(runtime, kind, namespace, name)
	if err != nil {
		return out, err
	}
	return append(out, r), nil
}

func subjectMatches(s rbacv1.Subject, kind, namespace, name, fallbackNamespace string) bool {
	if s.Kind != kind || s.Name != name {
		return false
	}
	if kind == "ServiceAccount" {
		ns := s.Namespace
		if ns == "" {
			ns = fallbackNamespace
		}
		return ns == namespace
	}
	return true
}

func anySubjectMatches(subjects []rbacv1.Subject, kind, namespace, name, fallbackNamespace string) bool {
	for i := range subjects {
		if subjectMatches(subjects[i], kind, namespace, name, fallbackNamespace) {
			return true
		}
	}
	return false
}

// rbacSubjects enumerates every distinct subject (user, group, or service
// account) named in any RoleBinding or ClusterRoleBinding, deduplicated across
// all bindings.
func (k *mqlK8s) rbacSubjects() ([]any, error) {
	rbs := k.GetRolebindings()
	if rbs.Error != nil {
		return nil, rbs.Error
	}
	crbs := k.GetClusterrolebindings()
	if crbs.Error != nil {
		return nil, crbs.Error
	}

	seen := map[string]struct{}{}
	out := []any{}
	var err error

	for i := range rbs.Data {
		rb, ok := rbs.Data[i].(*mqlK8sRbacRolebinding)
		if !ok {
			continue
		}
		for _, s := range rb.obj.Subjects {
			ns, valid := subjectNamespace(s, rb.obj.Namespace)
			if !valid {
				continue
			}
			if out, err = appendSubject(k.MqlRuntime, out, seen, s.Kind, ns, s.Name); err != nil {
				return nil, err
			}
		}
	}

	for i := range crbs.Data {
		crb, ok := crbs.Data[i].(*mqlK8sRbacClusterrolebinding)
		if !ok {
			continue
		}
		for _, s := range crb.obj.Subjects {
			ns, valid := subjectNamespace(s, "")
			if !valid {
				continue
			}
			if out, err = appendSubject(k.MqlRuntime, out, seen, s.Kind, ns, s.Name); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

func (k *mqlK8sRbacSubject) k8sParent() (*mqlK8s, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return o.(*mqlK8s), nil
}

func (k *mqlK8sRbacSubject) serviceAccount() (*mqlK8sServiceaccount, error) {
	if k.Kind.Data != "ServiceAccount" || k.Namespace.Data == "" || k.Name.Data == "" {
		k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.serviceaccount", map[string]*llx.RawData{
		"name":      llx.StringData(k.Name.Data),
		"namespace": llx.StringData(k.Namespace.Data),
	})
	if err != nil {
		// The subject can outlive the ServiceAccount it names; resolve a missing
		// account to null and surface any other error.
		if errors.Is(err, ErrResourceNotFound) {
			k.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sServiceaccount), nil
}

// roleBindings returns the RoleBindings that name this subject.
func (k *mqlK8sRbacSubject) roleBindings() ([]any, error) {
	o, err := k.k8sParent()
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
		if anySubjectMatches(rb.obj.Subjects, k.Kind.Data, k.Namespace.Data, k.Name.Data, rb.obj.Namespace) {
			out = append(out, rb)
		}
	}
	return out, nil
}

// clusterRoleBindings returns the ClusterRoleBindings that name this subject.
func (k *mqlK8sRbacSubject) clusterRoleBindings() ([]any, error) {
	o, err := k.k8sParent()
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
		if anySubjectMatches(crb.obj.Subjects, k.Kind.Data, k.Namespace.Data, k.Name.Data, "") {
			out = append(out, crb)
		}
	}
	return out, nil
}

// effectiveRules aggregates the policy rules of every Role and ClusterRole bound
// to this subject, the union of what the subject is permitted to do. The result
// is computed once and reused by the four access rollups.
func (k *mqlK8sRbacSubject) effectiveRules() ([]rbacv1.PolicyRule, error) {
	all, _, err := k.scopedRules()
	return all, err
}

// scopedRules returns every rule bound to this subject, and separately the
// subset reached through ClusterRoleBindings.
func (k *mqlK8sRbacSubject) scopedRules() ([]rbacv1.PolicyRule, []rbacv1.PolicyRule, error) {
	k.effectiveRulesOnce.Do(func() {
		k.effectiveRulesData, k.clusterRulesData, k.effectiveRulesErr = k.computeEffectiveRules()
	})
	return k.effectiveRulesData, k.clusterRulesData, k.effectiveRulesErr
}

func (k *mqlK8sRbacSubject) computeEffectiveRules() ([]rbacv1.PolicyRule, []rbacv1.PolicyRule, error) {
	var rules, clusterRules []rbacv1.PolicyRule

	rbs := k.GetRoleBindings()
	if rbs.Error != nil {
		return nil, nil, rbs.Error
	}
	for i := range rbs.Data {
		rr, err := rbs.Data[i].(*mqlK8sRbacRolebinding).referencedRules()
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rr...)
	}

	crbs := k.GetClusterRoleBindings()
	if crbs.Error != nil {
		return nil, nil, crbs.Error
	}
	for i := range crbs.Data {
		rr, err := crbs.Data[i].(*mqlK8sRbacClusterrolebinding).referencedRules()
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rr...)
		clusterRules = append(clusterRules, rr...)
	}

	return rules, clusterRules, nil
}

func (k *mqlK8sRbacSubject) isClusterAdmin() (bool, error) {
	_, clusterRules, err := k.scopedRules()
	if err != nil {
		return false, err
	}
	// Only a ClusterRoleBinding confers cluster-wide power; a RoleBinding to
	// the same wildcard ClusterRole is namespace admin.
	return rbacGrantsClusterAdmin(clusterRules), nil
}

func (k *mqlK8sRbacSubject) canEscalatePrivileges() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacAllowsPrivilegeEscalation(rules), nil
}

func (k *mqlK8sRbacSubject) canReadSecrets() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacCanReadSecrets(rules), nil
}

func (k *mqlK8sRbacSubject) hasWildcardPermissions() (bool, error) {
	rules, err := k.effectiveRules()
	if err != nil {
		return false, err
	}
	return rbacHasWildcardRule(rules), nil
}

// initK8sRbacWhoCan defaults the optional selectors to the empty string and
// derives a stable cache key from the action under test.
func initK8sRbacWhoCan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	for _, f := range []string{"verb", "resource", "group", "namespace", "name"} {
		if _, ok := args[f]; !ok {
			args[f] = llx.StringData("")
		}
	}
	str := func(k string) string {
		if v, ok := args[k]; ok && v.Value != nil {
			if s, ok := v.Value.(string); ok {
				return s
			}
		}
		return ""
	}
	args["__id"] = llx.StringData(fmt.Sprintf("k8s.rbac.whoCan\x00verb=%s\x00grp=%s\x00res=%s\x00ns=%s\x00name=%s",
		str("verb"), str("group"), str("resource"), str("namespace"), str("name")))
	return args, nil, nil
}

// subjects resolves the users, groups, and service accounts whose bound roles
// grant the queried action. ClusterRoleBindings apply cluster-wide; RoleBindings
// apply only within their own namespace, so a namespace selector narrows the
// RoleBinding set while an empty selector considers every namespace.
func (k *mqlK8sRbacWhoCan) subjects() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	parent := o.(*mqlK8s)

	verb := k.Verb.Data
	resource := k.Resource.Data
	group := k.Group.Data
	resourceName := k.Name.Data
	queryNamespace := k.Namespace.Data

	grants := func(rules []rbacv1.PolicyRule) bool {
		for i := range rules {
			if rbacRuleGrants(rules[i], group, resource, verb, resourceName) {
				return true
			}
		}
		return false
	}

	seen := map[string]struct{}{}
	out := []any{}

	crbs := parent.GetClusterrolebindings()
	if crbs.Error != nil {
		return nil, crbs.Error
	}
	for i := range crbs.Data {
		crb, ok := crbs.Data[i].(*mqlK8sRbacClusterrolebinding)
		if !ok {
			continue
		}
		rules, err := crb.referencedRules()
		if err != nil {
			return nil, err
		}
		if !grants(rules) {
			continue
		}
		for _, s := range crb.obj.Subjects {
			ns, valid := subjectNamespace(s, "")
			if !valid {
				continue
			}
			if out, err = appendSubject(k.MqlRuntime, out, seen, s.Kind, ns, s.Name); err != nil {
				return nil, err
			}
		}
	}

	rbs := parent.GetRolebindings()
	if rbs.Error != nil {
		return nil, rbs.Error
	}
	for i := range rbs.Data {
		rb, ok := rbs.Data[i].(*mqlK8sRbacRolebinding)
		if !ok {
			continue
		}
		if queryNamespace != "" && rb.obj.Namespace != queryNamespace {
			continue
		}
		rules, err := rb.referencedRules()
		if err != nil {
			return nil, err
		}
		if !grants(rules) {
			continue
		}
		for _, s := range rb.obj.Subjects {
			ns, valid := subjectNamespace(s, rb.obj.Namespace)
			if !valid {
				continue
			}
			if out, err = appendSubject(k.MqlRuntime, out, seen, s.Kind, ns, s.Name); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

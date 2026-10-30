// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
	rbacv1 "k8s.io/api/rbac/v1"
)

// rbacPolicyRules converts the typed PolicyRule slice of a Role or ClusterRole
// into k8s.rbac.policyRule resources. parentID is the owning role's id and is
// used to build a stable, unique __id per rule.
func rbacPolicyRules(runtime *plugin.Runtime, parentID string, rules []rbacv1.PolicyRule) ([]any, error) {
	out := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]
		r, err := CreateResource(runtime, "k8s.rbac.policyRule", map[string]*llx.RawData{
			"__id":            llx.StringData(fmt.Sprintf("%s/rule/%d", parentID, i)),
			"verbs":           llx.ArrayData(convert.SliceAnyToInterface(rule.Verbs), types.String),
			"apiGroups":       llx.ArrayData(convert.SliceAnyToInterface(rule.APIGroups), types.String),
			"resources":       llx.ArrayData(convert.SliceAnyToInterface(rule.Resources), types.String),
			"resourceNames":   llx.ArrayData(convert.SliceAnyToInterface(rule.ResourceNames), types.String),
			"nonResourceURLs": llx.ArrayData(convert.SliceAnyToInterface(rule.NonResourceURLs), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// rbacListMatches reports whether list contains target or the wildcard "*".
func rbacListMatches(list []string, target string) bool {
	return stringx.Contains(list, "*") || stringx.Contains(list, target)
}

// rbacResourceMatches reports whether a rule's resources cover the requested
// resource, written as "<resource>" or "<resource>/<subresource>". Besides "*"
// and an exact match, a rule resource "*/<subresource>" covers that subresource
// of every resource, as in the API server's RBAC authorizer. There is no
// "<resource>/*" form: it matches only a subresource literally named "*".
func rbacResourceMatches(ruleResources []string, resource string) bool {
	if rbacListMatches(ruleResources, resource) {
		return true
	}
	_, sub, ok := strings.Cut(resource, "/")
	if !ok || sub == "" {
		return false
	}
	return stringx.Contains(ruleResources, "*/"+sub)
}

// rbacRuleGrants reports whether the rule grants the given verb on the given
// (apiGroup, resource, resourceName), honoring wildcards in the group, resource,
// and verb dimensions, including the "*/<subresource>" resource form. A rule
// with a non-empty ResourceNames list grants the action only on those named
// objects; an empty list grants it on every object.
// An empty resourceName means the action is not scoped to a specific object, so
// a name-restricted rule still counts (the subject can act on at least the named
// objects). This matches the API server's RBAC authorizer and keeps whoCan
// consistent with k8s.accessReview.
func rbacRuleGrants(rule rbacv1.PolicyRule, apiGroup, resource, verb, resourceName string) bool {
	return rbacListMatches(rule.APIGroups, apiGroup) &&
		rbacResourceMatches(rule.Resources, resource) &&
		rbacListMatches(rule.Verbs, verb) &&
		rbacRuleMatchesResourceName(rule, resourceName)
}

// rbacRuleMatchesResourceName reports whether a rule covers the named object.
// An empty resourceName (unscoped query) or an empty ResourceNames list (rule
// applies to all objects of the type) matches anything.
func rbacRuleMatchesResourceName(rule rbacv1.PolicyRule, resourceName string) bool {
	if resourceName == "" || len(rule.ResourceNames) == 0 {
		return true
	}
	return stringx.Contains(rule.ResourceNames, resourceName)
}

// rbacHasWildcardRule reports whether any rule uses a wildcard for verbs, API
// groups, or resources.
func rbacHasWildcardRule(rules []rbacv1.PolicyRule) bool {
	for i := range rules {
		rule := rules[i]
		if stringx.Contains(rule.Verbs, "*") ||
			stringx.Contains(rule.APIGroups, "*") ||
			stringx.Contains(rule.Resources, "*") {
			return true
		}
	}
	return false
}

// rbacGrantsClusterAdmin reports whether any rule grants unrestricted access:
// the verb, API group, and resource dimensions all include the wildcard "*".
// This is the rule shape of the built-in cluster-admin ClusterRole and of any
// equivalent custom role.
func rbacGrantsClusterAdmin(rules []rbacv1.PolicyRule) bool {
	for i := range rules {
		rule := rules[i]
		if stringx.Contains(rule.Verbs, "*") &&
			stringx.Contains(rule.APIGroups, "*") &&
			stringx.Contains(rule.Resources, "*") {
			return true
		}
	}
	return false
}

// rbacAllowsPrivilegeEscalation reports whether any rule grants one of the
// canonical RBAC privilege-escalation permissions.
func rbacAllowsPrivilegeEscalation(rules []rbacv1.PolicyRule) bool {
	const rbacGroup = "rbac.authorization.k8s.io"
	for i := range rules {
		rule := rules[i]
		// escalate on roles/clusterroles
		if rbacRuleGrants(rule, rbacGroup, "roles", "escalate", "") ||
			rbacRuleGrants(rule, rbacGroup, "clusterroles", "escalate", "") {
			return true
		}
		// bind on roles/clusterroles
		if rbacRuleGrants(rule, rbacGroup, "roles", "bind", "") ||
			rbacRuleGrants(rule, rbacGroup, "clusterroles", "bind", "") {
			return true
		}
		// impersonate users/groups/serviceaccounts (core group)
		if rbacRuleGrants(rule, "", "users", "impersonate", "") ||
			rbacRuleGrants(rule, "", "groups", "impersonate", "") ||
			rbacRuleGrants(rule, "", "serviceaccounts", "impersonate", "") {
			return true
		}
	}
	return false
}

// rbacCanReadSecrets reports whether any rule grants read access (get, list, or
// watch) to Secrets in the core API group.
func rbacCanReadSecrets(rules []rbacv1.PolicyRule) bool {
	for i := range rules {
		rule := rules[i]
		if rbacRuleGrants(rule, "", "secrets", "get", "") ||
			rbacRuleGrants(rule, "", "secrets", "list", "") ||
			rbacRuleGrants(rule, "", "secrets", "watch", "") {
			return true
		}
	}
	return false
}

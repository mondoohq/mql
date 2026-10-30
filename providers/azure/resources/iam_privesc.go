// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// privilegeEscalatingActions are the control-plane actions that let a principal
// grant itself further access. Holding any of them makes a role's effective
// privilege equal to Owner at the assigned scope, whatever the role is named:
// the holder can write a new role assignment (or author a new role definition,
// then assign it) to obtain any permission it does not already have.
// elevateAccess is the tenant-root escalation a Global Administrator uses to
// gain User Access Administrator over every subscription.
var privilegeEscalatingActions = []string{
	"Microsoft.Authorization/roleAssignments/write",
	"Microsoft.Authorization/roleDefinitions/write",
	"Microsoft.Authorization/elevateAccess/action",
}

// matchesActionPattern reports whether an Azure RBAC action pattern matches a
// concrete action. In a pattern, `*` stands for zero or more characters and is
// not bounded by the `/` separators, so `Microsoft.Authorization/*` matches
// `Microsoft.Authorization/roleAssignments/write`. Comparison is
// case-insensitive, matching how Azure evaluates action names.
func matchesActionPattern(pattern, action string) bool {
	if pattern == "" {
		return false
	}
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)
	if !strings.Contains(pattern, "*") {
		return pattern == action
	}

	// Split on the wildcards: the first segment is anchored to the start of the
	// action, the last to its end, and the segments between must appear in
	// order. Consuming each middle segment at its earliest occurrence is safe
	// here because the segments are literals.
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(action, parts[0]) {
		return false
	}
	rest := action[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := strings.Index(rest, mid)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(mid):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// grantsAction reports whether a role's permission set allows a concrete
// action. Azure treats NotActions as a subtraction from Actions, evaluated
// within a single permission block, so an action is granted when some Actions
// pattern matches it and no NotActions pattern in that same block does.
func grantsAction(permissions []*authorization.Permission, action string) bool {
	for _, p := range permissions {
		if p == nil {
			continue
		}
		allowed := false
		for _, a := range p.Actions {
			if a != nil && matchesActionPattern(*a, action) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		denied := false
		for _, na := range p.NotActions {
			if na != nil && matchesActionPattern(*na, action) {
				denied = true
				break
			}
		}
		if !denied {
			return true
		}
	}
	return false
}

// roleIsPrivilegeEscalating reports whether any of the role-granting actions
// survives the role's NotActions.
func roleIsPrivilegeEscalating(permissions []*authorization.Permission) bool {
	for _, action := range privilegeEscalatingActions {
		if grantsAction(permissions, action) {
			return true
		}
	}
	return false
}

// roleHasWildcardActions reports whether any allowed control-plane action
// contains a wildcard. Unlike the checks above this deliberately ignores
// NotActions: the point is that the role's reach is open-ended and grows as
// Azure adds actions to the matched namespace, which a fixed NotActions list
// cannot keep up with.
func roleHasWildcardActions(permissions []*authorization.Permission) bool {
	for _, p := range permissions {
		if p == nil {
			continue
		}
		for _, a := range p.Actions {
			if a != nil && strings.Contains(*a, "*") {
				return true
			}
		}
	}
	return false
}

// roleGrantsDataAccess reports whether the role allows any data-plane action
// that its NotDataActions do not take back. A data action pattern counts as
// negated only when a NotDataActions pattern covers the pattern itself, which
// catches the total-negation case (DataActions `*` alongside NotDataActions
// `*`) without trying to reason about partially overlapping wildcards.
func roleGrantsDataAccess(permissions []*authorization.Permission) bool {
	for _, p := range permissions {
		if p == nil {
			continue
		}
		for _, da := range p.DataActions {
			if da == nil || *da == "" {
				continue
			}
			negated := false
			for _, nda := range p.NotDataActions {
				if nda != nil && matchesActionPattern(*nda, *da) {
					negated = true
					break
				}
			}
			if !negated {
				return true
			}
		}
	}
	return false
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleDefinition) isPrivilegeEscalating() (bool, error) {
	return roleIsPrivilegeEscalating(a.cachePermissions), nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleDefinition) hasWildcardActions() (bool, error) {
	return roleHasWildcardActions(a.cachePermissions), nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleDefinition) grantsDataAccess() (bool, error) {
	return roleGrantsDataAccess(a.cachePermissions), nil
}

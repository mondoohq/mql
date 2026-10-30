// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// oktaCustomRoleTypePrefix is what Okta reports as the type of an assignment
// whose privileges come from a custom role, either on its own or as the prefix
// of a longer name.
const oktaCustomRoleTypePrefix = "CUSTOM"

type mqlOktaRoleInternal struct {
	cacheUserID        string
	cacheGroupID       string
	cacheClientID      string
	cacheCustomRoleID  string
	cacheResourceSetID string
}

type mqlOktaRoleAppTargetInternal struct {
	cacheApplicationID string
}

// oktaAssignedRole is one entry of the user and group role-assignment
// endpoints, flattened onto the shape the role mapper consumes.
//
// Those endpoints answer with a union of a standard admin role and a custom
// role binding. The two members carry the same assignment fields under
// different types, and the custom-role member names its role and resource set
// in dedicated fields rather than only in the HAL links, so those ids are
// carried alongside and used in preference to parsing the links.
type oktaAssignedRole struct {
	role          *okta.Role
	customRoleID  string
	resourceSetID string
	// classified is false when neither union member was set, which happens
	// when the API returns a kind of assignment this code does not yet handle.
	// Callers report those rather than mapping a role with no id.
	classified bool
}

// flattenOktaAssignedRole reduces a role-assignment union entry to a single
// role. A member that is not recognized yields classified false; see
// TestFlattenOktaAssignedRoleCoversUnion, which fails when the SDK grows a
// member this function does not handle.
func flattenOktaAssignedRole(inner *okta.ListGroupAssignedRoles200ResponseInner) oktaAssignedRole {
	switch {
	case inner == nil:
		return oktaAssignedRole{}

	case inner.StandardRole != nil:
		s := inner.StandardRole
		roleType := s.Type
		return oktaAssignedRole{
			role: &okta.Role{
				AssignmentType: s.AssignmentType,
				Created:        s.Created,
				Id:             s.Id,
				Label:          s.Label,
				LastUpdated:    s.LastUpdated,
				Status:         s.Status,
				Type:           &roleType,
			},
			classified: true,
		}

	case inner.CustomRole != nil:
		c := inner.CustomRole
		roleType := c.Type
		return oktaAssignedRole{
			role: &okta.Role{
				AssignmentType: c.AssignmentType,
				Created:        c.Created,
				Id:             c.Id,
				Label:          c.Label,
				LastUpdated:    c.LastUpdated,
				Status:         c.Status,
				Type:           &roleType,
			},
			customRoleID:  oktaStr(c.Role),
			resourceSetID: oktaStr(c.ResourceSet),
			classified:    true,
		}

	default:
		return oktaAssignedRole{}
	}
}

// newMqlOktaAssignedRole maps one entry of a role-assignment collection. It
// differs from newMqlOktaRole in taking the union the assignment endpoints
// return, and in taking the custom-role and resource-set ids from the union
// member instead of from the assignment's HAL links.
func newMqlOktaAssignedRole(runtime *plugin.Runtime, inner *okta.ListGroupAssignedRoles200ResponseInner, principalType, principalID string) (*mqlOktaRole, error) {
	flat := flattenOktaAssignedRole(inner)
	if !flat.classified {
		return nil, nil
	}

	mqlRole, err := newMqlOktaRole(runtime, flat.role, principalType, principalID)
	if err != nil {
		return nil, err
	}
	if flat.customRoleID != "" {
		mqlRole.cacheCustomRoleID = flat.customRoleID
	}
	if flat.resourceSetID != "" {
		mqlRole.cacheResourceSetID = flat.resourceSetID
	}
	return mqlRole, nil
}

// newMqlOktaRole maps an Okta role assignment. principalType is "user",
// "group", or "client" and principalID is the account, group, or OAuth client
// the assignment was read from, which becomes the assignment's principal
// back-reference and the key its scope targets are looked up under.
func newMqlOktaRole(runtime *plugin.Runtime, role *okta.Role, principalType, principalID string) (*mqlOktaRole, error) {
	r, err := CreateResource(runtime, "okta.role", map[string]*llx.RawData{
		"id":             llx.StringData(oktaStr(role.Id)),
		"assignmentType": llx.StringData(oktaStr(role.AssignmentType)),
		"created":        llx.TimeDataPtr(role.Created),
		"lastUpdated":    llx.TimeDataPtr(role.LastUpdated),
		"label":          llx.StringData(oktaStr(role.Label)),
		"status":         llx.StringData(oktaStr(role.Status)),
		"type":           llx.StringData(oktaStr(role.Type)),
	})
	if err != nil {
		return nil, err
	}

	mqlRole := r.(*mqlOktaRole)
	switch principalType {
	case "user":
		mqlRole.cacheUserID = principalID
	case "group":
		mqlRole.cacheGroupID = principalID
	case "client":
		mqlRole.cacheClientID = principalID
	}
	mqlRole.cacheCustomRoleID, mqlRole.cacheResourceSetID = oktaRoleTypedRefs(role)
	return mqlRole, nil
}

// oktaRoleTypedRefs extracts the custom-role and resource-set ids referenced by
// a role assignment from its HAL `_links`. Both are best-effort: standard admin
// roles carry neither, and org-wide custom-role assignments carry no resource
// set. The SDK maps only the `self` link into a typed field, so the other
// links are read from the untyped AdditionalProperties.
func oktaRoleTypedRefs(role *okta.Role) (customRoleID, resourceSetID string) {
	links := role.GetLinks()
	ap := links.AdditionalProperties
	if ap == nil {
		return "", ""
	}

	if h := oktaLinkHref(ap["resource-set"]); h != "" {
		resourceSetID = lastPathSegment(h)
	}

	if strings.HasPrefix(oktaStr(role.Type), oktaCustomRoleTypePrefix) {
		if h := oktaLinkHref(ap["permissions"]); h != "" {
			customRoleID = oktaRoleIdFromPermissionsHref(h)
		}
		if customRoleID == "" {
			if h := oktaLinkHref(ap["role"]); h != "" {
				customRoleID = lastPathSegment(h)
			}
		}
	}
	return customRoleID, resourceSetID
}

func (o *mqlOktaRole) customRole() (*mqlOktaCustomRole, error) {
	return resolveOktaCustomRoleRef(o.MqlRuntime, o.cacheCustomRoleID, &o.CustomRole)
}

func (o *mqlOktaRole) resourceSet() (*mqlOktaResourceSet, error) {
	if o.cacheResourceSetID == "" {
		o.ResourceSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "okta.resourceSet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheResourceSetID),
	})
	if err != nil {
		// A binding can outlive the resource set it scoped.
		if errors.Is(err, errOktaResourceNotFound) {
			o.ResourceSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaResourceSet), nil
}

func (o *mqlOktaRole) user() (*mqlOktaUser, error) {
	return resolveOktaUserRef(o.MqlRuntime, o.cacheUserID, &o.User)
}

func (o *mqlOktaRole) group() (*mqlOktaGroup, error) {
	return resolveOktaGroupRef(o.MqlRuntime, o.cacheGroupID, &o.Group)
}

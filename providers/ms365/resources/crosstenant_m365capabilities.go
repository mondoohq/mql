// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// m365ResourceType* name the resource kinds a cross-tenant capability scope can
// point at.
const (
	m365ResourceTypeUser  = "user"
	m365ResourceTypeGroup = "group"

	// m365ResourceScopeAll is the literal Microsoft Graph reports in resourceId
	// when a scope covers every resource of its type rather than one object.
	m365ResourceScopeAll = "All"
)

// m365ResourceTypeString renders the resource type of a capability scope. An
// absent type reads as an empty string rather than as the Kiota enum's zero
// value, which is "none" and would report a deliberate "no type selected" on a
// scope Microsoft Graph said nothing about.
func m365ResourceTypeString(resourceType *models.M365ResourceType) string {
	if resourceType == nil {
		return ""
	}
	return resourceType.String()
}

// m365Capabilities lists the Microsoft 365 capabilities open to external
// tenants under the default cross-tenant access policy.
//
// m365Capabilities is a navigation property with a request path of its own, so
// the GET on the default policy that populates every other field of this
// resource does not return it. It needs this second request.
func (a *mqlMicrosoftCrossTenantAccessPolicyDefault) m365Capabilities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.
		Policies().
		CrossTenantAccessPolicy().
		DefaultEscaped().
		M365Capabilities().
		Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	if resp == nil {
		return []any{}, nil
	}

	capabilities, err := iterate[models.M365CapabilityBaseable](ctx, resp, graphClient.GetAdapter(), models.CreateM365CapabilityBaseCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, capability := range capabilities {
		if capability == nil {
			continue
		}
		mqlCapability, err := newMqlM365Capability(a.MqlRuntime, a.__id, capability)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCapability)
	}
	return res, nil
}

// newMqlM365Capability maps one cross-tenant Microsoft 365 capability. The
// capability name is the key Microsoft Graph addresses the entry by, so it is
// what makes the cache key stable across scans.
func newMqlM365Capability(runtime *plugin.Runtime, parentID string, capability models.M365CapabilityBaseable) (plugin.Resource, error) {
	name := convert.ToValue(capability.GetName())
	capabilityID := fmt.Sprintf("%s/m365Capabilities/%s", parentID, name)

	inboundAllowed := m365CapabilityInboundAllowed(capability)
	included := []any{}
	excluded := []any{}

	if inbound := capability.GetInboundAccess(); inbound != nil {
		if scopes := inbound.GetResourceScopes(); scopes != nil {
			var err error
			included, err = newMqlM365CapabilityResourceScopes(runtime, capabilityID+"/included", scopes.GetIncluded())
			if err != nil {
				return nil, err
			}
			excluded, err = newMqlM365CapabilityResourceScopes(runtime, capabilityID+"/excluded", scopes.GetExcluded())
			if err != nil {
				return nil, err
			}
		}
	}

	scopeType := types.Resource(ResourceMicrosoftCrossTenantAccessPolicyDefaultM365CapabilityResourceScope)
	return CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultM365Capability,
		map[string]*llx.RawData{
			"__id":                   llx.StringData(capabilityID),
			"name":                   llx.StringData(name),
			"lastModifiedDateTime":   graphTimeData(capability.GetLastModifiedDateTime()),
			"inboundAccessAllowed":   llx.BoolData(inboundAllowed),
			"includedResourceScopes": llx.ArrayData(included, scopeType),
			"excludedResourceScopes": llx.ArrayData(excluded, scopeType),
		})
}

// m365CapabilityInboundAllowed reports whether external tenants may use a
// capability inbound. A capability with no inbound access block, or one whose
// isAllowed Microsoft Graph omitted, reads as not allowed: Microsoft only
// returns a capability that has been configured, so an entry without inbound
// access is nothing to allow rather than something allowed by default.
func m365CapabilityInboundAllowed(capability models.M365CapabilityBaseable) bool {
	inbound := capability.GetInboundAccess()
	if inbound == nil {
		return false
	}
	return convert.ToValue(inbound.GetIsAllowed())
}

// newMqlM365CapabilityResourceScopes maps the users and groups a capability
// applies to. A scope carries no identifier of its own, and Microsoft Graph
// returns an empty object as a placeholder for "nothing excluded", so the cache
// key is the capability plus the position of the entry.
func newMqlM365CapabilityResourceScopes(runtime *plugin.Runtime, prefix string, scopes []models.M365CapabilityResourceScopeable) ([]any, error) {
	res := []any{}
	for i, scope := range scopes {
		if scope == nil {
			continue
		}
		resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyDefaultM365CapabilityResourceScope,
			newM365CapabilityResourceScopeArgs(prefix, i, scope))
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// newM365CapabilityResourceScopeArgs maps one capability resource scope onto
// the arguments of the resource scope resource.
func newM365CapabilityResourceScopeArgs(prefix string, index int, scope models.M365CapabilityResourceScopeable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("%s/%d", prefix, index)),
		"resourceId":   llx.StringDataPtr(scope.GetResourceId()),
		"resourceType": llx.StringData(m365ResourceTypeString(scope.GetResourceType())),
	}
}

// user resolves the user a capability scope names. A scope covering every user
// carries the literal All rather than an object identifier, so it resolves to
// null instead of being looked up.
func (m *mqlMicrosoftCrossTenantAccessPolicyDefaultM365CapabilityResourceScope) user() (*mqlMicrosoftUser, error) {
	id := m.ResourceId.Data
	if m.ResourceType.Data != m365ResourceTypeUser || id == "" || id == m365ResourceScopeAll {
		m.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

// group resolves the group a capability scope names. A scope covering every
// group carries the literal All rather than an object identifier, so it
// resolves to null instead of being looked up.
func (m *mqlMicrosoftCrossTenantAccessPolicyDefaultM365CapabilityResourceScope) group() (*mqlMicrosoftGroup, error) {
	id := m.ResourceId.Data
	if m.ResourceType.Data != m365ResourceTypeGroup || id == "" || id == m365ResourceScopeAll {
		m.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, ResourceMicrosoftGroup, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftGroup), nil
}

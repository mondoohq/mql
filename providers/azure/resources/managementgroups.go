// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// managementGroupsUnavailable reports whether an entities-listing error means
// the credential simply cannot read the management group hierarchy, as opposed
// to something having gone wrong. Only the two authorization outcomes count.
//
// Following pimUnavailable, the status codes are matched individually rather
// than as a 4xx range: a 429 means Microsoft.Management throttled a tenant-wide
// scan and says nothing about access, and reporting an empty hierarchy for it
// would silently drop management groups from the results of a scan that had
// every right to see them.
func managementGroupsUnavailable(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	switch respErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// managementGroupIDPrefix is the ARM path every management group ID starts
// with; it also doubles as the scope prefix used in role and policy
// assignments made at a management group.
const managementGroupIDPrefix = "/providers/Microsoft.Management/managementGroups/"

// isManagementGroupEntity reports whether an entity from the entities listing
// is a management group rather than a subscription. Classifying on the ID
// prefix rather than the Type string keeps this working regardless of the
// casing or exact literal ARM returns for the type.
func isManagementGroupEntity(e *armmanagementgroups.EntityInfo) bool {
	if e == nil || e.ID == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(*e.ID), strings.ToLower(managementGroupIDPrefix))
}

// isSubscriptionEntity reports whether an entity is a subscription. The
// entities listing returns both management groups and the subscriptions that
// hang off them.
func isSubscriptionEntity(e *armmanagementgroups.EntityInfo) bool {
	if e == nil || e.ID == nil {
		return false
	}
	if strings.HasPrefix(strings.ToLower(*e.ID), "/subscriptions/") {
		return true
	}
	return e.Type != nil && strings.Contains(strings.ToLower(*e.Type), "subscription")
}

// entityParentID returns the ARM ID of an entity's parent management group, or
// "" for the tenant root group (which has no parent).
func entityParentID(e *armmanagementgroups.EntityInfo) string {
	if e == nil || e.Properties == nil || e.Properties.Parent == nil {
		return ""
	}
	return convert.ToValue(e.Properties.Parent.ID)
}

// entityParentNameChain returns the management group names from the tenant root
// down to the entity's immediate parent.
func entityParentNameChain(e *armmanagementgroups.EntityInfo) []string {
	if e == nil || e.Properties == nil {
		return nil
	}
	chain := make([]string, 0, len(e.Properties.ParentNameChain))
	for _, n := range e.Properties.ParentNameChain {
		if n != nil {
			chain = append(chain, *n)
		}
	}
	return chain
}

// managementGroupEntities fetches the tenant's management group hierarchy once
// and caches it on the azure singleton. The entities listing returns every
// management group and subscription the credential can see, each carrying its
// parent and its ancestor name chain, so a single paged call is enough to
// answer parentage, children, and subtree counts without further requests.
//
// A credential without Microsoft.Management read access gets an authorization
// failure here. That is reported as an empty hierarchy rather than an error:
// management group access is frequently not granted to a subscription-scoped
// service principal, and every caller of this treats "no hierarchy" as a
// legitimate state. It does not understate anyone's privileges, because the
// role assignments made at a management group still surface through the
// subscription's own assignment listing, which includes inherited grants.
func (a *mqlAzure) managementGroupEntities() ([]*armmanagementgroups.EntityInfo, error) {
	a.mgOnce.Do(func() {
		conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
		if !ok {
			a.mgErr = errors.New("invalid connection provided, it is not an Azure connection")
			return
		}

		client, err := armmanagementgroups.NewEntitiesClient(conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.mgErr = err
			return
		}

		ctx := context.Background()
		pager := client.NewListPager(&armmanagementgroups.EntitiesClientListOptions{})
		entities := []*armmanagementgroups.EntityInfo{}
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				if managementGroupsUnavailable(err) {
					log.Debug().Err(err).Msg("azure> no management group read access, reporting an empty hierarchy")
					a.mgEntities = []*armmanagementgroups.EntityInfo{}
					return
				}
				a.mgErr = err
				return
			}
			entities = append(entities, page.Value...)
		}
		a.mgEntities = entities
	})
	return a.mgEntities, a.mgErr
}

// azureSingleton resolves the provider's top-level azure resource, which owns
// the cached management group hierarchy.
func azureSingleton(runtime *plugin.Runtime) (*mqlAzure, error) {
	r, err := CreateResource(runtime, "azure", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzure), nil
}

func (a *mqlAzure) managementGroups() ([]any, error) {
	entities, err := a.managementGroupEntities()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, e := range entities {
		if !isManagementGroupEntity(e) {
			continue
		}
		mqlGroup, err := newMqlManagementGroup(a.MqlRuntime, e, entities)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

type mqlAzureManagementGroupInternal struct {
	parentID string
}

// newMqlManagementGroup builds a management group resource. The subscription
// membership fields are derived from the full entity list, which the caller
// already holds, so they cost no extra request: subscriptionIds are the
// subscriptions parented directly by this group, and subscriptionCount is every
// subscription anywhere beneath it, found through the ancestor name chains.
//
// Both figures cover only what the credential can read. A partially visible
// hierarchy therefore undercounts rather than overcounts the reach of an
// assignment made at this scope.
func newMqlManagementGroup(runtime *plugin.Runtime, e *armmanagementgroups.EntityInfo, all []*armmanagementgroups.EntityInfo) (*mqlAzureManagementGroup, error) {
	name := convert.ToValue(e.Name)
	id := convert.ToValue(e.ID)

	var displayName, tenantID string
	if e.Properties != nil {
		displayName = convert.ToValue(e.Properties.DisplayName)
		tenantID = convert.ToValue(e.Properties.TenantID)
	}
	parentID := entityParentID(e)

	directSubscriptions := []any{}
	subtreeCount := 0
	for _, other := range all {
		if !isSubscriptionEntity(other) {
			continue
		}
		if strings.EqualFold(entityParentID(other), id) {
			directSubscriptions = append(directSubscriptions, convert.ToValue(other.Name))
			subtreeCount++
			continue
		}
		for _, ancestor := range entityParentNameChain(other) {
			if strings.EqualFold(ancestor, name) {
				subtreeCount++
				break
			}
		}
	}

	r, err := CreateResource(runtime, ResourceAzureManagementGroup,
		map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"id":                llx.StringData(id),
			"name":              llx.StringData(name),
			"displayName":       llx.StringData(displayName),
			"tenantId":          llx.StringData(tenantID),
			"isRoot":            llx.BoolData(parentID == ""),
			"subscriptionIds":   llx.ArrayData(directSubscriptions, types.String),
			"subscriptionCount": llx.IntData(int64(subtreeCount)),
		})
	if err != nil {
		return nil, err
	}
	group := r.(*mqlAzureManagementGroup)
	group.parentID = parentID
	return group, nil
}

func initAzureManagementGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}

	az, err := azureSingleton(runtime)
	if err != nil {
		return nil, nil, err
	}
	entities, err := az.managementGroupEntities()
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entities {
		if !isManagementGroupEntity(e) {
			continue
		}
		if !strings.EqualFold(convert.ToValue(e.Name), name) {
			continue
		}
		group, err := newMqlManagementGroup(runtime, e, entities)
		if err != nil {
			return nil, nil, err
		}
		// Returning the built resource is the only way to carry the parentID
		// cache field onto it; args alone would leave parent() unable to
		// resolve.
		return nil, group, nil
	}
	return nil, nil, errors.New("azure.managementGroup with name " + name + " not found, or not readable by this credential")
}

func (a *mqlAzureManagementGroup) parent() (*mqlAzureManagementGroup, error) {
	if a.parentID == "" {
		// The tenant root group has no parent.
		a.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	az, err := azureSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	entities, err := az.managementGroupEntities()
	if err != nil {
		return nil, err
	}
	for _, e := range entities {
		if isManagementGroupEntity(e) && strings.EqualFold(convert.ToValue(e.ID), a.parentID) {
			return newMqlManagementGroup(a.MqlRuntime, e, entities)
		}
	}
	// The parent exists but sits outside what this credential can read.
	a.Parent.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureManagementGroup) children() ([]any, error) {
	az, err := azureSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	entities, err := az.managementGroupEntities()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, e := range entities {
		if !isManagementGroupEntity(e) {
			continue
		}
		if !strings.EqualFold(entityParentID(e), a.Id.Data) {
			continue
		}
		child, err := newMqlManagementGroup(a.MqlRuntime, e, entities)
		if err != nil {
			return nil, err
		}
		res = append(res, child)
	}
	return res, nil
}

func (a *mqlAzureManagementGroup) roleAssignments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	// The client is constructed with a subscription ID but the scope argument
	// below overrides it, so the listing is genuinely management-group scoped.
	client, err := authorization.NewRoleAssignmentsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	scope := a.Id.Data
	ctx := context.Background()
	filter := "atScope()"
	pager := client.NewListForScopePager(scope, &authorization.RoleAssignmentsClientListForScopeOptions{
		Filter: &filter,
	})

	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ra := range page.Value {
			if ra == nil {
				continue
			}
			// atScope() bounds the listing from below, but not reliably from
			// above: assignments inherited from a parent group can still come
			// back. Keep only the ones whose scope is exactly this group, which
			// is what the field promises.
			if ra.Properties == nil || !strings.EqualFold(convert.ToValue(ra.Properties.Scope), scope) {
				continue
			}
			mqlRoleAssignment, err := newMqlRoleAssignment(a.MqlRuntime, ra)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRoleAssignment)
		}
	}
	return res, nil
}

func (a *mqlAzureManagementGroup) policyAssignments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	// The subscription's policy assignment listing already includes assignments
	// inherited from the management groups above it, so this narrows that cached
	// fetch instead of issuing a management-group query. The consequence, called
	// out on the field, is that a management group the connected subscription
	// does not descend from reports no assignments.
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	policyVal := r.(*mqlAzureSubscription).GetPolicy()
	if policyVal.Error != nil {
		return nil, policyVal.Error
	}
	if policyVal.Data == nil {
		return nil, errors.New("cannot resolve the policy service for the subscription")
	}
	assignments := policyVal.Data.GetAssignments()
	if assignments.Error != nil {
		return nil, assignments.Error
	}

	scope := strings.ToLower(a.Id.Data)
	res := []any{}
	for _, item := range assignments.Data {
		assignment, ok := item.(*mqlAzureSubscriptionPolicyAssignment)
		if !ok {
			continue
		}
		if strings.ToLower(assignment.Scope.Data) == scope {
			res = append(res, assignment)
		}
	}
	return res, nil
}

// managementGroups returns the management group ancestry of the connected
// subscription, nearest parent first and the tenant root group last. These are
// the scopes whose role and policy assignments the subscription inherits.
func (a *mqlAzureSubscription) managementGroups() ([]any, error) {
	az, err := azureSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	entities, err := az.managementGroupEntities()
	if err != nil {
		return nil, err
	}

	// Locate the subscription's own entity to read its ancestor chain, which
	// runs root-first.
	var chain []string
	subID := a.SubscriptionId.Data
	for _, e := range entities {
		if isSubscriptionEntity(e) && strings.EqualFold(convert.ToValue(e.Name), subID) {
			chain = entityParentNameChain(e)
			break
		}
	}

	byName := map[string]*armmanagementgroups.EntityInfo{}
	for _, e := range entities {
		if isManagementGroupEntity(e) {
			byName[strings.ToLower(convert.ToValue(e.Name))] = e
		}
	}

	res := []any{}
	// Reverse the root-first chain so the immediate parent comes first.
	for _, c := range slices.Backward(chain) {
		e, ok := byName[strings.ToLower(c)]
		if !ok {
			continue
		}
		group, err := newMqlManagementGroup(a.MqlRuntime, e, entities)
		if err != nil {
			return nil, err
		}
		res = append(res, group)
	}
	return res, nil
}

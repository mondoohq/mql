// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// Unified RBAC providers beyond the directory one. Exchange Online and
// Microsoft Defender XDR expose their roles through the same unified role
// management API as Entra ID, but only on the beta endpoint.
const (
	rbacProviderExchange = "exchange"
	rbacProviderDefender = "defender"

	exchangeRoleManagementID = "microsoft.exchangeRoleManagement"
	defenderRoleManagementID = "microsoft.defenderRoleManagement"

	// Graph application permissions for reading each provider's roles.
	exchangeRBACReadPermission = "RoleManagement.Read.Exchange"
	defenderRBACReadPermission = "RoleManagement.Read.Defender"
	// Resolving assigned principals reads them from the directory.
	directoryReadPermission = "Directory.Read.All"
)

// unifiedRBACID namespaces a role definition or assignment id by its RBAC
// provider. Ids are only unique within one provider, and the directory
// provider's definitions use the bare id as their cache key.
func unifiedRBACID(provider string, kind string, id string) string {
	return provider + "/" + kind + "/" + id
}

func (a *mqlMicrosoft) exchangeRoleManagement() (*mqlMicrosoftExchangeRoleManagement, error) {
	return exchangeRoleManagementRoot(a.MqlRuntime)
}

func (a *mqlMicrosoft) defenderRoleManagement() (*mqlMicrosoftDefenderRoleManagement, error) {
	return defenderRoleManagementRoot(a.MqlRuntime)
}

func exchangeRoleManagementRoot(runtime *plugin.Runtime) (*mqlMicrosoftExchangeRoleManagement, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftExchangeRoleManagement, map[string]*llx.RawData{
		"__id": llx.StringData(exchangeRoleManagementID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftExchangeRoleManagement), nil
}

func defenderRoleManagementRoot(runtime *plugin.Runtime) (*mqlMicrosoftDefenderRoleManagement, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftDefenderRoleManagement, map[string]*llx.RawData{
		"__id": llx.StringData(defenderRoleManagementID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftDefenderRoleManagement), nil
}

func (a *mqlMicrosoftExchangeRoleManagement) id() (string, error) {
	return exchangeRoleManagementID, nil
}

func (a *mqlMicrosoftDefenderRoleManagement) id() (string, error) {
	return defenderRoleManagementID, nil
}

// listDistinctAttempts bounds how often listDistinct re-reads a listing.
const listDistinctAttempts = 5

// listDistinct reads a listing whose pages are not stable, and returns every
// distinct entry, keyed by id.
//
// The beta Exchange role endpoints page by offset over an order that changes
// between requests and reject $orderby, so a walk over several pages returns
// the right number of entries with some repeated and as many others missing.
// The listing is read again, and the entries of every read are combined, until
// the combination holds as many distinct entries as a single read returns.
// An entry without an id is dropped, as it can not be told apart from others.
func listDistinct[T any](fetch func() ([]T, error), id func(T) string) ([]T, error) {
	seen := map[string]struct{}{}
	res := []T{}
	want := 0
	for attempt := 1; attempt <= listDistinctAttempts; attempt++ {
		items, err := fetch()
		if err != nil {
			return nil, err
		}
		n := 0
		for _, item := range items {
			key := id(item)
			if key == "" {
				continue
			}
			n++
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			res = append(res, item)
		}
		want = max(want, n)
		if len(res) >= want {
			return res, nil
		}
		log.Debug().
			Int("attempt", attempt).
			Int("distinct", len(res)).
			Int("want", want).
			Msg("ms365> listing returned repeated entries; reading it again")
	}
	return nil, fmt.Errorf("listing is incomplete after %d reads: %d of %d entries read", listDistinctAttempts, len(res), want)
}

// entityID is the id of a Graph entity, empty for a nil entry.
func entityID[T interface{ GetId() *string }](e T) string {
	if any(e) == nil {
		return ""
	}
	return convert.ToValue(e.GetId())
}

// memoList computes a resource list once and hands every caller the same
// answer, error included. Role definitions and assignments are read by the
// list fields and by every reference between them, so each is fetched once.
type memoList struct {
	lock sync.Mutex
	done bool
	list []any
	err  error
}

func (m *memoList) get(fetch func() ([]any, error)) ([]any, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if !m.done {
		m.list, m.err = fetch()
		m.done = true
	}
	return m.list, m.err
}

// ---------------------------------------------------------------------------
// Exchange Online

type mqlMicrosoftExchangeRoleManagementInternal struct {
	definitions memoList
	assignments memoList
}

func (a *mqlMicrosoftExchangeRoleManagement) roleDefinitions() ([]any, error) {
	return a.definitions.get(func() ([]any, error) {
		return fetchExchangeRoleDefinitions(a.MqlRuntime)
	})
}

func (a *mqlMicrosoftExchangeRoleManagement) roleAssignments() ([]any, error) {
	return a.assignments.get(func() ([]any, error) {
		return fetchExchangeRoleAssignments(a.MqlRuntime)
	})
}

func fetchExchangeRoleDefinitions(runtime *plugin.Runtime) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	defs, err := listDistinct(func() ([]betamodels.UnifiedRoleDefinitionable, error) {
		resp, err := betaClient.RoleManagement().Exchange().RoleDefinitions().Get(ctx, nil)
		if err != nil {
			return nil, classifyGraphError(err, exchangeRBACReadPermission)
		}
		defs, err := iterate[betamodels.UnifiedRoleDefinitionable](ctx, resp, betaClient.GetAdapter(), betamodels.CreateUnifiedRoleDefinitionCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return nil, classifyGraphError(err, exchangeRBACReadPermission)
		}
		return defs, nil
	}, entityID[betamodels.UnifiedRoleDefinitionable])
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(defs))
	for _, def := range defs {
		if def == nil {
			continue
		}
		rolePermissions, err := convert.JsonToDictSlice(newRolePermissions(def.GetRolePermissions()))
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(runtime, ResourceMicrosoftRolemanagementRoledefinition, map[string]*llx.RawData{
			"__id":            llx.StringData(unifiedRBACID(rbacProviderExchange, "roleDefinition", convert.ToValue(def.GetId()))),
			"id":              llx.StringDataPtr(def.GetId()),
			"description":     llx.StringDataPtr(def.GetDescription()),
			"displayName":     llx.StringDataPtr(def.GetDisplayName()),
			"isBuiltIn":       llx.BoolDataPtr(def.GetIsBuiltIn()),
			"isEnabled":       llx.BoolDataPtr(def.GetIsEnabled()),
			"rolePermissions": llx.ArrayData(rolePermissions, types.Any),
			"templateId":      llx.StringDataPtr(def.GetTemplateId()),
			"version":         llx.StringDataPtr(def.GetVersion()),
		})
		if err != nil {
			return nil, err
		}
		mqlDef := r.(*mqlMicrosoftRolemanagementRoledefinition)
		mqlDef.rbacProvider = rbacProviderExchange
		res = append(res, mqlDef)
	}
	return res, nil
}

func fetchExchangeRoleAssignments(runtime *plugin.Runtime) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	assignments, err := listDistinct(func() ([]betamodels.UnifiedRoleAssignmentable, error) {
		resp, err := betaClient.RoleManagement().Exchange().RoleAssignments().Get(ctx, nil)
		if err != nil {
			return nil, classifyGraphError(err, exchangeRBACReadPermission)
		}
		assignments, err := iterate[betamodels.UnifiedRoleAssignmentable](ctx, resp, betaClient.GetAdapter(), betamodels.CreateUnifiedRoleAssignmentCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return nil, classifyGraphError(err, exchangeRBACReadPermission)
		}
		return assignments, nil
	}, entityID[betamodels.UnifiedRoleAssignmentable])
	if err != nil {
		return nil, err
	}

	principalIds := []string{}
	for _, assignment := range assignments {
		if assignment == nil {
			continue
		}
		if id := assignment.GetPrincipalId(); id != nil && *id != "" {
			principalIds = append(principalIds, *id)
		}
	}
	principals, err := fetchDirectoryObjectsByIds(ctx, graphClient, directoryObjectIds(principalIds))
	if err != nil {
		return nil, classifyGraphError(err, directoryReadPermission)
	}

	res := make([]any, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment == nil {
			continue
		}
		var principal models.DirectoryObjectable
		if id := assignment.GetPrincipalId(); id != nil {
			principal = principals[*id]
		}
		principalDict, err := convert.JsonToDict(newDirectoryPrincipal(principal))
		if err != nil {
			return nil, err
		}
		principalType, principalName := directoryPrincipalInfo(principal)
		if principal == nil {
			principalType, principalName = exchangePrincipalInfo(convert.ToValue(assignment.GetPrincipalId()))
		}
		r, err := CreateResource(runtime, ResourceMicrosoftRolemanagementRoleassignment, map[string]*llx.RawData{
			"__id":             llx.StringData(unifiedRBACID(rbacProviderExchange, "roleAssignment", convert.ToValue(assignment.GetId()))),
			"id":               llx.StringDataPtr(assignment.GetId()),
			"principalId":      llx.StringDataPtr(assignment.GetPrincipalId()),
			"principalType":    llx.StringData(principalType),
			"principalName":    llx.StringData(principalName),
			"principal":        llx.DictData(principalDict),
			"directoryScopeId": llx.StringDataPtr(assignment.GetDirectoryScopeId()),
			"appScopeId":       llx.StringDataPtr(assignment.GetAppScopeId()),
			"condition":        llx.StringDataPtr(assignment.GetCondition()),
		})
		if err != nil {
			return nil, err
		}
		mqlAssignment := r.(*mqlMicrosoftRolemanagementRoleassignment)
		mqlAssignment.rbacProvider = rbacProviderExchange
		mqlAssignment.cacheRoleDefinitionID = convert.ToValue(assignment.GetRoleDefinitionId())
		res = append(res, mqlAssignment)
	}
	return res, nil
}

// exchangePrincipalPrefixes maps the path prefixes Exchange uses for principals
// that live outside the directory to the principal type they denote.
var exchangePrincipalPrefixes = []struct {
	prefix        string
	principalType string
}{
	{"/RoleGroups/", "roleGroup"},
	{"/RoleAssignmentPolicies/", "roleAssignmentPolicy"},
}

// exchangePrincipalInfo derives the principal type and name of an Exchange
// principal that is not a directory object, such as
// `/RoleGroups/Organization Management`. Both are empty for any other form.
func exchangePrincipalInfo(principalId string) (principalType string, principalName string) {
	for _, p := range exchangePrincipalPrefixes {
		if name, ok := strings.CutPrefix(principalId, p.prefix); ok && name != "" {
			return p.principalType, name
		}
	}
	return "", ""
}

// exchangeRoleDefinitionByID finds an Exchange role definition in the tenant's
// definition list, nil when no definition has that id.
func exchangeRoleDefinitionByID(runtime *plugin.Runtime, id string) (*mqlMicrosoftRolemanagementRoledefinition, error) {
	root, err := exchangeRoleManagementRoot(runtime)
	if err != nil {
		return nil, err
	}
	defs, err := root.roleDefinitions()
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		def := d.(*mqlMicrosoftRolemanagementRoledefinition)
		if def.Id.Data == id {
			return def, nil
		}
	}
	return nil, nil
}

// exchangeRoleAssignmentsForDefinition picks the assignments of one Exchange
// role definition out of the tenant's assignment list.
func exchangeRoleAssignmentsForDefinition(runtime *plugin.Runtime, definitionID string) ([]any, error) {
	root, err := exchangeRoleManagementRoot(runtime)
	if err != nil {
		return nil, err
	}
	all, err := root.roleAssignments()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, a := range all {
		if a.(*mqlMicrosoftRolemanagementRoleassignment).cacheRoleDefinitionID == definitionID {
			res = append(res, a)
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Microsoft Defender XDR

type mqlMicrosoftDefenderRoleManagementInternal struct {
	definitions memoList
	assignments memoList
}

func (a *mqlMicrosoftDefenderRoleManagement) roleDefinitions() ([]any, error) {
	return a.definitions.get(func() ([]any, error) {
		return fetchDefenderRoleDefinitions(a.MqlRuntime)
	})
}

func (a *mqlMicrosoftDefenderRoleManagement) roleAssignments() ([]any, error) {
	return a.assignments.get(func() ([]any, error) {
		return fetchDefenderRoleAssignments(a.MqlRuntime)
	})
}

func fetchDefenderRoleDefinitions(runtime *plugin.Runtime) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	defs, err := listDistinct(func() ([]betamodels.UnifiedRoleDefinitionable, error) {
		resp, err := betaClient.RoleManagement().Defender().RoleDefinitions().Get(ctx, nil)
		if err != nil {
			return nil, classifyGraphError(err, defenderRBACReadPermission)
		}
		defs, err := iterate[betamodels.UnifiedRoleDefinitionable](ctx, resp, betaClient.GetAdapter(), betamodels.CreateUnifiedRoleDefinitionCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return nil, classifyGraphError(err, defenderRBACReadPermission)
		}
		return defs, nil
	}, entityID[betamodels.UnifiedRoleDefinitionable])
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(defs))
	for _, def := range defs {
		if def == nil {
			continue
		}
		rolePermissions, err := convert.JsonToDictSlice(newRolePermissions(def.GetRolePermissions()))
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(runtime, ResourceMicrosoftDefenderRoleManagementRoleDefinition, map[string]*llx.RawData{
			"__id":            llx.StringData(unifiedRBACID(rbacProviderDefender, "roleDefinition", convert.ToValue(def.GetId()))),
			"id":              llx.StringDataPtr(def.GetId()),
			"displayName":     llx.StringDataPtr(def.GetDisplayName()),
			"description":     llx.StringDataPtr(def.GetDescription()),
			"isBuiltIn":       llx.BoolDataPtr(def.GetIsBuiltIn()),
			"isEnabled":       llx.BoolDataPtr(def.GetIsEnabled()),
			"rolePermissions": llx.ArrayData(rolePermissions, types.Any),
			"version":         llx.StringDataPtr(def.GetVersion()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

type mqlMicrosoftDefenderRoleManagementRoleAssignmentInternal struct {
	cacheRoleDefinitionID string
	principals            assignedPrincipals
}

// assignedPrincipals is the set of principals of one assignment, split by
// directory type.
type assignedPrincipals struct {
	userIds             []string
	groupIds            []string
	servicePrincipalIds []string
}

// splitPrincipalsByType sorts principal ids by the directory type of the
// object each resolves to. An id with no directory object (a principal that
// was deleted) or of another type is reported in skipped.
func splitPrincipalsByType(ids []string, objects map[string]models.DirectoryObjectable) (res assignedPrincipals, skipped []string) {
	for _, id := range ids {
		obj := objects[id]
		if obj == nil {
			skipped = append(skipped, id)
			continue
		}
		t, _ := directoryPrincipalInfo(obj)
		switch t {
		case "user":
			res.userIds = append(res.userIds, id)
		case "group":
			res.groupIds = append(res.groupIds, id)
		case "servicePrincipal":
			res.servicePrincipalIds = append(res.servicePrincipalIds, id)
		default:
			skipped = append(skipped, id)
		}
	}
	return res, skipped
}

func fetchDefenderRoleAssignments(runtime *plugin.Runtime) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	assignments, err := listDistinct(func() ([]betamodels.UnifiedRoleAssignmentMultipleable, error) {
		resp, err := betaClient.RoleManagement().Defender().RoleAssignments().Get(ctx, nil)
		if err != nil {
			return nil, classifyGraphError(err, defenderRBACReadPermission)
		}
		assignments, err := iterate[betamodels.UnifiedRoleAssignmentMultipleable](ctx, resp, betaClient.GetAdapter(), betamodels.CreateUnifiedRoleAssignmentMultipleCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return nil, classifyGraphError(err, defenderRBACReadPermission)
		}
		return assignments, nil
	}, entityID[betamodels.UnifiedRoleAssignmentMultipleable])
	if err != nil {
		return nil, err
	}

	principalIds := []string{}
	for _, assignment := range assignments {
		if assignment == nil {
			continue
		}
		principalIds = append(principalIds, assignment.GetPrincipalIds()...)
	}
	principals, err := fetchDirectoryObjectsByIds(ctx, graphClient, directoryObjectIds(principalIds))
	if err != nil {
		return nil, classifyGraphError(err, directoryReadPermission)
	}

	res := make([]any, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment == nil {
			continue
		}
		r, err := CreateResource(runtime, ResourceMicrosoftDefenderRoleManagementRoleAssignment, map[string]*llx.RawData{
			"__id":              llx.StringData(unifiedRBACID(rbacProviderDefender, "roleAssignment", convert.ToValue(assignment.GetId()))),
			"id":                llx.StringDataPtr(assignment.GetId()),
			"displayName":       llx.StringDataPtr(assignment.GetDisplayName()),
			"description":       llx.StringDataPtr(assignment.GetDescription()),
			"directoryScopeIds": llx.ArrayData(convert.SliceAnyToInterface(assignment.GetDirectoryScopeIds()), types.String),
			"appScopeIds":       llx.ArrayData(convert.SliceAnyToInterface(assignment.GetAppScopeIds()), types.String),
			"condition":         llx.StringDataPtr(assignment.GetCondition()),
		})
		if err != nil {
			return nil, err
		}
		mqlAssignment := r.(*mqlMicrosoftDefenderRoleManagementRoleAssignment)
		mqlAssignment.cacheRoleDefinitionID = convert.ToValue(assignment.GetRoleDefinitionId())
		split, skipped := splitPrincipalsByType(assignment.GetPrincipalIds(), principals)
		if len(skipped) > 0 {
			log.Debug().
				Str("assignment", mqlAssignment.Id.Data).
				Strs("principalIds", skipped).
				Msg("ms365> defender role assignment principals not found in the directory")
		}
		mqlAssignment.principals = split
		res = append(res, mqlAssignment)
	}
	return res, nil
}

func (a *mqlMicrosoftDefenderRoleManagementRoleDefinition) assignments() ([]any, error) {
	root, err := defenderRoleManagementRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	all, err := root.roleAssignments()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, x := range all {
		if x.(*mqlMicrosoftDefenderRoleManagementRoleAssignment).cacheRoleDefinitionID == a.Id.Data {
			res = append(res, x)
		}
	}
	return res, nil
}

func (a *mqlMicrosoftDefenderRoleManagementRoleAssignment) roleDefinition() (*mqlMicrosoftDefenderRoleManagementRoleDefinition, error) {
	if a.cacheRoleDefinitionID != "" {
		root, err := defenderRoleManagementRoot(a.MqlRuntime)
		if err != nil {
			return nil, err
		}
		defs, err := root.roleDefinitions()
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			def := d.(*mqlMicrosoftDefenderRoleManagementRoleDefinition)
			if def.Id.Data == a.cacheRoleDefinitionID {
				return def, nil
			}
		}
	}
	a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlMicrosoftDefenderRoleManagementRoleAssignment) users() ([]any, error) {
	return newResourcesByID(a.MqlRuntime, ResourceMicrosoftUser, a.principals.userIds)
}

func (a *mqlMicrosoftDefenderRoleManagementRoleAssignment) groups() ([]any, error) {
	return newResourcesByID(a.MqlRuntime, ResourceMicrosoftGroup, a.principals.groupIds)
}

func (a *mqlMicrosoftDefenderRoleManagementRoleAssignment) servicePrincipals() ([]any, error) {
	return newResourcesByID(a.MqlRuntime, ResourceMicrosoftServiceprincipal, a.principals.servicePrincipalIds)
}

// newResourcesByID resolves each id as resource.
func newResourcesByID(runtime *plugin.Runtime, resource string, ids []string) ([]any, error) {
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		r, err := NewResource(runtime, resource, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// newRolePermissions converts the permission sets of a beta role definition.
func newRolePermissions(p []betamodels.UnifiedRolePermissionable) []UnifiedRolePermission {
	res := []UnifiedRolePermission{}
	for i := range p {
		if p[i] == nil {
			continue
		}
		res = append(res, newUnifiedRolePermission(p[i]))
	}
	return res
}

// directoryObjectIds returns the principal ids that name a directory object,
// without duplicates, keeping the first occurrence. Unified RBAC providers also
// assign roles to principals outside the directory, such as Exchange role
// groups (`/RoleGroups/<name>`), and Graph rejects a whole getByIds request
// that carries one of those.
func directoryObjectIds(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	res := make([]string, 0, len(ids))
	for _, id := range ids {
		if uuid.Validate(id) != nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		res = append(res, id)
	}
	return res
}

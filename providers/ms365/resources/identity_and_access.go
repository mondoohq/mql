// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	graphidentitygovernance "github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/organization"
	graphpolicies "github.com/microsoftgraph/msgraph-sdk-go/policies"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	defaultRequestFilterDirectoryRole = "scopeId eq '/' and scopeType eq 'DirectoryRole'"

	identityAndAccessID                                     = "microsoft.identityAndAccess"
	identityAndAccessPrivilegedIdentityManagementID         = "microsoft.identityAndAccess/privilegedIdentityManagement"
	identityAndAccessPrivilegedIdentityManagementPoliciesID = "microsoft.identityAndAccess/privilegedIdentityManagement/policies"
)

func (a *mqlMicrosoft) identityAndAccess() (*mqlMicrosoftIdentityAndAccess, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft.identityAndAccess", nil)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccess), nil
}

func (a *mqlMicrosoftIdentityAndAccess) privilegedIdentityManagement() (*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagement, error) {
	resource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagement, map[string]*llx.RawData{
		"__id": llx.StringData(identityAndAccessPrivilegedIdentityManagementID),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagement), nil
}

func (a *mqlMicrosoftIdentityAndAccess) organization() (*mqlMicrosoftTenant, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	tenant, err := graphClient.Organization().ByOrganizationId(conn.TenantId()).Get(context.Background(), &organization.OrganizationItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &organization.OrganizationItemRequestBuilderGetQueryParameters{
			Select: tenantFields,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("organization not found for tenant %q", conn.TenantId())
	}

	return newMicrosoftTenant(a.MqlRuntime, tenant)
}

func (pim *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagement) policies() (*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies, error) {
	resource, err := CreateResource(pim.MqlRuntime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies), nil
}

func initMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return args, nil, nil
}

// filterID renders a filter value for embedding in a resource __id, using an
// explicit sentinel for the empty (no-filter) case so unfiltered instances
// share one deliberate cache key rather than an empty-suffixed one.
func filterID(filter string) string {
	if filter == "" {
		return "<none>"
	}
	return filter
}

func (a *mqlMicrosoftIdentityAndAccess) id() (string, error) {
	return identityAndAccessID, nil
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies) id() (string, error) {
	return identityAndAccessPrivilegedIdentityManagementPoliciesID + "/filter/" + filterID(a.Filter.Data), nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessReviews) id() (string, error) {
	return "microsoft.identityAndAccess.accessReviews/filter/" + filterID(a.Filter.Data), nil
}

func (a *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicies) list() ([]any, error) {
	return listRoleManagementPolicies(a.MqlRuntime, a.Filter.Data)
}

func listRoleManagementPolicies(runtime *plugin.Runtime, requestFilter string) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	if requestFilter == "" {
		requestFilter = defaultRequestFilterDirectoryRole
	}

	requestParameters := &graphpolicies.RoleManagementPoliciesRequestBuilderGetQueryParameters{}

	switch {
	case strings.Contains(requestFilter, "scopeType eq 'DirectoryRole'"):
		requestParameters = &graphpolicies.RoleManagementPoliciesRequestBuilderGetQueryParameters{
			Filter: &requestFilter,
		}
	// we can only get rules if scopeType set to 'Directory'
	case strings.Contains(requestFilter, "scopeType eq 'Directory'"):
		requestParameters = &graphpolicies.RoleManagementPoliciesRequestBuilderGetQueryParameters{
			Filter: &requestFilter,
			Expand: []string{"rules"},
		}

	default:
		return nil, fmt.Errorf("scopeType in the filter needs to equal to 'Directory' or 'DirectoryRole', got %q", requestFilter)
	}

	configuration := &graphpolicies.RoleManagementPoliciesRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().RoleManagementPolicies().Get(ctx, configuration)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve role management policies with filter '%s': %w", requestFilter, err)
	}
	if resp == nil {
		return nil, nil
	}
	policies, err := iterate[models.UnifiedRoleManagementPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleManagementPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var policyResources []any
	for _, policy := range policies {
		if policy.GetId() != nil && policy.GetDisplayName() != nil {
			policyResource, err := newMqlRoleManagementPolicy(runtime, policy)
			if err != nil {
				return nil, fmt.Errorf("failed to create MQL resource for policy ID %s: %w", *policy.GetId(), err)
			}
			policyResources = append(policyResources, policyResource)
		}
	}

	return policyResources, nil
}

func newMqlRoleManagementPolicy(runtime *plugin.Runtime, u models.UnifiedRoleManagementPolicyable) (any, error) {
	lastModifiedByDict := map[string]any{}
	var err error

	if u.GetLastModifiedBy() != nil {
		lastModifiedByDict, err = convert.JsonToDict(newLastModifiedBy(u.GetLastModifiedBy()))
		if err != nil {
			return nil, err
		}
	}

	resource, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy,
		map[string]*llx.RawData{
			"__id":                  llx.StringDataPtr(u.GetId()),
			"id":                    llx.StringDataPtr(u.GetId()),
			"displayName":           llx.StringDataPtr(u.GetDisplayName()),
			"description":           llx.StringDataPtr(u.GetDescription()),
			"isOrganizationDefault": llx.BoolDataPtr(u.GetIsOrganizationDefault()),
			"scopeId":               llx.StringDataPtr(u.GetScopeId()),
			"scopeType":             llx.StringDataPtr(u.GetScopeType()),
			"lastModifiedDateTime":  graphTimeData(u.GetLastModifiedDateTime()),
			"lastModifiedBy":        llx.DictData(lastModifiedByDict),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy), nil
}

func (m *mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicy) rules() ([]any, error) {
	return listRoleManagementPolicyRules(m.MqlRuntime, m.Id.Data)
}

func listRoleManagementPolicyRules(runtime *plugin.Runtime, policyID string) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	if policyID == "" {
		return nil, fmt.Errorf("policy resource has an empty ID, cannot fetch rules")
	}

	ctx := context.Background()

	rulesResult, err := graphClient.Policies().RoleManagementPolicies().ByUnifiedRoleManagementPolicyId(policyID).Rules().Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules for policy %s: %w", policyID, err)
	}

	var ruleResources []any
	if rulesResult == nil {
		return nil, nil
	}

	// Follow @odata.nextLink so policies with more than one page of rules are
	// fully enumerated rather than truncated to the first page.
	rules, err := iterate[models.UnifiedRoleManagementPolicyRuleable](ctx, rulesResult, graphClient.GetAdapter(), models.CreateUnifiedRoleManagementPolicyRuleCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	for _, rule := range rules {
		if rule.GetId() == nil {
			continue
		}
		ruleResource, err := newMqlRoleManagementPolicyRule(runtime, rule)
		if err != nil {
			return nil, fmt.Errorf("failed to create MQL resource for rule ID %s: %w", *rule.GetId(), err)
		}
		ruleResources = append(ruleResources, ruleResource)
	}

	return ruleResources, nil
}

func newMqlRoleManagementPolicyRule(runtime *plugin.Runtime, rule models.UnifiedRoleManagementPolicyRuleable) (any, error) {
	const targetResource = ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicyRuleTarget
	var mqlPolicyRuleTarget plugin.Resource
	var err error

	if rule.GetTarget() != nil {
		ruleTargetID := fmt.Sprintf("%s-ruleTarget", *rule.GetId())
		targetData := map[string]*llx.RawData{
			"__id":                llx.StringData(ruleTargetID),
			"caller":              llx.StringDataPtr(rule.GetTarget().GetCaller()),
			"enforcedSettings":    llx.ArrayData(convert.SliceAnyToInterface(rule.GetTarget().GetEnforcedSettings()), types.String),
			"inheritableSettings": llx.ArrayData(convert.SliceAnyToInterface(rule.GetTarget().GetInheritableSettings()), types.String),
			"level":               llx.StringDataPtr(rule.GetTarget().GetLevel()),
			"operations":          llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(rule.GetTarget().GetOperations())), types.String),
		}

		mqlPolicyRuleTarget, err = CreateResource(runtime, targetResource, targetData)
		if err != nil {
			return nil, err
		}
	}

	resource, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicyRule,
		map[string]*llx.RawData{
			"__id":   llx.StringDataPtr(rule.GetId()),
			"id":     llx.StringDataPtr(rule.GetId()),
			"target": llx.ResourceData(mqlPolicyRuleTarget, targetResource),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicyRule), nil
}

// Least privileged permissions: RoleEligibilitySchedule.Read.Directory
func (a *mqlMicrosoftIdentityAndAccess) roleEligibilityScheduleInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.RoleManagement().Directory().RoleEligibilityScheduleInstances().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	if resp == nil {
		return nil, nil
	}
	roleEligibilityScheduleInstances, err := iterate[models.UnifiedRoleEligibilityScheduleInstanceable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleEligibilityScheduleInstanceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var instances []any
	for _, inst := range roleEligibilityScheduleInstances {
		if inst.GetId() == nil {
			continue
		}
		instanceResource, err := newMqlRoleEligibilityScheduleInstance(a.MqlRuntime, inst)
		if err != nil {
			return nil, fmt.Errorf("failed to create MQL resource for rule ID %s: %w", *inst.GetId(), err)
		}
		instances = append(instances, instanceResource)
	}

	return instances, nil
}

type mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstanceInternal struct {
	cacheRoleDefinitionID string
}

func newMqlRoleEligibilityScheduleInstance(runtime *plugin.Runtime, inst models.UnifiedRoleEligibilityScheduleInstanceable) (*mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance, error) {
	resource, err := CreateResource(runtime, "microsoft.identityAndAccess.roleEligibilityScheduleInstance", map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(inst.GetId()),
		"__id":                      llx.StringDataPtr(inst.GetId()),
		"principalId":               llx.StringDataPtr(inst.GetPrincipalId()),
		"directoryScopeId":          llx.StringDataPtr(inst.GetDirectoryScopeId()),
		"appScopeId":                llx.StringDataPtr(inst.GetAppScopeId()),
		"startDateTime":             graphTimeData(inst.GetStartDateTime()),
		"endDateTime":               graphTimeData(inst.GetEndDateTime()),
		"memberType":                llx.StringDataPtr(inst.GetMemberType()),
		"roleEligibilityScheduleId": llx.StringDataPtr(inst.GetRoleEligibilityScheduleId()),
	})
	if err != nil {
		return nil, err
	}
	mqlInstance := resource.(*mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance)
	if roleDefinitionID := inst.GetRoleDefinitionId(); roleDefinitionID != nil {
		mqlInstance.cacheRoleDefinitionID = *roleDefinitionID
	}
	return mqlInstance, nil
}

// roleDefinition resolves the role definition this eligibility grants.
func (a *mqlMicrosoftIdentityAndAccessRoleEligibilityScheduleInstance) roleDefinition() (*mqlMicrosoftRolemanagementRoledefinition, error) {
	id := a.cacheRoleDefinitionID
	if id == "" {
		a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "microsoft.rolemanagement.roledefinition", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftRolemanagementRoledefinition), nil
}

// Implementation for the new identityAndSignIn resource
func (a *mqlMicrosoftIdentityAndAccess) identityAndSignIn() (*mqlMicrosoftIdentityAndAccessIdentityAndSignIn, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft.identityAndAccess.identityAndSignIn", map[string]*llx.RawData{
		"__id": llx.StringData("identityAndSignIn"),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessIdentityAndSignIn), nil
}

// Implementation for the policies resource
func (a *mqlMicrosoftIdentityAndAccessIdentityAndSignIn) policies() (*mqlMicrosoftIdentityAndAccessIdentityAndSignInPolicies, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft.identityAndAccess.identityAndSignIn.policies", map[string]*llx.RawData{
		"__id": llx.StringData("policies"),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessIdentityAndSignInPolicies), nil
}

// initMicrosoftIdentityAndAccessIdentityAndSignInPoliciesIdentitySecurityDefaultsEnforcementPolicy
// populates the policy when it is queried directly via its full dotted path
// rather than through the parent accessor chain. Without this, the terminal
// resource is built as a bare husk with all fields null. We rebuild the chain
// (identityAndSignIn -> policies -> identitySecurityDefaultsEnforcementPolicy),
// which fetches the policy.
func initMicrosoftIdentityAndAccessIdentityAndSignInPoliciesIdentitySecurityDefaultsEnforcementPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	signIn, err := CreateResource(runtime, "microsoft.identityAndAccess.identityAndSignIn", map[string]*llx.RawData{
		"__id": llx.StringData("identityAndSignIn"),
	})
	if err != nil {
		return nil, nil, err
	}

	policies, err := signIn.(*mqlMicrosoftIdentityAndAccessIdentityAndSignIn).policies()
	if err != nil {
		return nil, nil, err
	}

	policy, err := policies.identitySecurityDefaultsEnforcementPolicy()
	if err != nil {
		return nil, nil, err
	}

	return nil, policy, nil
}

// Implementation for the identitySecurityDefaultsEnforcementPolicy resource
func (a *mqlMicrosoftIdentityAndAccessIdentityAndSignInPolicies) identitySecurityDefaultsEnforcementPolicy() (*mqlMicrosoftIdentityAndAccessIdentityAndSignInPoliciesIdentitySecurityDefaultsEnforcementPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policy, err := graphClient.Policies().IdentitySecurityDefaultsEnforcementPolicy().Get(ctx, &graphpolicies.IdentitySecurityDefaultsEnforcementPolicyRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}

	if policy == nil {
		return nil, fmt.Errorf("identity security defaults enforcement policy not found")
	}

	// Extract the policy data
	policyId := ""
	if policy.GetId() != nil {
		policyId = *policy.GetId()
	}

	displayName := ""
	if policy.GetDisplayName() != nil {
		displayName = *policy.GetDisplayName()
	}

	description := ""
	if policy.GetDescription() != nil {
		description = *policy.GetDescription()
	}

	isEnabled := false
	if policy.GetIsEnabled() != nil {
		isEnabled = *policy.GetIsEnabled()
	}

	resource, err := CreateResource(a.MqlRuntime, "microsoft.identityAndAccess.identityAndSignIn.policies.identitySecurityDefaultsEnforcementPolicy", map[string]*llx.RawData{
		"__id":        llx.StringData(policyId),
		"id":          llx.StringData(policyId),
		"displayName": llx.StringData(displayName),
		"description": llx.StringData(description),
		"isEnabled":   llx.BoolData(isEnabled),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftIdentityAndAccessIdentityAndSignInPoliciesIdentitySecurityDefaultsEnforcementPolicy), nil
}

// Needs the permission AccessReview.Read.All
func (a *mqlMicrosoft) accessReviews() (*mqlMicrosoftIdentityAndAccessAccessReviews, error) {
	mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.identityAndAccess.accessReviews", map[string]*llx.RawData{})
	return mqlResource.(*mqlMicrosoftIdentityAndAccessAccessReviews), err
}

// The $filter query parameter with the contains operator is supported on
// the scope property of accessReviewScheduleDefinition. Use the following format for the request:
// filter=contains(scope/microsoft.graph.accessReviewQueryScope/query, '{object}')
// The {object} can have one of the following values:
// /groups: List every accessReviewScheduleDefinition on individual groups (excludes definitions scoped to all Microsoft 365 groups with guests).
// /groups/{group_id}:	List every accessReviewScheduleDefinition on a specific group (excludes definitions scoped to all Microsoft 365 groups with guests).
// ./members: List every accessReviewScheduleDefinition scoped to all Microsoft 365 groups with guests.
// accessPackageAssignments:	List every accessReviewScheduleDefinition on an access package.
// roleAssignmentScheduleInstances:	List every accessReviewScheduleDefinition for principals that are assigned to a privileged role.
func (a *mqlMicrosoftIdentityAndAccessAccessReviews) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	configuration := &graphidentitygovernance.AccessReviewsDefinitionsRequestBuilderGetRequestConfiguration{}

	requestFilter := a.Filter.Data
	if requestFilter != "" {
		requestParameters := &graphidentitygovernance.AccessReviewsDefinitionsRequestBuilderGetQueryParameters{
			Filter: &requestFilter,
		}
		configuration = &graphidentitygovernance.AccessReviewsDefinitionsRequestBuilderGetRequestConfiguration{
			QueryParameters: requestParameters,
		}
	}

	ctx := context.Background()
	resp, err := graphClient.
		IdentityGovernance().
		AccessReviews().
		Definitions().
		Get(ctx, configuration)
	if err != nil {
		return nil, transformError(err)
	}
	if resp == nil {
		return nil, nil
	}
	definitions, err := iterate[models.AccessReviewScheduleDefinitionable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessReviewScheduleDefinitionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var accessReviewResources []any
	for _, accessReviewSchedule := range definitions {
		if accessReviewSchedule.GetId() != nil {
			reviewResource, err := newMqlAccessReviewDefinition(a.MqlRuntime, accessReviewSchedule)
			if err != nil {
				return nil, fmt.Errorf("failed to create MQL resource for access review ID %s: %w", *accessReviewSchedule.GetId(), err)
			}
			accessReviewResources = append(accessReviewResources, reviewResource)
		}
	}

	return accessReviewResources, nil
}

// stringPtrOrNil dereferences s for use as a dict value, keeping an absent
// value as nil.
func stringPtrOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// accessReviewReviewersDict builds the deprecated reviewers list: one dict
// per reviewer scope with `reviewer` (the query), `queryType`, and
// `queryRoot`.
func accessReviewReviewersDict(reviewers []models.AccessReviewReviewerScopeable) []any {
	res := []any{}
	for _, reviewer := range reviewers {
		if reviewer == nil {
			continue
		}
		res = append(res, map[string]any{
			"reviewer":  stringPtrOrNil(reviewer.GetQuery()),
			"queryType": stringPtrOrNil(reviewer.GetQueryType()),
			"queryRoot": stringPtrOrNil(reviewer.GetQueryRoot()),
		})
	}
	return res
}

// accessReviewRecurrenceDict builds the recurrence dict of an access review
// schedule: `pattern` and `range` with Graph's property names, each nil when
// the recurrence does not set it.
func accessReviewRecurrenceDict(recurrence models.PatternedRecurrenceable) (map[string]any, error) {
	res := map[string]any{"pattern": nil, "range": nil}
	if recurrence == nil {
		return res, nil
	}
	patternDict, err := kiotaToDict(recurrence.GetPattern())
	if err != nil {
		return nil, err
	}
	if patternDict != nil {
		delete(patternDict, "@odata.type")
		res["pattern"] = patternDict
	}
	rangeDict, err := kiotaToDict(recurrence.GetRangeEscaped())
	if err != nil {
		return nil, err
	}
	if rangeDict != nil {
		delete(rangeDict, "@odata.type")
		res["range"] = rangeDict
	}
	return res, nil
}

func newMqlAccessReviewDefinition(runtime *plugin.Runtime, d models.AccessReviewScheduleDefinitionable) (*mqlMicrosoftIdentityAndAccessAccessReviewDefinition, error) {
	reviewersDict := accessReviewReviewersDict(d.GetReviewers())

	var mqlScope plugin.Resource
	if scope := d.GetScope(); scope != nil {
		if queryScope, ok := scope.(models.AccessReviewQueryScopeable); ok {
			var err error
			mqlScope, err = CreateResource(runtime, ResourceMicrosoftIdentityAndAccessAccessReviewDefinitionScope, map[string]*llx.RawData{
				"__id":      llx.StringData(*d.GetId() + "_scope"),
				"query":     llx.StringDataPtr(queryScope.GetQuery()),
				"queryType": llx.StringDataPtr(queryScope.GetQueryType()),
				"queryRoot": llx.StringDataPtr(queryScope.GetQueryRoot()),
			})
			if err != nil {
				return nil, err
			}
		}
	}

	var mqlAccessReviewScheduleSettings plugin.Resource
	var err error

	if d.GetSettings() != nil {
		settingsId := *d.GetId() + "_settings"

		recurrenceDict, err := accessReviewRecurrenceDict(d.GetSettings().GetRecurrence())
		if err != nil {
			return nil, err
		}

		targetData := map[string]*llx.RawData{
			"__id":                                 llx.StringData(settingsId),
			"autoApplyDecisionsEnabled":            llx.BoolDataPtr(d.GetSettings().GetAutoApplyDecisionsEnabled()),
			"decisionHistoriesForReviewersEnabled": llx.BoolDataPtr(d.GetSettings().GetDecisionHistoriesForReviewersEnabled()),
			"defaultDecision":                      llx.StringDataPtr(d.GetSettings().GetDefaultDecision()),
			"defaultDecisionEnabled":               llx.BoolDataPtr(d.GetSettings().GetDefaultDecisionEnabled()),
			"instanceDurationInDays":               llx.IntDataPtr(d.GetSettings().GetInstanceDurationInDays()),
			"reminderNotificationsEnabled":         llx.BoolDataPtr(d.GetSettings().GetReminderNotificationsEnabled()),
			"justificationRequiredOnApproval":      llx.BoolDataPtr(d.GetSettings().GetJustificationRequiredOnApproval()),
			"mailNotificationsEnabled":             llx.BoolDataPtr(d.GetSettings().GetMailNotificationsEnabled()),
			"recommendationsEnabled":               llx.BoolDataPtr(d.GetSettings().GetRecommendationsEnabled()),
			"recurrence":                           llx.DictData(recurrenceDict),
		}

		mqlAccessReviewScheduleSettings, err = CreateResource(runtime, "microsoft.identityAndAccess.accessReviewDefinition.accessReviewScheduleSettings", targetData)
		if err != nil {
			return nil, err
		}
	}

	reviewerScopes, err := newMqlAccessReviewReviewerScopes(runtime, convert.ToValue(d.GetId()), d.GetReviewers())
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "microsoft.identityAndAccess.accessReviewDefinition",
		map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(d.GetId()),
			"id":             llx.StringDataPtr(d.GetId()),
			"displayName":    llx.StringDataPtr(d.GetDisplayName()),
			"status":         llx.StringDataPtr(d.GetStatus()),
			"scope":          llx.ResourceData(mqlScope, ResourceMicrosoftIdentityAndAccessAccessReviewDefinitionScope),
			"reviewers":      llx.DictData(reviewersDict),
			"reviewerScopes": llx.ArrayData(reviewerScopes, types.Resource(ResourceMicrosoftIdentityAndAccessAccessReviewDefinitionReviewerScope)),
			"settings":       llx.ResourceData(mqlAccessReviewScheduleSettings, "microsoft.identityAndAccess.accessReviewDefinition.accessReviewScheduleSettings"),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftIdentityAndAccessAccessReviewDefinition), nil
}

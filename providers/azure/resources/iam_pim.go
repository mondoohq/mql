// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// scopeForSubscription is the PIM list scope for a subscription's privileged
// role schedules.
func scopeForSubscription(subID string) string {
	return "/subscriptions/" + subID
}

// pimUnavailable reports whether a PIM list error means the tenant genuinely
// has no PIM data — most commonly AadPremiumLicenseRequired on tenants without
// Entra ID P2 / Governance, but also access-denied and not-found. Callers turn
// those into an empty result rather than failing the whole authorization query.
//
// The status codes are matched individually rather than as a 4xx range. A 429
// means Microsoft.Authorization throttled us, which is likely on a tenant-wide
// scan and says nothing about PIM: treating it as "no PIM data" would report
// zero standing Owner eligibilities on a tenant that has dozens, and let
// `roleEligibilitySchedules.none(...)` pass vacuously.
func pimUnavailable(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	switch respErr.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

type mqlAzureSubscriptionAuthorizationServiceRoleEligibilityScheduleInternal struct {
	roleDefinitionId string
}

func (a *mqlAzureSubscriptionAuthorizationService) roleEligibilitySchedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := authorization.NewRoleEligibilitySchedulesClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListForScopePager(scopeForSubscription(a.SubscriptionId.Data), &authorization.RoleEligibilitySchedulesClientListForScopeOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if pimUnavailable(err) {
				log.Warn().Str("subscription", a.SubscriptionId.Data).Msg("PIM role schedules unavailable (requires Entra ID P2 / Governance)")
				return res, nil
			}
			return nil, err
		}
		for _, sched := range page.Value {
			if sched == nil {
				continue
			}
			var principalId, principalType, principalDisplayName, scope, status string
			var memberType, condition, roleDefinitionId, roleDefinitionName string
			var startDateTime, endDateTime *time.Time
			if p := sched.Properties; p != nil {
				principalId = convert.ToValue(p.PrincipalID)
				if p.PrincipalType != nil {
					principalType = string(*p.PrincipalType)
				}
				scope = convert.ToValue(p.Scope)
				if p.Status != nil {
					status = string(*p.Status)
				}
				if p.MemberType != nil {
					memberType = string(*p.MemberType)
				}
				condition = convert.ToValue(p.Condition)
				roleDefinitionId = convert.ToValue(p.RoleDefinitionID)
				startDateTime = p.StartDateTime
				endDateTime = p.EndDateTime
				principalDisplayName, roleDefinitionName = expandedPrincipalAndRoleNames(p.ExpandedProperties)
			}
			mqlSched, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.roleEligibilitySchedule",
				map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(sched.ID),
					"name":                 llx.StringDataPtr(sched.Name),
					"principalId":          llx.StringData(principalId),
					"principalType":        llx.StringData(principalType),
					"principalDisplayName": llx.StringData(principalDisplayName),
					"scope":                llx.StringData(scope),
					"status":               llx.StringData(status),
					"memberType":           llx.StringData(memberType),
					"startDateTime":        llx.TimeDataPtr(startDateTime),
					"endDateTime":          llx.TimeDataPtr(endDateTime),
					"condition":            llx.StringData(condition),
					"roleDefinitionName":   llx.StringData(roleDefinitionName),
				})
			if err != nil {
				return nil, err
			}
			mqlSched.(*mqlAzureSubscriptionAuthorizationServiceRoleEligibilitySchedule).roleDefinitionId = roleDefinitionId
			res = append(res, mqlSched)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleEligibilitySchedule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleEligibilitySchedule) roleDefinition() (*mqlAzureSubscriptionAuthorizationServiceRoleDefinition, error) {
	return resolveRoleDefinition(a.MqlRuntime, a.roleDefinitionId, &a.RoleDefinition)
}

type mqlAzureSubscriptionAuthorizationServiceRoleAssignmentScheduleInternal struct {
	roleDefinitionId string
}

func (a *mqlAzureSubscriptionAuthorizationService) roleAssignmentSchedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := authorization.NewRoleAssignmentSchedulesClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListForScopePager(scopeForSubscription(a.SubscriptionId.Data), &authorization.RoleAssignmentSchedulesClientListForScopeOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if pimUnavailable(err) {
				log.Warn().Str("subscription", a.SubscriptionId.Data).Msg("PIM role schedules unavailable (requires Entra ID P2 / Governance)")
				return res, nil
			}
			return nil, err
		}
		for _, sched := range page.Value {
			if sched == nil {
				continue
			}
			var principalId, principalType, principalDisplayName, scope, status string
			var assignmentType, memberType, condition, roleDefinitionId, roleDefinitionName string
			var startDateTime, endDateTime *time.Time
			if p := sched.Properties; p != nil {
				principalId = convert.ToValue(p.PrincipalID)
				if p.PrincipalType != nil {
					principalType = string(*p.PrincipalType)
				}
				scope = convert.ToValue(p.Scope)
				if p.Status != nil {
					status = string(*p.Status)
				}
				if p.AssignmentType != nil {
					assignmentType = string(*p.AssignmentType)
				}
				if p.MemberType != nil {
					memberType = string(*p.MemberType)
				}
				condition = convert.ToValue(p.Condition)
				roleDefinitionId = convert.ToValue(p.RoleDefinitionID)
				startDateTime = p.StartDateTime
				endDateTime = p.EndDateTime
				principalDisplayName, roleDefinitionName = expandedPrincipalAndRoleNames(p.ExpandedProperties)
			}
			mqlSched, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.roleAssignmentSchedule",
				map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(sched.ID),
					"name":                 llx.StringDataPtr(sched.Name),
					"principalId":          llx.StringData(principalId),
					"principalType":        llx.StringData(principalType),
					"principalDisplayName": llx.StringData(principalDisplayName),
					"scope":                llx.StringData(scope),
					"assignmentType":       llx.StringData(assignmentType),
					"status":               llx.StringData(status),
					"memberType":           llx.StringData(memberType),
					"startDateTime":        llx.TimeDataPtr(startDateTime),
					"endDateTime":          llx.TimeDataPtr(endDateTime),
					"condition":            llx.StringData(condition),
					"roleDefinitionName":   llx.StringData(roleDefinitionName),
				})
			if err != nil {
				return nil, err
			}
			mqlSched.(*mqlAzureSubscriptionAuthorizationServiceRoleAssignmentSchedule).roleDefinitionId = roleDefinitionId
			res = append(res, mqlSched)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleAssignmentSchedule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleAssignmentSchedule) roleDefinition() (*mqlAzureSubscriptionAuthorizationServiceRoleDefinition, error) {
	return resolveRoleDefinition(a.MqlRuntime, a.roleDefinitionId, &a.RoleDefinition)
}

type mqlAzureSubscriptionAuthorizationServiceRoleManagementPolicyInternal struct {
	cacheRules []authorization.RoleManagementPolicyRuleClassification
}

func (a *mqlAzureSubscriptionAuthorizationService) roleManagementPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := authorization.NewRoleManagementPoliciesClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListForScopePager(scopeForSubscription(a.SubscriptionId.Data), nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if pimUnavailable(err) {
				log.Warn().Str("subscription", a.SubscriptionId.Data).Msg("PIM role management policies unavailable (requires Entra ID P2 / Governance)")
				return res, nil
			}
			return nil, err
		}
		for _, policy := range page.Value {
			if policy == nil {
				continue
			}
			var scope, displayName, description string
			var isOrgDefault *bool
			var lastModified *time.Time
			var lastModifiedBy any
			var rules []authorization.RoleManagementPolicyRuleClassification
			if p := policy.Properties; p != nil {
				scope = convert.ToValue(p.Scope)
				displayName = convert.ToValue(p.DisplayName)
				description = convert.ToValue(p.Description)
				isOrgDefault = p.IsOrganizationDefault
				lastModified = p.LastModifiedDateTime
				if p.LastModifiedBy != nil {
					lastModifiedBy, err = convert.JsonToDict(p.LastModifiedBy)
					if err != nil {
						return nil, err
					}
				}
				rules = p.Rules
			}
			mqlPolicy, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.roleManagementPolicy",
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(policy.ID),
					"name":                  llx.StringDataPtr(policy.Name),
					"scope":                 llx.StringData(scope),
					"displayName":           llx.StringData(displayName),
					"description":           llx.StringData(description),
					"isOrganizationDefault": llx.BoolDataPtr(isOrgDefault),
					"lastModifiedDateTime":  llx.TimeDataPtr(lastModified),
					"lastModifiedBy":        llx.DictData(lastModifiedBy),
				})
			if err != nil {
				return nil, err
			}
			mqlPolicy.(*mqlAzureSubscriptionAuthorizationServiceRoleManagementPolicy).cacheRules = rules
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleManagementPolicy) id() (string, error) {
	return a.Id.Data, nil
}

// rules maps the policy's heterogeneous rule set to the unified rule
// resource, discriminated by ruleType. Fields that don't apply to a given
// rule type are left null.
func (a *mqlAzureSubscriptionAuthorizationServiceRoleManagementPolicy) rules() ([]any, error) {
	res := []any{}
	for _, r := range a.cacheRules {
		if r == nil {
			continue
		}
		base := r.GetRoleManagementPolicyRule()
		if base == nil {
			continue
		}
		ruleId := convert.ToValue(base.ID)
		ruleType := ""
		if base.RuleType != nil {
			ruleType = string(*base.RuleType)
		}
		targetDict, err := convert.JsonToDict(base.Target)
		if err != nil {
			return nil, err
		}

		args := map[string]*llx.RawData{
			"__id":                       llx.StringData(fmt.Sprintf("%s/rules/%s", a.Id.Data, ruleId)),
			"id":                         llx.StringData(ruleId),
			"ruleType":                   llx.StringData(ruleType),
			"target":                     llx.DictData(targetDict),
			"enabledRules":               llx.ArrayData([]any{}, types.String),
			"isExpirationRequired":       llx.BoolDataPtr(nil),
			"maximumDuration":            llx.StringData(""),
			"approvalSetting":            llx.DictData(nil),
			"isEnabled":                  llx.BoolDataPtr(nil),
			"claimValue":                 llx.StringData(""),
			"notificationLevel":          llx.StringData(""),
			"notificationType":           llx.StringData(""),
			"recipientType":              llx.StringData(""),
			"notificationRecipients":     llx.ArrayData([]any{}, types.String),
			"isDefaultRecipientsEnabled": llx.BoolDataPtr(nil),
		}

		switch rule := r.(type) {
		case *authorization.RoleManagementPolicyEnablementRule:
			enabled := []any{}
			for _, er := range rule.EnabledRules {
				if er != nil {
					enabled = append(enabled, string(*er))
				}
			}
			args["enabledRules"] = llx.ArrayData(enabled, types.String)
		case *authorization.RoleManagementPolicyExpirationRule:
			args["isExpirationRequired"] = llx.BoolDataPtr(rule.IsExpirationRequired)
			args["maximumDuration"] = llx.StringDataPtr(rule.MaximumDuration)
		case *authorization.RoleManagementPolicyApprovalRule:
			if rule.Setting != nil {
				setting, err := convert.JsonToDict(rule.Setting)
				if err != nil {
					return nil, err
				}
				args["approvalSetting"] = llx.DictData(setting)
			}
		case *authorization.RoleManagementPolicyAuthenticationContextRule:
			args["isEnabled"] = llx.BoolDataPtr(rule.IsEnabled)
			args["claimValue"] = llx.StringDataPtr(rule.ClaimValue)
		case *authorization.RoleManagementPolicyNotificationRule:
			if rule.NotificationLevel != nil {
				args["notificationLevel"] = llx.StringData(string(*rule.NotificationLevel))
			}
			if rule.NotificationType != nil {
				args["notificationType"] = llx.StringData(string(*rule.NotificationType))
			}
			if rule.RecipientType != nil {
				args["recipientType"] = llx.StringData(string(*rule.RecipientType))
			}
			args["isDefaultRecipientsEnabled"] = llx.BoolDataPtr(rule.IsDefaultRecipientsEnabled)
			recipients := []any{}
			for _, nr := range rule.NotificationRecipients {
				if nr != nil {
					recipients = append(recipients, *nr)
				}
			}
			args["notificationRecipients"] = llx.ArrayData(recipients, types.String)
		}

		mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.roleManagementPolicy.rule", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

// expandedPrincipalAndRoleNames pulls the human-readable principal and role
// display names out of a PIM schedule's expanded properties, so audits don't
// have to resolve GUIDs.
func expandedPrincipalAndRoleNames(ep *authorization.ExpandedProperties) (principalDisplayName, roleDefinitionName string) {
	if ep == nil {
		return "", ""
	}
	if ep.Principal != nil {
		principalDisplayName = convert.ToValue(ep.Principal.DisplayName)
	}
	if ep.RoleDefinition != nil {
		roleDefinitionName = convert.ToValue(ep.RoleDefinition.DisplayName)
	}
	return principalDisplayName, roleDefinitionName
}

// resolveRoleDefinition resolves a role definition ID to its typed resource via
// the subscription's cached IAM roles, mirroring roleAssignment.role(). Returns
// null when the ID is empty.
func resolveRoleDefinition(runtime *plugin.Runtime, roleDefinitionId string, field *plugin.TValue[*mqlAzureSubscriptionAuthorizationServiceRoleDefinition]) (*mqlAzureSubscriptionAuthorizationServiceRoleDefinition, error) {
	if roleDefinitionId == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// Resolve against the connected subscription. A PIM eligibility can name a
	// role defined at a management group, whose ID has no "subscriptions"
	// segment to parse; the subscription-scoped listing already includes
	// MG-inherited definitions, so it covers that case.
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	r, err := CreateResource(runtime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	iam := r.(*mqlAzureSubscription).GetIam()
	if iam.Error != nil {
		return nil, iam.Error
	}
	if iam.Data == nil {
		return nil, errors.New("cannot resolve the authorization service for the subscription")
	}
	rolesVal := iam.Data.GetRoles()
	if rolesVal.Error != nil {
		return nil, rolesVal.Error
	}
	for i := range rolesVal.Data {
		role, ok := rolesVal.Data[i].(*mqlAzureSubscriptionAuthorizationServiceRoleDefinition)
		if !ok {
			continue
		}
		if strings.EqualFold(role.__id, roleDefinitionId) {
			return role, nil
		}
	}
	// The role definition isn't in the subscription's cached list (e.g. a custom
	// role scoped elsewhere, or eventual consistency). Don't fail the schedule
	// query over it — surface the schedule with a null role reference.
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

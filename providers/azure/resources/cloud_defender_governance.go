// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionCloudDefenderServiceGovernanceRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCloudDefenderServiceAssessmentGovernanceAssignment) id() (string, error) {
	return a.Id.Data, nil
}

// governanceRuleArgs flattens a Defender for Cloud governance rule into the
// fields of azure.subscription.cloudDefenderService.governanceRule. Every
// optional property is passed through as a pointer so an absent value reads
// as null rather than as false or zero.
func governanceRuleArgs(rule *armsecurity.GovernanceRule) (map[string]*llx.RawData, error) {
	var (
		displayName, description, remediationTimeframe *string
		ruleType, sourceResourceType                   *string
		ownerSourceType, ownerSource                   *string
		isDisabled, isGracePeriod, includeMemberScopes *bool
		disableOwnerEmail, disableManagerEmail         *bool
		rulePriority                                   *int32
		conditionSets                                  = []any{}
		excludedScopes                                 = []any{}
	)
	if p := rule.Properties; p != nil {
		displayName = p.DisplayName
		description = p.Description
		remediationTimeframe = p.RemediationTimeframe
		ruleType = stringEnumPtr(p.RuleType)
		sourceResourceType = stringEnumPtr(p.SourceResourceType)
		isDisabled = p.IsDisabled
		isGracePeriod = p.IsGracePeriod
		includeMemberScopes = p.IncludeMemberScopes
		rulePriority = p.RulePriority
		if o := p.OwnerSource; o != nil {
			ownerSourceType = stringEnumPtr(o.Type)
			ownerSource = o.Value
		}
		if n := p.GovernanceEmailNotification; n != nil {
			disableOwnerEmail = n.DisableOwnerEmailNotification
			disableManagerEmail = n.DisableManagerEmailNotification
		}
		for _, cs := range p.ConditionSets {
			if cs == nil {
				continue
			}
			d, err := convert.JsonToDict(cs)
			if err != nil {
				return nil, err
			}
			conditionSets = append(conditionSets, d)
		}
		for _, s := range p.ExcludedScopes {
			if s != nil {
				excludedScopes = append(excludedScopes, *s)
			}
		}
	}
	return map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(rule.ID),
		"name":                            llx.StringDataPtr(rule.Name),
		"displayName":                     llx.StringDataPtr(displayName),
		"description":                     llx.StringDataPtr(description),
		"isDisabled":                      llx.BoolDataPtr(isDisabled),
		"rulePriority":                    llx.IntDataPtr(rulePriority),
		"ruleType":                        llx.StringDataPtr(ruleType),
		"remediationTimeframe":            llx.StringDataPtr(remediationTimeframe),
		"isGracePeriod":                   llx.BoolDataPtr(isGracePeriod),
		"ownerSourceType":                 llx.StringDataPtr(ownerSourceType),
		"ownerSource":                     llx.StringDataPtr(ownerSource),
		"sourceResourceType":              llx.StringDataPtr(sourceResourceType),
		"conditionSets":                   llx.ArrayData(conditionSets, types.Dict),
		"excludedScopes":                  llx.ArrayData(excludedScopes, types.String),
		"includeMemberScopes":             llx.BoolDataPtr(includeMemberScopes),
		"disableOwnerEmailNotification":   llx.BoolDataPtr(disableOwnerEmail),
		"disableManagerEmailNotification": llx.BoolDataPtr(disableManagerEmail),
	}, nil
}

// governanceRules lists the Defender for Cloud governance rules defined at
// subscription scope.
func (a *mqlAzureSubscriptionCloudDefenderService) governanceRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	clientFactory, err := armsecurity.NewClientFactory(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := clientFactory.NewGovernanceRulesClient().NewListPager("subscriptions/"+subId, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Security/governanceRules/read")
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			args, err := governanceRuleArgs(rule)
			if err != nil {
				return nil, err
			}
			mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionCloudDefenderServiceGovernanceRule, args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

// governanceAssignmentArgs flattens a governance assignment into the fields of
// azure.subscription.cloudDefenderService.assessment.governanceAssignment.
func governanceAssignmentArgs(asg *armsecurity.GovernanceAssignment) map[string]*llx.RawData {
	var (
		owner, etaJustification                *string
		isGracePeriod                          *bool
		disableOwnerEmail, disableManagerEmail *bool
		args                                   = map[string]*llx.RawData{}
	)
	args["remediationDueDate"] = llx.NilData
	args["remediationEta"] = llx.NilData
	if p := asg.Properties; p != nil {
		owner = p.Owner
		isGracePeriod = p.IsGracePeriod
		args["remediationDueDate"] = llx.TimeDataPtr(p.RemediationDueDate)
		if eta := p.RemediationEta; eta != nil {
			args["remediationEta"] = llx.TimeDataPtr(eta.Eta)
			etaJustification = eta.Justification
		}
		if n := p.GovernanceEmailNotification; n != nil {
			disableOwnerEmail = n.DisableOwnerEmailNotification
			disableManagerEmail = n.DisableManagerEmailNotification
		}
	}
	args["id"] = llx.StringDataPtr(asg.ID)
	args["name"] = llx.StringDataPtr(asg.Name)
	args["owner"] = llx.StringDataPtr(owner)
	args["isGracePeriod"] = llx.BoolDataPtr(isGracePeriod)
	args["remediationEtaJustification"] = llx.StringDataPtr(etaJustification)
	args["disableOwnerEmailNotification"] = llx.BoolDataPtr(disableOwnerEmail)
	args["disableManagerEmailNotification"] = llx.BoolDataPtr(disableManagerEmail)
	return args
}

// noGovernanceAssignments reports whether ARM answered a governance assignment
// list with its "nothing here" response. For an assessment that has no
// assignment, ARM does not return an empty list: it returns 404 with
// ResourceNotFound and "No Governance Assignments found". The assessment
// itself was just listed, so the 404 is about the assignments and is an
// absence, not a failure. Any other 404 stays an error.
//
// ARM sends this one as {"Error":{"Code":"ResourceNotFound",...}}, which azcore
// does not read into ErrorCode, so the code comes from azureErrorCode's body
// fallback.
func noGovernanceAssignments(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusNotFound &&
		strings.EqualFold(azureErrorCode(respErr), "ResourceNotFound")
}

// governanceAssignments lists the owners and due dates assigned to one
// assessment. Azure lists assignments per assessment, so this costs one
// request per assessment and runs only when the field is queried.
func (a *mqlAzureSubscriptionCloudDefenderServiceAssessment) governanceAssignments() ([]any, error) {
	scope := a.ResourceId.Data
	assessmentName := a.Name.Data
	if scope == "" || assessmentName == "" {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	clientFactory, err := armsecurity.NewClientFactory(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := clientFactory.NewGovernanceAssignmentsClient().NewListPager(scope, assessmentName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if noGovernanceAssignments(err) {
				return res, nil
			}
			return nil, classifyAzureRefusal(err, "Microsoft.Security/assessments/governanceAssignments/read")
		}
		for _, asg := range page.Value {
			if asg == nil {
				continue
			}
			mqlAsg, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionCloudDefenderServiceAssessmentGovernanceAssignment,
				governanceAssignmentArgs(asg))
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAsg)
		}
	}
	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionPolicyRemediationInternal struct {
	subscriptionId     string
	policyAssignmentId string
}

type mqlAzureSubscriptionPolicyAttestationInternal struct {
	subscriptionId     string
	policyAssignmentId string
}

func (a *mqlAzureSubscriptionPolicyRemediation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionPolicyAttestation) id() (string, error) {
	return a.Id.Data, nil
}

// policyAssignmentFromList finds a policy assignment by its ARM id in the
// subscription's assignment list, which the runtime caches, so every reference
// shares one fetch. It returns nil when the assignment is not in the list, for
// example one deleted after the remediation or attestation was created.
func policyAssignmentFromList(runtime *plugin.Runtime, subscriptionId, assignmentId string) (*mqlAzureSubscriptionPolicyAssignment, error) {
	if assignmentId == "" {
		return nil, nil
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionPolicy, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(subscriptionId),
	})
	if err != nil {
		return nil, err
	}
	list := res.(*mqlAzureSubscriptionPolicy).GetAssignments()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		asg, ok := x.(*mqlAzureSubscriptionPolicyAssignment)
		if ok && strings.EqualFold(asg.AssignmentId.Data, assignmentId) {
			return asg, nil
		}
	}
	return nil, nil
}

// remediationArgs maps a policy remediation onto the fields of
// azure.subscription.policy.remediation. The deployment counts read as null
// when Azure reports no deployment summary, rather than as zero deployments.
func remediationArgs(r *armpolicyinsights.Remediation) map[string]*llx.RawData {
	var (
		policyDefinitionReferenceID, provisioningState, statusMessage, resourceDiscoveryMode *string
		total, successful, failed                                                            *int32
		args                                                                                 = map[string]*llx.RawData{}
	)
	args["createdOn"] = llx.NilData
	args["lastUpdatedOn"] = llx.NilData
	if p := r.Properties; p != nil {
		policyDefinitionReferenceID = p.PolicyDefinitionReferenceID
		provisioningState = p.ProvisioningState
		statusMessage = p.StatusMessage
		resourceDiscoveryMode = stringEnumPtr(p.ResourceDiscoveryMode)
		args["createdOn"] = llx.TimeDataPtr(p.CreatedOn)
		args["lastUpdatedOn"] = llx.TimeDataPtr(p.LastUpdatedOn)
		if d := p.DeploymentStatus; d != nil {
			total = d.TotalDeployments
			successful = d.SuccessfulDeployments
			failed = d.FailedDeployments
		}
	}
	args["id"] = llx.StringDataPtr(r.ID)
	args["name"] = llx.StringDataPtr(r.Name)
	args["policyDefinitionReferenceId"] = llx.StringDataPtr(policyDefinitionReferenceID)
	args["provisioningState"] = llx.StringDataPtr(provisioningState)
	args["statusMessage"] = llx.StringDataPtr(statusMessage)
	args["resourceDiscoveryMode"] = llx.StringDataPtr(resourceDiscoveryMode)
	args["totalDeployments"] = llx.IntDataPtr(total)
	args["successfulDeployments"] = llx.IntDataPtr(successful)
	args["failedDeployments"] = llx.IntDataPtr(failed)
	return args
}

func (a *mqlAzureSubscriptionPolicy) remediations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := armpolicyinsights.NewRemediationsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.PolicyInsights/remediations/read")
		}
		for _, r := range page.Value {
			if r == nil {
				continue
			}
			mqlRem, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionPolicyRemediation, remediationArgs(r))
			if err != nil {
				return nil, err
			}
			rem := mqlRem.(*mqlAzureSubscriptionPolicyRemediation)
			rem.subscriptionId = a.SubscriptionId.Data
			if r.Properties != nil {
				rem.policyAssignmentId = convert.ToValue(r.Properties.PolicyAssignmentID)
			}
			res = append(res, rem)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionPolicyRemediation) policyAssignment() (*mqlAzureSubscriptionPolicyAssignment, error) {
	asg, err := policyAssignmentFromList(a.MqlRuntime, a.subscriptionId, a.policyAssignmentId)
	if err != nil {
		return nil, err
	}
	if asg == nil {
		a.PolicyAssignment.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return asg, nil
}

// attestationEvidence converts attestation evidence into dicts, skipping nil
// entries.
func attestationEvidence(evidence []*armpolicyinsights.AttestationEvidence) []any {
	res := []any{}
	for _, e := range evidence {
		if e == nil {
			continue
		}
		res = append(res, map[string]any{
			"description": convert.ToValue(e.Description),
			"sourceUri":   convert.ToValue(e.SourceURI),
		})
	}
	return res
}

// attestationArgs maps a policy attestation onto the fields of
// azure.subscription.policy.attestation.
func attestationArgs(at *armpolicyinsights.Attestation) map[string]*llx.RawData {
	var (
		policyDefinitionReferenceID, complianceState, owner, comments, provisioningState *string
		evidence                                                                         = []any{}
		args                                                                             = map[string]*llx.RawData{}
	)
	args["expiresOn"] = llx.NilData
	args["assessmentDate"] = llx.NilData
	args["lastComplianceStateChangeAt"] = llx.NilData
	if p := at.Properties; p != nil {
		policyDefinitionReferenceID = p.PolicyDefinitionReferenceID
		complianceState = stringEnumPtr(p.ComplianceState)
		owner = p.Owner
		comments = p.Comments
		provisioningState = p.ProvisioningState
		evidence = attestationEvidence(p.Evidence)
		args["expiresOn"] = llx.TimeDataPtr(p.ExpiresOn)
		args["assessmentDate"] = llx.TimeDataPtr(p.AssessmentDate)
		args["lastComplianceStateChangeAt"] = llx.TimeDataPtr(p.LastComplianceStateChangeAt)
	}
	args["id"] = llx.StringDataPtr(at.ID)
	args["name"] = llx.StringDataPtr(at.Name)
	args["policyDefinitionReferenceId"] = llx.StringDataPtr(policyDefinitionReferenceID)
	args["complianceState"] = llx.StringDataPtr(complianceState)
	args["owner"] = llx.StringDataPtr(owner)
	args["comments"] = llx.StringDataPtr(comments)
	args["evidence"] = llx.ArrayData(evidence, types.Dict)
	args["provisioningState"] = llx.StringDataPtr(provisioningState)
	return args
}

func (a *mqlAzureSubscriptionPolicy) attestations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := armpolicyinsights.NewAttestationsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.PolicyInsights/attestations/read")
		}
		for _, at := range page.Value {
			if at == nil {
				continue
			}
			mqlAt, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionPolicyAttestation, attestationArgs(at))
			if err != nil {
				return nil, err
			}
			att := mqlAt.(*mqlAzureSubscriptionPolicyAttestation)
			att.subscriptionId = a.SubscriptionId.Data
			if at.Properties != nil {
				att.policyAssignmentId = convert.ToValue(at.Properties.PolicyAssignmentID)
			}
			res = append(res, att)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionPolicyAttestation) policyAssignment() (*mqlAzureSubscriptionPolicyAssignment, error) {
	asg, err := policyAssignmentFromList(a.MqlRuntime, a.subscriptionId, a.policyAssignmentId)
	if err != nil {
		return nil, err
	}
	if asg == nil {
		a.PolicyAssignment.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return asg, nil
}

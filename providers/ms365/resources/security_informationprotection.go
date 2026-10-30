// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-beta-sdk-go/models/security"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlMicrosoftSecurity) informationProtection() (*mqlMicrosoftSecurityInformationProtection, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)
	resource, err := CreateResource(r.MqlRuntime, ResourceMicrosoftSecurityInformationProtection, map[string]*llx.RawData{
		"__id": llx.StringData("microsoft.security.informationProtection/" + conn.TenantId()),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftSecurityInformationProtection), nil
}

func (r *mqlMicrosoftSecurityInformationProtection) sensitivityLabels() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := betaClient.Security().InformationProtection().SensitivityLabels().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}

	labels, err := iterate[security.SensitivityLabelable](ctx, resp, betaClient.GetAdapter(), security.CreateSensitivityLabelCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var res []any
	for _, label := range labels {
		if label == nil {
			continue
		}
		mqlResource, err := createSensitivityLabelResource(r.MqlRuntime, label)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

func createSensitivityLabelResource(runtime *plugin.Runtime, label security.SensitivityLabelable) (plugin.Resource, error) {
	var contentFormats []any
	if formats := label.GetContentFormats(); formats != nil {
		for _, format := range formats {
			contentFormats = append(contentFormats, format)
		}
	}

	var parentResource plugin.Resource
	if parent := label.GetParent(); parent != nil {
		var err error
		parentResource, err = createSensitivityLabelResource(runtime, parent)
		if err != nil {
			return nil, err
		}
	}

	mqlResource, err := CreateResource(runtime, ResourceMicrosoftSecurityInformationProtectionSensitivityLabel,
		map[string]*llx.RawData{
			"__id":           llx.StringDataPtr(label.GetId()),
			"id":             llx.StringDataPtr(label.GetId()),
			"name":           llx.StringDataPtr(label.GetName()),
			"description":    llx.StringDataPtr(label.GetDescription()),
			"toolTip":        llx.StringDataPtr(label.GetTooltip()),
			"color":          llx.StringDataPtr(label.GetColor()),
			"contentFormats": llx.ArrayData(contentFormats, types.String),
			"isAppliable":    llx.BoolDataPtr(label.GetIsAppliable()),
			"hasProtection":  llx.BoolDataPtr(label.GetHasProtection()),
			"isActive":       llx.BoolDataPtr(label.GetIsActive()),
			"sensitivity":    llx.IntDataPtr(label.GetSensitivity()),
			"parent":         llx.ResourceData(parentResource, ResourceMicrosoftSecurityInformationProtectionSensitivityLabel),
		})
	if err != nil {
		return nil, err
	}

	return mqlResource, nil
}

func (r *mqlMicrosoftSecurityInformationProtectionSensitivityLabel) id() (string, error) {
	return r.Id.Data, nil
}

// labelPolicies reports the sensitivity label policies that publish labels to
// users.
//
// Unlike sensitivityLabels this does not come from Graph: Purview exposes no
// read API for label policies, so the data is the Get-LabelPolicy output the
// Security & Compliance report already collects. The report is memoized on
// ms365.exchangeonline.securityAndCompliance, so querying this alongside the
// DLP resources costs one collection rather than two.
func (r *mqlMicrosoftSecurityInformationProtection) labelPolicies() ([]any, error) {
	resource, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.securityAndCompliance", nil)
	if err != nil {
		return nil, err
	}

	report, err := resource.(*mqlMs365ExchangeonlineSecurityAndCompliance).getSecurityAndComplianceReport()
	if err != nil {
		return nil, err
	}
	// a cmdlet that did not run leaves the section null, and reporting that as
	// an empty list would answer "no label policy publishes anything" with data
	// that was never collected. Returning (nil, nil) is not enough: without
	// StateIsNull the field still renders as [].
	if report == nil || report.LabelPolicy == nil {
		r.LabelPolicies.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convertLabelPolicies(r.MqlRuntime, report.LabelPolicy)
}

func convertLabelPolicies(runtime *plugin.Runtime, raw []any) ([]any, error) {
	result := []any{}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		guid := dlpString(m, "Guid")
		id := guid
		if id == "" {
			id = dlpString(m, "Name")
		}

		mql, err := CreateResource(runtime, ResourceMicrosoftSecurityInformationProtectionLabelPolicy,
			labelPolicyFields(m, guid, id))
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// labelPolicyFields maps one Get-LabelPolicy row onto the resource's fields.
func labelPolicyFields(m map[string]any, guid string, id string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData("labelPolicy-" + id),
		"name":               llx.StringData(dlpString(m, "Name")),
		"guid":               llx.StringData(guid),
		"enabled":            llx.BoolDataPtr(dlpBoolPtr(m, "Enabled")),
		"mode":               llx.StringData(dlpString(m, "Mode")),
		"labels":             llx.ArrayData(dlpStringSlice(m, "Labels"), types.String),
		"workload":           llx.StringData(dlpWorkload(m)),
		"distributionStatus": llx.StringData(dlpString(m, "DistributionStatus")),
		"comment":            llx.StringData(dlpString(m, "Comment")),
		"whenCreated":        llx.TimeDataPtr(dlpTime(m, "WhenCreated")),
		"whenChanged":        llx.TimeDataPtr(dlpTime(m, "WhenChanged")),
	}
}

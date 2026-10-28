// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isSecurityHubCentralConfigUnavailable reports whether Security Hub refused a
// central configuration API because central configuration does not apply to
// this account or region, rather than because IAM denied the call.
//
// Security Hub answers both with AccessDeniedException, so the code alone
// cannot separate them. Outside the delegated administrator's home region, or
// in any account that is not the delegated administrator, the message reads
// "Must be a Security Hub delegated administrator with Central Configuration
// enabled". An IAM denial names the missing action instead. A region where
// Security Hub is not enabled answers InvalidAccessException.
func isSecurityHubCentralConfigUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var invalidAccess *types.InvalidAccessException
	if errors.As(err, &invalidAccess) {
		return true
	}
	var ae smithy.APIError
	if !errors.As(err, &ae) || ae.ErrorCode() != "AccessDeniedException" {
		return false
	}
	msg := strings.ToLower(ae.ErrorMessage())
	return strings.Contains(msg, "delegated administrator") ||
		strings.Contains(msg, "central configuration")
}

func (a *mqlAwsSecurityhub) configurationPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	tally := &orgScopeTally{}
	items, err := perRegion(conn, "securityhub", func(ctx context.Context, region string) ([]any, error) {
		res, err := a.listConfigurationPolicies(ctx, conn, region)
		if err == nil {
			tally.answer()
			return res, nil
		}
		if isSecurityHubCentralConfigUnavailable(err) {
			log.Debug().Str("region", region).Err(err).Msg("security hub central configuration does not apply here")
			tally.refuse(err)
			return []any{}, nil
		}
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	return tally.result(items, plugin.StructuredErrors())
}

func (a *mqlAwsSecurityhub) listConfigurationPolicies(ctx context.Context, conn *connection.AwsConnection, region string) ([]any, error) {
	svc := conn.Securityhub(region)
	res := []any{}
	paginator := securityhub.NewListConfigurationPoliciesPaginator(svc, &securityhub.ListConfigurationPoliciesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.ConfigurationPolicySummaries {
			mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsSecurityhubConfigurationPolicy,
				map[string]*llx.RawData{
					"arn":            llx.StringDataPtr(p.Arn),
					"id":             llx.StringDataPtr(p.Id),
					"name":           llx.StringDataPtr(p.Name),
					"description":    llx.StringDataPtr(p.Description),
					"region":         llx.StringData(region),
					"serviceEnabled": llx.BoolDataPtr(p.ServiceEnabled),
					"updatedAt":      llx.TimeDataPtr(p.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

// securityHubPolicyDetail is the decoded body of a configuration policy.
// enabledControls and disabledControls are nil when the policy does not use
// that list; a policy sets one or the other.
type securityHubPolicyDetail struct {
	createdAt         *time.Time
	enabledStandards  []any
	enabledControls   []any
	disabledControls  []any
	controlParameters map[string]any
}

func decodeSecurityHubPolicy(out *securityhub.GetConfigurationPolicyOutput) *securityHubPolicyDetail {
	d := &securityHubPolicyDetail{
		createdAt:         out.CreatedAt,
		enabledStandards:  []any{},
		controlParameters: map[string]any{},
	}
	member, ok := out.ConfigurationPolicy.(*types.PolicyMemberSecurityHub)
	if !ok {
		return d
	}
	d.enabledStandards = toAnySlice(member.Value.EnabledStandardIdentifiers)
	controls := member.Value.SecurityControlsConfiguration
	if controls == nil {
		return d
	}
	if controls.EnabledSecurityControlIdentifiers != nil {
		d.enabledControls = toAnySlice(controls.EnabledSecurityControlIdentifiers)
	}
	if controls.DisabledSecurityControlIdentifiers != nil {
		d.disabledControls = toAnySlice(controls.DisabledSecurityControlIdentifiers)
	}
	for _, cp := range controls.SecurityControlCustomParameters {
		if cp.SecurityControlId == nil {
			continue
		}
		params := make(map[string]any, len(cp.Parameters))
		for name, cfg := range cp.Parameters {
			params[name] = map[string]any{
				"valueType": string(cfg.ValueType),
				"value":     securityHubParameterValue(cfg.Value),
			}
		}
		d.controlParameters[*cp.SecurityControlId] = params
	}
	return d
}

// securityHubParameterValue unwraps a control parameter's union value into a
// plain value. A default-valued parameter carries no value, which is nil.
func securityHubParameterValue(v types.ParameterValue) any {
	switch p := v.(type) {
	case *types.ParameterValueMemberBoolean:
		return p.Value
	case *types.ParameterValueMemberDouble:
		return p.Value
	case *types.ParameterValueMemberEnum:
		return p.Value
	case *types.ParameterValueMemberEnumList:
		return toAnySlice(p.Value)
	case *types.ParameterValueMemberInteger:
		return int64(p.Value)
	case *types.ParameterValueMemberIntegerList:
		res := make([]any, len(p.Value))
		for i, n := range p.Value {
			res[i] = int64(n)
		}
		return res
	case *types.ParameterValueMemberString:
		return p.Value
	case *types.ParameterValueMemberStringList:
		return toAnySlice(p.Value)
	}
	return nil
}

type mqlAwsSecurityhubConfigurationPolicyInternal struct {
	detailLock    sync.Mutex
	detailFetched bool
	detail        *securityHubPolicyDetail
	detailErr     error
}

func (a *mqlAwsSecurityhubConfigurationPolicy) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) getDetail() (*securityHubPolicyDetail, error) {
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.detailFetched = true

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Securityhub(a.Region.Data)
	identifier := a.Arn.Data
	out, err := svc.GetConfigurationPolicy(context.Background(), &securityhub.GetConfigurationPolicyInput{
		Identifier: &identifier,
	})
	if err != nil {
		if Is400AccessDeniedError(err) && !isSecurityHubCentralConfigUnavailable(err) {
			a.detailErr = llx.Forbidden(err, llx.WithPermissions("securityhub:GetConfigurationPolicy"))
		} else {
			a.detailErr = err
		}
		return nil, a.detailErr
	}
	a.detail = decodeSecurityHubPolicy(out)
	return a.detail, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) enabledStandardIdentifiers() ([]any, error) {
	d, err := a.getDetail()
	if err != nil {
		return nil, err
	}
	return d.enabledStandards, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) enabledControlIdentifiers() ([]any, error) {
	d, err := a.getDetail()
	if err != nil {
		return nil, err
	}
	if d.enabledControls == nil {
		a.EnabledControlIdentifiers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.enabledControls, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) disabledControlIdentifiers() ([]any, error) {
	d, err := a.getDetail()
	if err != nil {
		return nil, err
	}
	if d.disabledControls == nil {
		a.DisabledControlIdentifiers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.disabledControls, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) controlParameters() (any, error) {
	d, err := a.getDetail()
	if err != nil {
		return nil, err
	}
	return d.controlParameters, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) createdAt() (*time.Time, error) {
	d, err := a.getDetail()
	if err != nil {
		return nil, err
	}
	return d.createdAt, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicy) associations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Securityhub(a.Region.Data)
	ctx := context.Background()
	policyID := a.Id.Data

	res := []any{}
	paginator := securityhub.NewListConfigurationPolicyAssociationsPaginator(svc, &securityhub.ListConfigurationPolicyAssociationsInput{
		Filters: &types.AssociationFilters{ConfigurationPolicyId: &policyID},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) && !isSecurityHubCentralConfigUnavailable(err) {
				if !plugin.StructuredErrors() {
					return []any{}, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("securityhub:ListConfigurationPolicyAssociations"))
			}
			return nil, err
		}
		for _, assoc := range page.ConfigurationPolicyAssociationSummaries {
			targetID := ""
			if assoc.TargetId != nil {
				targetID = *assoc.TargetId
			}
			mqlAssoc, err := CreateResource(a.MqlRuntime, ResourceAwsSecurityhubConfigurationPolicyAssociation,
				map[string]*llx.RawData{
					"__id":                     llx.StringData(a.Arn.Data + "/association/" + targetID),
					"targetId":                 llx.StringData(targetID),
					"targetType":               llx.StringData(string(assoc.TargetType)),
					"associationType":          llx.StringData(string(assoc.AssociationType)),
					"associationStatus":        llx.StringData(string(assoc.AssociationStatus)),
					"associationStatusMessage": llx.StringDataPtr(assoc.AssociationStatusMessage),
					"updatedAt":                llx.TimeDataPtr(assoc.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAssoc)
		}
	}
	return res, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicyAssociation) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSecurityhubConfigurationPolicyAssociation) account() (*mqlAwsAccount, error) {
	if a.TargetType.Data != string(types.TargetTypeAccount) || a.TargetId.Data == "" {
		a.Account.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAccount, map[string]*llx.RawData{
		"id": llx.StringData(a.TargetId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAccount), nil
}

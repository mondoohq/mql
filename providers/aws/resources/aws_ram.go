// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsRam) id() (string, error) {
	return "aws.ram", nil
}

func (a *mqlAwsRam) resourceShares() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getResourceShares(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsRam) getResourceShares(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ram>getResourceShares>calling aws with region %s", region)

			svc := conn.Ram(region)
			ctx := context.Background()
			res := []any{}

			paginator := ram.NewGetResourceSharesPaginator(svc, &ram.GetResourceSharesInput{
				ResourceOwner: ramtypes.ResourceOwnerSelf,
			})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("RAM is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, share := range page.ResourceShares {
					tags := make(map[string]any)
					for _, tag := range share.Tags {
						tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
					}

					mqlShare, err := CreateResource(a.MqlRuntime, "aws.ram.resourceShare",
						map[string]*llx.RawData{
							"__id":                    llx.StringDataPtr(share.ResourceShareArn),
							"arn":                     llx.StringDataPtr(share.ResourceShareArn),
							"name":                    llx.StringDataPtr(share.Name),
							"region":                  llx.StringData(region),
							"status":                  llx.StringData(string(share.Status)),
							"owningAccountId":         llx.StringDataPtr(share.OwningAccountId),
							"allowExternalPrincipals": llx.BoolData(convert.ToValue(share.AllowExternalPrincipals)),
							"createdAt":               llx.TimeDataPtr(share.CreationTime),
							"tags":                    llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlShare)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRamResourceShare) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRamResourceShare) principals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ram(region)
	ctx := context.Background()

	arn := a.Arn.Data
	res := []any{}
	paginator := ram.NewListPrincipalsPaginator(svc, &ram.ListPrincipalsInput{
		ResourceOwner:     ramtypes.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, principal := range page.Principals {
			res = append(res, map[string]any{
				"id":               convert.ToValue(principal.Id),
				"resourceShareArn": convert.ToValue(principal.ResourceShareArn),
				// Must be a plain bool: llx's dict encoder accepts only
				// JSON-native values, so a *bool here failed the whole field with
				// "unsupported child type: *bool" for every share that has a
				// principal -- which is every share worth auditing.
				"external": convert.ToValue(principal.External),
			})
		}
	}
	return res, nil
}

func (a *mqlAwsRamResourceShare) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ram(region)
	ctx := context.Background()

	arn := a.Arn.Data
	res := []any{}
	paginator := ram.NewListResourcesPaginator(svc, &ram.ListResourcesInput{
		ResourceOwner:     ramtypes.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, resource := range page.Resources {
			res = append(res, map[string]any{
				"arn":              convert.ToValue(resource.Arn),
				"type":             convert.ToValue(resource.Type),
				"resourceShareArn": convert.ToValue(resource.ResourceShareArn),
				"status":           string(resource.Status),
			})
		}
	}
	return res, nil
}

func (a *mqlAwsRamResourceShare) permissions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ram(region)
	ctx := context.Background()

	shareArn := a.Arn.Data
	res := []any{}
	paginator := ram.NewListResourceSharePermissionsPaginator(svc, &ram.ListResourceSharePermissionsInput{
		ResourceShareArn: &shareArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, llx.Forbidden(err, llx.WithPermissions("ram:ListResourceSharePermissions"))
			}
			return nil, err
		}
		for _, p := range page.Permissions {
			mqlPerm, err := CreateResource(a.MqlRuntime, ResourceAwsRamPermission, ramPermissionArgs(shareArn, region, p))
			if err != nil {
				return nil, err
			}
			perm := mqlPerm.(*mqlAwsRamPermission)
			perm.cacheTemplateParams = p.PermissionTemplateParameters
			res = append(res, perm)
		}
	}
	return res, nil
}

// ramPermissionArgs builds the resource arguments for a permission attached to
// a share. Template parameter values belong to the association, not to the
// permission version, so the share ARN is part of the id: two shares using the
// same permission version can assign it different values.
func ramPermissionArgs(shareArn, region string, p ramtypes.ResourceSharePermissionSummary) map[string]*llx.RawData {
	arn := convert.ToValue(p.Arn)
	version := convert.ToValue(p.Version)
	return map[string]*llx.RawData{
		"__id":                  llx.StringData(shareArn + "/" + arn + "/" + version),
		"arn":                   llx.StringData(arn),
		"name":                  llx.StringDataPtr(p.Name),
		"version":               llx.StringData(version),
		"defaultVersion":        llx.BoolDataPtr(p.DefaultVersion),
		"isResourceTypeDefault": llx.BoolDataPtr(p.IsResourceTypeDefault),
		"permissionType":        llx.StringData(string(p.PermissionType)),
		"resourceOwner":         llx.StringData(string(p.ResourceOwner)),
		"featureSet":            llx.StringData(string(p.FeatureSet)),
		"status":                llx.StringDataPtr(p.Status),
		"resourceType":          llx.StringDataPtr(p.ResourceType),
		"templateParameters":    llx.ArrayData(ramTemplateParametersToDicts(p.PermissionTemplateParameters), types.Dict),
		"createdAt":             llx.TimeDataPtr(p.CreationTime),
		"updatedAt":             llx.TimeDataPtr(p.LastUpdatedTime),
		"region":                llx.StringData(region),
	}
}

func ramTemplateParametersToDicts(params []ramtypes.PermissionTemplateParameter) []any {
	res := make([]any, 0, len(params))
	for _, p := range params {
		values := make([]any, 0, len(p.Values))
		for _, v := range p.Values {
			values = append(values, v)
		}
		res = append(res, map[string]any{
			"name":        convert.ToValue(p.Name),
			"description": convert.ToValue(p.Description),
			"type":        string(p.Type),
			"values":      values,
		})
	}
	return res
}

// ramTemplateParameterInputs returns the share's template parameter values in
// the form GetPermission renders a policy with. GetPermission requires a value
// for every declared parameter, so when any parameter is unassigned it returns
// nil and the policy is read as the unrendered template.
func ramTemplateParameterInputs(params []ramtypes.PermissionTemplateParameter) []ramtypes.PermissionTemplateParameterInput {
	if len(params) == 0 {
		return nil
	}
	res := make([]ramtypes.PermissionTemplateParameterInput, 0, len(params))
	for _, p := range params {
		if p.Name == nil || len(p.Values) == 0 {
			return nil
		}
		res = append(res, ramtypes.PermissionTemplateParameterInput{Name: p.Name, Values: p.Values})
	}
	return res
}

// parseRamPermissionVersion converts the summary's string version into the
// number GetPermission takes. It returns nil for a version that does not
// parse, because a nil version makes GetPermission read the default version
// instead of the attached one.
func parseRamPermissionVersion(version string) *int32 {
	v, err := strconv.ParseInt(version, 10, 32)
	if err != nil || v < 1 {
		return nil
	}
	n := int32(v)
	return &n
}

type mqlAwsRamPermissionInternal struct {
	cacheTemplateParams []ramtypes.PermissionTemplateParameter
}

func (a *mqlAwsRamPermission) policy() (any, error) {
	version := parseRamPermissionVersion(a.Version.Data)
	if version == nil {
		return nil, fmt.Errorf("aws.ram.permission %q has no usable version %q", a.Arn.Data, a.Version.Data)
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ram(a.Region.Data)
	arn := a.Arn.Data
	resp, err := svc.GetPermission(context.Background(), &ram.GetPermissionInput{
		PermissionArn:                &arn,
		PermissionVersion:            version,
		PermissionTemplateParameters: ramTemplateParameterInputs(a.cacheTemplateParams),
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("ram:GetPermission"))
		}
		return nil, err
	}
	if resp.Permission == nil || resp.Permission.Permission == nil || *resp.Permission.Permission == "" {
		return nil, nil
	}
	return parseRamPermissionPolicy(*resp.Permission.Permission)
}

// parseRamPermissionPolicy decodes the permission's JSON policy document.
func parseRamPermissionPolicy(doc string) (any, error) {
	var res any
	if err := json.Unmarshal([]byte(doc), &res); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse RAM permission policy: %w", err))
	}
	return res, nil
}

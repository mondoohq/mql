// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	lakeformation_types "github.com/aws/aws-sdk-go-v2/service/lakeformation/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsLakeformation) id() (string, error) {
	return "aws.lakeformation", nil
}

func lakeformationPrincipalIdentifiers(principals []lakeformation_types.DataLakePrincipal) []any {
	res := []any{}
	for _, p := range principals {
		if p.DataLakePrincipalIdentifier != nil {
			res = append(res, *p.DataLakePrincipalIdentifier)
		}
	}
	return res
}

func lakeformationDefaultPermissions(perms []lakeformation_types.PrincipalPermissions) []any {
	res := []any{}
	for _, p := range perms {
		principal := ""
		if p.Principal != nil && p.Principal.DataLakePrincipalIdentifier != nil {
			principal = *p.Principal.DataLakePrincipalIdentifier
		}
		permissions := []any{}
		for _, perm := range p.Permissions {
			permissions = append(permissions, string(perm))
		}
		res = append(res, map[string]any{
			"principal":   principal,
			"permissions": permissions,
		})
	}
	return res
}

// ---- aws.lakeformation.dataLakeSettings ----

func (a *mqlAwsLakeformation) settings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDataLakeSettings(conn), 5)
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

func (a *mqlAwsLakeformation) getDataLakeSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lakeformation>getDataLakeSettings>calling aws with region %s", region)

			svc := conn.Lakeformation(region)
			ctx := context.Background()

			resp, err := svc.GetDataLakeSettings(ctx, &lakeformation.GetDataLakeSettingsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return []any{}, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("Lake Formation service not available in region")
					return []any{}, nil
				}
				return nil, err
			}
			if resp.DataLakeSettings == nil {
				return []any{}, nil
			}

			mqlSettings, err := newMqlAwsLakeformationDataLakeSettings(a.MqlRuntime, region, *resp.DataLakeSettings)
			if err != nil {
				return nil, err
			}
			return []any{mqlSettings}, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsLakeformationDataLakeSettings(runtime *plugin.Runtime, region string, settings lakeformation_types.DataLakeSettings) (*mqlAwsLakeformationDataLakeSettings, error) {
	resource, err := CreateResource(runtime, "aws.lakeformation.dataLakeSettings",
		map[string]*llx.RawData{
			"__id":                             llx.StringData(fmt.Sprintf("aws/lakeformation/datalakesettings/%s", region)),
			"region":                           llx.StringData(region),
			"admins":                           llx.ArrayData(lakeformationPrincipalIdentifiers(settings.DataLakeAdmins), types.String),
			"readOnlyAdmins":                   llx.ArrayData(lakeformationPrincipalIdentifiers(settings.ReadOnlyAdmins), types.String),
			"trustedResourceOwners":            llx.ArrayData(convert.SliceAnyToInterface(settings.TrustedResourceOwners), types.String),
			"allowExternalDataFiltering":       llx.BoolDataPtr(settings.AllowExternalDataFiltering),
			"allowFullTableExternalDataAccess": llx.BoolDataPtr(settings.AllowFullTableExternalDataAccess),
			"createDatabaseDefaultPermissions": llx.ArrayData(lakeformationDefaultPermissions(settings.CreateDatabaseDefaultPermissions), types.Dict),
			"createTableDefaultPermissions":    llx.ArrayData(lakeformationDefaultPermissions(settings.CreateTableDefaultPermissions), types.Dict),
			"authorizedSessionTagValueList":    llx.ArrayData(convert.SliceAnyToInterface(settings.AuthorizedSessionTagValueList), types.String),
			"parameters":                       llx.MapData(convert.MapToInterfaceMap(settings.Parameters), types.String),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsLakeformationDataLakeSettings), nil
}

func initAwsLakeformationDataLakeSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["region"] == nil {
		return nil, nil, errors.New("region required to fetch aws lakeformation data lake settings")
	}

	obj, err := CreateResource(runtime, "aws.lakeformation", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	lf := obj.(*mqlAwsLakeformation)
	settings := lf.GetSettings()
	if settings != nil && settings.Error == nil {
		regionVal, _ := args["region"].Value.(string)
		for _, raw := range settings.Data {
			s := raw.(*mqlAwsLakeformationDataLakeSettings)
			if s.Region.Data == regionVal {
				return args, s, nil
			}
		}
	}

	return nil, nil, errors.New("aws lakeformation data lake settings not found")
}

// lakeformationPermissionId derives a stable cache key for a permission grant.
// ListPermissions returns no identifier and does not guarantee ordering, so the
// key is hashed from the grant's defining fields (principal, resource, and the
// two permission sets) to stay stable across calls.
func lakeformationPermissionId(region, principal string, perm lakeformation_types.PrincipalResourcePermissions) string {
	resourceJSON, _ := json.Marshal(perm.Resource)
	permStrings := make([]string, 0, len(perm.Permissions))
	for _, p := range perm.Permissions {
		permStrings = append(permStrings, string(p))
	}
	grantStrings := make([]string, 0, len(perm.PermissionsWithGrantOption))
	for _, p := range perm.PermissionsWithGrantOption {
		grantStrings = append(grantStrings, string(p))
	}
	raw := strings.Join([]string{
		region, principal, string(resourceJSON),
		strings.Join(permStrings, ","), strings.Join(grantStrings, ","),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("aws/lakeformation/permission/%x", sum)
}

// ---- aws.lakeformation.permission ----

func (a *mqlAwsLakeformation) permissions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPermissions(conn), 5)
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

func (a *mqlAwsLakeformation) getPermissions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lakeformation>getPermissions>calling aws with region %s", region)

			svc := conn.Lakeformation(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListPermissions(ctx, &lakeformation.ListPermissionsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("Lake Formation service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, perm := range page.PrincipalResourcePermissions {
					mqlPerm, err := newMqlAwsLakeformationPermission(a.MqlRuntime, region, perm)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPerm)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsLakeformationPermission(runtime *plugin.Runtime, region string, perm lakeformation_types.PrincipalResourcePermissions) (*mqlAwsLakeformationPermission, error) {
	principal := ""
	if perm.Principal != nil && perm.Principal.DataLakePrincipalIdentifier != nil {
		principal = *perm.Principal.DataLakePrincipalIdentifier
	}

	resourceDict, err := convert.JsonToDict(perm.Resource)
	if err != nil {
		return nil, err
	}

	permissions := []any{}
	for _, p := range perm.Permissions {
		permissions = append(permissions, string(p))
	}
	withGrant := []any{}
	for _, p := range perm.PermissionsWithGrantOption {
		withGrant = append(withGrant, string(p))
	}

	var lastUpdated *llx.RawData
	if perm.LastUpdated != nil {
		lastUpdated = llx.TimeData(*perm.LastUpdated)
	} else {
		lastUpdated = llx.NilData
	}

	resource, err := CreateResource(runtime, "aws.lakeformation.permission",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(lakeformationPermissionId(region, principal, perm)),
			"region":                     llx.StringData(region),
			"principal":                  llx.StringData(principal),
			"resource":                   llx.DictData(resourceDict),
			"permissions":                llx.ArrayData(permissions, types.String),
			"permissionsWithGrantOption": llx.ArrayData(withGrant, types.String),
			"lastUpdated":                lastUpdated,
			"lastUpdatedBy":              llx.StringData(convert.ToValue(perm.LastUpdatedBy)),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsLakeformationPermission), nil
}

// ---- aws.lakeformation.resource ----

func (a *mqlAwsLakeformation) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getResources(conn), 5)
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

func (a *mqlAwsLakeformation) getResources(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lakeformation>getResources>calling aws with region %s", region)

			svc := conn.Lakeformation(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.ListResources(ctx, &lakeformation.ListResourcesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("Lake Formation service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, resourceInfo := range page.ResourceInfoList {
					// The ARN is the resource's natural key and its only stable
					// identity; a registered location without one cannot be
					// modeled or looked up, so skip it rather than collide every
					// such row on an empty cache key.
					if resourceInfo.ResourceArn == nil || *resourceInfo.ResourceArn == "" {
						log.Warn().Str("region", region).Msg("skipping Lake Formation resource with empty ARN")
						continue
					}
					mqlResource, err := newMqlAwsLakeformationResource(a.MqlRuntime, region, resourceInfo)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlResource)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsLakeformationResource(runtime *plugin.Runtime, region string, resourceInfo lakeformation_types.ResourceInfo) (*mqlAwsLakeformationResource, error) {
	var lastModified *llx.RawData
	if resourceInfo.LastModified != nil {
		lastModified = llx.TimeData(*resourceInfo.LastModified)
	} else {
		lastModified = llx.NilData
	}

	resource, err := CreateResource(runtime, "aws.lakeformation.resource",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(convert.ToValue(resourceInfo.ResourceArn)),
			"arn":                  llx.StringData(convert.ToValue(resourceInfo.ResourceArn)),
			"region":               llx.StringData(region),
			"withFederation":       llx.BoolDataPtr(resourceInfo.WithFederation),
			"hybridAccessEnabled":  llx.BoolDataPtr(resourceInfo.HybridAccessEnabled),
			"withPrivilegedAccess": llx.BoolDataPtr(resourceInfo.WithPrivilegedAccess),
			"lastModified":         lastModified,
		})
	if err != nil {
		return nil, err
	}

	mqlResource := resource.(*mqlAwsLakeformationResource)
	mqlResource.cacheRoleArn = resourceInfo.RoleArn
	return mqlResource, nil
}

type mqlAwsLakeformationResourceInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsLakeformationResource) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func initAwsLakeformationResource(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws lakeformation resource")
	}

	obj, err := CreateResource(runtime, "aws.lakeformation", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	lf := obj.(*mqlAwsLakeformation)
	resources := lf.GetResources()
	if resources != nil && resources.Error == nil {
		arnVal, _ := args["arn"].Value.(string)
		for _, raw := range resources.Data {
			r := raw.(*mqlAwsLakeformationResource)
			if r.Arn.Data == arnVal {
				return args, r, nil
			}
		}
	}

	return nil, nil, errors.New("aws lakeformation resource not found")
}

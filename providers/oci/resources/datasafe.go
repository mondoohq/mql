// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/datasafe"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciDataSafe) id() (string, error) {
	return "oci.dataSafe", nil
}

func (o *mqlOciDataSafeConfiguration) id() (string, error) {
	return "oci.dataSafe.configuration/" + o.Region.Data, nil
}

func (o *mqlOciDataSafeTargetDatabase) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafeSecurityAssessment) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafeUserAssessment) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafeSensitiveDataModel) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafeSensitiveType) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafeMaskingPolicy) id() (string, error) {
	return o.Id.Data, nil
}

func (o *mqlOciDataSafe) regionsList() ([]*mqlOciRegion, error) {
	list, err := ociRegionsFor(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	regions := make([]*mqlOciRegion, 0, len(list))
	for _, r := range list {
		region, ok := r.(*mqlOciRegion)
		if !ok {
			return nil, errors.New("invalid region type")
		}
		regions = append(regions, region)
	}
	return regions, nil
}

// dataSafeFromTenantSubtree forms the standard list request: compartment ==
// tenancy root, subtree == true, so every region call returns every Data Safe
// resource visible to the caller across every nested compartment.
func dataSafeFromTenantSubtree(tenancyId string) (string, *bool) {
	subtree := true
	return tenancyId, &subtree
}

func (o *mqlOciDataSafe) gatherResults(jobs []*jobpool.Job, err error) ([]any, error) {
	if err != nil {
		return nil, err
	}
	return ociRunRegionPool(jobs)
}

// ============================================================================
// configurations — per-region GetDataSafeConfiguration
// ============================================================================

func (o *mqlOciDataSafe) configurations() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			resp, err := svc.GetDataSafeConfiguration(context.Background(), datasafe.GetDataSafeConfigurationRequest{
				CompartmentId: common.String(conn.TenantID()),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not get Data Safe configuration")
				return jobpool.JobResult([]any{}), nil
			}

			cfg := resp.DataSafeConfiguration
			globalSettingsDict, err := convert.JsonToDict(cfg.GlobalSettings)
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not convert Data Safe global settings to dict")
			}

			args := map[string]*llx.RawData{
				"region":              llx.StringData(regionId),
				"isEnabled":           llx.BoolData(boolValue(cfg.IsEnabled)),
				"url":                 llx.StringData(stringValue(cfg.Url)),
				"lifecycleState":      llx.StringData(string(cfg.LifecycleState)),
				"natGatewayIpAddress": llx.StringData(stringValue(cfg.DataSafeNatGatewayIpAddress)),
				"globalSettings":      llx.DictData(globalSettingsDict),
				"freeformTags":        llx.MapData(strMapToAny(cfg.FreeformTags), types.String),
				"definedTags":         llx.MapData(definedTagsToAny(cfg.DefinedTags), types.Any),
			}
			if cfg.TimeEnabled != nil {
				args["enabledAt"] = llx.TimeData(cfg.TimeEnabled.Time)
			} else {
				args["enabledAt"] = llx.NilData
			}

			mqlCfg, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.configuration", stringValue(cfg.CompartmentId), args)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult([]any{mqlCfg}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// targetDatabases — per-region ListTargetDatabases
// ============================================================================

func (o *mqlOciDataSafe) targetDatabases() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.TargetDatabaseSummary, *string, error) {
				resp, err := svc.ListTargetDatabases(ctx, datasafe.ListTargetDatabasesRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe target databases")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				t := items[i]
				args := map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(t.Id),
					"region":                llx.StringData(regionId),
					"displayName":           llx.StringDataPtr(t.DisplayName),
					"description":           llx.StringData(stringValue(t.Description)),
					"infrastructureType":    llx.StringData(string(t.InfrastructureType)),
					"databaseType":          llx.StringData(string(t.DatabaseType)),
					"lifecycleState":        llx.StringData(string(t.LifecycleState)),
					"lifecycleDetails":      llx.StringData(stringValue(t.LifecycleDetails)),
					"associatedResourceIds": llx.ArrayData(stringsToAny(t.AssociatedResourceIds), types.String),
					"features":              stringsOrNull(t.Features),
					"created":               sdkTimeData(t.TimeCreated),
					"freeformTags":          llx.MapData(strMapToAny(t.FreeformTags), types.String),
					"definedTags":           llx.MapData(definedTagsToAny(t.DefinedTags), types.Any),
					"systemTags":            llx.MapData(definedTagsToAny(t.SystemTags), types.Dict),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.targetDatabase", stringValue(t.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// securityAssessments — per-region ListSecurityAssessments
// ============================================================================

func (o *mqlOciDataSafe) securityAssessments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.SecurityAssessmentSummary, *string, error) {
				resp, err := svc.ListSecurityAssessments(ctx, datasafe.ListSecurityAssessmentsRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe security assessments")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				a := items[i]
				args := map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(a.Id),
					"region":                 llx.StringData(regionId),
					"displayName":            llx.StringDataPtr(a.DisplayName),
					"lifecycleState":         llx.StringData(string(a.LifecycleState)),
					"type":                   llx.StringData(string(a.Type)),
					"targetIds":              llx.ArrayData(stringsToAny(a.TargetIds), types.String),
					"isBaseline":             llx.BoolData(boolValue(a.IsBaseline)),
					"isDeviatedFromBaseline": llx.BoolData(boolValue(a.IsDeviatedFromBaseline)),
					"created":                sdkTimeData(a.TimeCreated),
					"timeUpdated":            sdkTimeData(a.TimeUpdated),
					"freeformTags":           llx.MapData(strMapToAny(a.FreeformTags), types.String),
					"definedTags":            llx.MapData(definedTagsToAny(a.DefinedTags), types.Any),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.securityAssessment", stringValue(a.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// userAssessments — per-region ListUserAssessments
// ============================================================================

func (o *mqlOciDataSafe) userAssessments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.UserAssessmentSummary, *string, error) {
				resp, err := svc.ListUserAssessments(ctx, datasafe.ListUserAssessmentsRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe user assessments")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				a := items[i]
				args := map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(a.Id),
					"region":                 llx.StringData(regionId),
					"displayName":            llx.StringDataPtr(a.DisplayName),
					"lifecycleState":         llx.StringData(string(a.LifecycleState)),
					"type":                   llx.StringData(string(a.Type)),
					"targetIds":              llx.ArrayData(stringsToAny(a.TargetIds), types.String),
					"isBaseline":             llx.BoolData(boolValue(a.IsBaseline)),
					"isDeviatedFromBaseline": llx.BoolData(boolValue(a.IsDeviatedFromBaseline)),
					"created":                sdkTimeData(a.TimeCreated),
					"timeUpdated":            sdkTimeData(a.TimeUpdated),
					"freeformTags":           llx.MapData(strMapToAny(a.FreeformTags), types.String),
					"definedTags":            llx.MapData(definedTagsToAny(a.DefinedTags), types.Any),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.userAssessment", stringValue(a.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// sensitiveDataModels — per-region ListSensitiveDataModels
// ============================================================================

func (o *mqlOciDataSafe) sensitiveDataModels() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.SensitiveDataModelSummary, *string, error) {
				resp, err := svc.ListSensitiveDataModels(ctx, datasafe.ListSensitiveDataModelsRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe sensitive data models")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				m := items[i]
				args := map[string]*llx.RawData{
					"id":             llx.StringDataPtr(m.Id),
					"region":         llx.StringData(regionId),
					"displayName":    llx.StringDataPtr(m.DisplayName),
					"description":    llx.StringData(stringValue(m.Description)),
					"lifecycleState": llx.StringData(string(m.LifecycleState)),
					"targetId":       llx.StringDataPtr(m.TargetId),
					"appSuiteName":   llx.StringDataPtr(m.AppSuiteName),
					"created":        sdkTimeData(m.TimeCreated),
					"timeUpdated":    sdkTimeData(m.TimeUpdated),
					"freeformTags":   llx.MapData(strMapToAny(m.FreeformTags), types.String),
					"definedTags":    llx.MapData(definedTagsToAny(m.DefinedTags), types.Any),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.sensitiveDataModel", stringValue(m.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// sensitiveTypes — per-region ListSensitiveTypes
// ============================================================================

func (o *mqlOciDataSafe) sensitiveTypes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.SensitiveTypeSummary, *string, error) {
				resp, err := svc.ListSensitiveTypes(ctx, datasafe.ListSensitiveTypesRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe sensitive types")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				t := items[i]
				args := map[string]*llx.RawData{
					"id":             llx.StringDataPtr(t.Id),
					"region":         llx.StringData(regionId),
					"displayName":    llx.StringDataPtr(t.DisplayName),
					"shortName":      llx.StringData(stringValue(t.ShortName)),
					"lifecycleState": llx.StringData(string(t.LifecycleState)),
					"source":         llx.StringData(string(t.Source)),
					"entityType":     llx.StringData(string(t.EntityType)),
					"created":        sdkTimeData(t.TimeCreated),
					"timeUpdated":    sdkTimeData(t.TimeUpdated),
					"freeformTags":   llx.MapData(strMapToAny(t.FreeformTags), types.String),
					"definedTags":    llx.MapData(definedTagsToAny(t.DefinedTags), types.Any),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.sensitiveType", stringValue(t.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

// ============================================================================
// maskingPolicies — per-region ListMaskingPolicies
// ============================================================================

func (o *mqlOciDataSafe) maskingPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	regions, err := o.regionsList()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		regionId := region.Id.Data
		f := func() (jobpool.JobResult, error) {
			svc, err := conn.DataSafeClient(regionId)
			if err != nil {
				return nil, err
			}
			compartmentId, subtree := dataSafeFromTenantSubtree(conn.TenantID())
			items, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]datasafe.MaskingPolicySummary, *string, error) {
				resp, err := svc.ListMaskingPolicies(ctx, datasafe.ListMaskingPoliciesRequest{
					CompartmentId:          common.String(compartmentId),
					CompartmentIdInSubtree: subtree,
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				log.Debug().Err(err).Str("region", regionId).Msg("could not list Data Safe masking policies")
				return jobpool.JobResult([]any{}), nil
			}

			res := make([]any, 0, len(items))
			for i := range items {
				p := items[i]
				columnSourceDict, err := convert.JsonToDict(p.ColumnSource)
				if err != nil {
					log.Debug().Err(err).Str("region", regionId).Str("policy", stringValue(p.Id)).Msg("could not convert masking policy column source to dict")
				}
				args := map[string]*llx.RawData{
					"id":             llx.StringDataPtr(p.Id),
					"region":         llx.StringData(regionId),
					"displayName":    llx.StringDataPtr(p.DisplayName),
					"description":    llx.StringData(stringValue(p.Description)),
					"lifecycleState": llx.StringData(string(p.LifecycleState)),
					"columnSource":   llx.DictData(columnSourceDict),
					"created":        sdkTimeData(p.TimeCreated),
					"timeUpdated":    sdkTimeData(p.TimeUpdated),
					"freeformTags":   llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":    llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
				}
				mql, err := createOciResourceInCompartment(o.MqlRuntime, "oci.dataSafe.maskingPolicy", stringValue(p.CompartmentId), args)
				if err != nil {
					return nil, err
				}
				res = append(res, mql)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return o.gatherResults(tasks, nil)
}

type mqlOciDataSafeConfigurationInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeMaskingPolicyInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeSecurityAssessmentInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeSensitiveDataModelInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeSensitiveTypeInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeTargetDatabaseInternal struct {
	ociCompartmentRef
}

type mqlOciDataSafeUserAssessmentInternal struct {
	ociCompartmentRef
}

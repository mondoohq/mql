// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/proto"
)

type mqlGcpProjectDlpServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) dlp() (*mqlGcpProjectDlpService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_dlp)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectDlpService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_dlp).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectDlpService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectDlpService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.dlpService", g.ProjectId.Data), nil
}

// ---------------------------------------------------------------
// Inspect Templates
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceInspectTemplate) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) inspectTemplates() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInspectTemplates(ctx, &dlppb.ListInspectTemplatesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		tmpl, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP inspect templates")
				break
			}
			return nil, err
		}

		inspectConfig, err := protoToDict(tmpl.InspectConfig)
		if err != nil {
			return nil, err
		}

		mqlTmpl, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.inspectTemplate", map[string]*llx.RawData{
			"name":          llx.StringData(tmpl.Name),
			"displayName":   llx.StringData(tmpl.DisplayName),
			"description":   llx.StringData(tmpl.Description),
			"inspectConfig": llx.DictData(inspectConfig),
			"created":       llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
			"updated":       llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTmpl)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Deidentify Templates
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceDeidentifyTemplate) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) deidentifyTemplates() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDeidentifyTemplates(ctx, &dlppb.ListDeidentifyTemplatesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		tmpl, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP deidentify templates")
				break
			}
			return nil, err
		}

		deidentifyConfig, err := protoToDict(tmpl.DeidentifyConfig)
		if err != nil {
			return nil, err
		}

		mqlTmpl, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.deidentifyTemplate", map[string]*llx.RawData{
			"name":             llx.StringData(tmpl.Name),
			"displayName":      llx.StringData(tmpl.DisplayName),
			"description":      llx.StringData(tmpl.Description),
			"deidentifyConfig": llx.DictData(deidentifyConfig),
			"created":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
			"updated":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTmpl)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Job Triggers
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceJobTrigger) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) jobTriggers() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListJobTriggers(ctx, &dlppb.ListJobTriggersRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		jt, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP job triggers")
				break
			}
			return nil, err
		}

		inspectJob, err := protoToDict(jt.GetInspectJob())
		if err != nil {
			return nil, err
		}

		triggers := make([]any, 0, len(jt.Triggers))
		for _, t := range jt.Triggers {
			d, err := protoToDict(t)
			if err != nil {
				return nil, err
			}
			triggers = append(triggers, d)
		}

		errs := make([]any, 0, len(jt.Errors))
		for _, e := range jt.Errors {
			d, err := protoToDict(e)
			if err != nil {
				return nil, err
			}
			errs = append(errs, d)
		}

		mqlJt, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.jobTrigger", map[string]*llx.RawData{
			"name":        llx.StringData(jt.Name),
			"displayName": llx.StringData(jt.DisplayName),
			"description": llx.StringData(jt.Description),
			"status":      llx.StringData(jt.Status.String()),
			"inspectJob":  llx.DictData(inspectJob),
			"triggers":    llx.ArrayData(triggers, types.Dict),
			"errors":      llx.ArrayData(errs, types.Dict),
			"created":     llx.TimeDataPtr(timestampAsTimePtr(jt.CreateTime)),
			"updated":     llx.TimeDataPtr(timestampAsTimePtr(jt.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJt)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Stored Info Types
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceStoredInfoType) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) storedInfoTypes() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListStoredInfoTypes(ctx, &dlppb.ListStoredInfoTypesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		sit, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP stored info types")
				break
			}
			return nil, err
		}

		currentVersion, err := protoToDict(sit.CurrentVersion)
		if err != nil {
			return nil, err
		}

		pendingVersions := make([]any, 0, len(sit.PendingVersions))
		for _, pv := range sit.PendingVersions {
			d, err := protoToDict(pv)
			if err != nil {
				return nil, err
			}
			pendingVersions = append(pendingVersions, d)
		}

		mqlSit, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.storedInfoType", map[string]*llx.RawData{
			"name":                     llx.StringData(sit.Name),
			"currentVersion":           llx.DictData(currentVersion),
			"pendingVersions":          llx.ArrayData(pendingVersions, types.Dict),
			"currentVersionCreateTime": llx.TimeDataPtr(timestampAsTimePtr(sit.GetCurrentVersion().GetCreateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSit)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Helpers shared by new accessors
// ---------------------------------------------------------------

// dlpDataProfilesLocation is the location that data profile listings
// (project / table / column / file-store) aggregate to. The DLP API
// supports "global" for project-scope data profile listings.
const dlpDataProfilesLocation = "global"

// dlpRegionalListLocations is the set of locations the DLP API supports
// for resources that cannot live in "global" at project scope —
// DiscoveryConfig and Connection. We query the three multi-regions and
// skip per-location errors so a project that has resources in any of
// them still returns useful data.
//
// Limitation: DLP also supports ~40 single-region locations
// (us-central1, europe-west1, asia-southeast1, ...). DiscoveryConfigs
// and Connections pinned to a specific region (rather than the
// containing multi-region) are *not* returned here. The DLP API does
// not expose a `locations.list` for client SDKs, so iterating every
// known region would multiply the listing cost by ~40x for every
// query — an unacceptable trade-off when the vast majority of
// customers use the multi-regions. If single-region coverage is
// needed, expand this list or add a connection-level location
// configuration.
var dlpRegionalListLocations = []string{"us", "eu", "asia"}

// dlpFilterEscape escapes characters that would break a double-quoted
// DLP list-filter string. The DLP filter grammar treats `\"` as a
// literal double quote inside a quoted value, so escaping `"` is enough
// for the identifiers we interpolate (BigQuery project / dataset /
// table IDs).
func dlpFilterEscape(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func dlpProtoSliceToDict[T proto.Message](items []T) ([]any, error) {
	res := make([]any, 0, len(items))
	for _, it := range items {
		d, err := protoToDict(it)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

// ---------------------------------------------------------------
// DLP Jobs
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceDlpJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) dlpJobs() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDlpJobs(ctx, &dlppb.ListDlpJobsRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		job, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP jobs")
				break
			}
			return nil, err
		}

		var details any
		switch d := job.Details.(type) {
		case *dlppb.DlpJob_InspectDetails:
			details, _ = protoToDict(d.InspectDetails)
		case *dlppb.DlpJob_RiskDetails:
			details, _ = protoToDict(d.RiskDetails)
		}

		errs, err := dlpProtoSliceToDict(job.Errors)
		if err != nil {
			return nil, err
		}
		actionDetails, err := dlpProtoSliceToDict(job.ActionDetails)
		if err != nil {
			return nil, err
		}

		mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.dlpJob", map[string]*llx.RawData{
			"name":          llx.StringData(job.Name),
			"type":          llx.StringData(job.Type.String()),
			"state":         llx.StringData(job.State.String()),
			"jobTrigger":    llx.StringData(job.JobTriggerName),
			"details":       llx.DictData(details),
			"errors":        llx.ArrayData(errs, types.Dict),
			"actionDetails": llx.ArrayData(actionDetails, types.Dict),
			"created":       llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
			"started":       llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
			"ended":         llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
			"lastModified":  llx.TimeDataPtr(timestampAsTimePtr(job.LastModified)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJob)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Discovery Configs
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceDiscoveryConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) discoveryConfigs() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var res []any
	for _, loc := range dlpRegionalListLocations {
		it := client.ListDiscoveryConfigs(ctx, &dlppb.ListDiscoveryConfigsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, loc),
		})
		for {
			dc, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("location", loc).Msg("could not list DLP discovery configs")
					break
				}
				return nil, err
			}

			targets, err := dlpProtoSliceToDict(dc.Targets)
			if err != nil {
				return nil, err
			}
			errs, err := dlpProtoSliceToDict(dc.Errors)
			if err != nil {
				return nil, err
			}
			actions, err := dlpProtoSliceToDict(dc.Actions)
			if err != nil {
				return nil, err
			}
			orgConfig, _ := protoToDict(dc.OrgConfig)

			mqlDc, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.discoveryConfig", map[string]*llx.RawData{
				"name":             llx.StringData(dc.Name),
				"displayName":      llx.StringData(dc.DisplayName),
				"status":           llx.StringData(dc.Status.String()),
				"targets":          llx.ArrayData(targets, types.Dict),
				"errors":           llx.ArrayData(errs, types.Dict),
				"inspectTemplates": llx.ArrayData(stringsToAnySlice(dc.InspectTemplates), types.String),
				"actions":          llx.ArrayData(actions, types.Dict),
				"orgConfig":        llx.DictData(orgConfig),
				"lastRunTime":      llx.TimeDataPtr(timestampAsTimePtr(dc.LastRunTime)),
				"created":          llx.TimeDataPtr(timestampAsTimePtr(dc.CreateTime)),
				"updated":          llx.TimeDataPtr(timestampAsTimePtr(dc.UpdateTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDc)
		}
	}

	return res, nil
}

func stringsToAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// ---------------------------------------------------------------
// Connections
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceConnection) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) connections() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var res []any
	for _, loc := range dlpRegionalListLocations {
		it := client.ListConnections(ctx, &dlppb.ListConnectionsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, loc),
		})
		for {
			c, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("location", loc).Msg("could not list DLP connections")
					break
				}
				return nil, err
			}

			errs, err := dlpProtoSliceToDict(c.Errors)
			if err != nil {
				return nil, err
			}
			var properties any
			switch p := c.Properties.(type) {
			case *dlppb.Connection_CloudSql:
				d, _ := protoToDict(p.CloudSql)
				properties = map[string]any{"cloudSql": d}
			}

			mqlConn, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.connection", map[string]*llx.RawData{
				"name":       llx.StringData(c.Name),
				"state":      llx.StringData(c.State.String()),
				"errors":     llx.ArrayData(errs, types.Dict),
				"properties": llx.DictData(properties),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}

	return res, nil
}

// ---------------------------------------------------------------
// Project Data Profiles
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceProjectDataProfile) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) projectDataProfiles() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListProjectDataProfiles(ctx, &dlppb.ListProjectDataProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, dlpDataProfilesLocation),
	})

	var res []any
	for {
		p, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP project data profiles")
				break
			}
			return nil, err
		}

		sensitivity, _ := protoToDict(p.SensitivityScore)
		riskLevel, _ := protoToDict(p.DataRiskLevel)
		status, _ := protoToDict(p.ProfileStatus)

		scores, err := newMqlDlpProfileScores(g.MqlRuntime, p.Name, p.SensitivityScore, p.DataRiskLevel)
		if err != nil {
			return nil, err
		}
		lastProfileStatus, err := newMqlDlpProfileStatus(g.MqlRuntime, p.Name, p.ProfileStatus)
		if err != nil {
			return nil, err
		}

		projectProfileArgs := map[string]*llx.RawData{
			"name":                      llx.StringData(p.Name),
			"projectId":                 llx.StringData(p.ProjectId),
			"sensitivityScore":          llx.DictData(sensitivity),
			"dataRiskLevel":             llx.DictData(riskLevel),
			"profileStatus":             llx.DictData(status),
			"lastProfileStatus":         lastProfileStatus,
			"tableDataProfileCount":     llx.IntData(p.TableDataProfileCount),
			"fileStoreDataProfileCount": llx.IntData(p.FileStoreDataProfileCount),
			"profileLastGenerated":      llx.TimeDataPtr(timestampAsTimePtr(p.ProfileLastGenerated)),
		}
		maps.Copy(projectProfileArgs, scores)

		mqlP, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.projectDataProfile", projectProfileArgs)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlP)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Table Data Profiles
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceTableDataProfile) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) tableDataProfiles() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTableDataProfiles(ctx, &dlppb.ListTableDataProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, dlpDataProfilesLocation),
	})

	var res []any
	for {
		t, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP table data profiles")
				break
			}
			return nil, err
		}

		mqlT, err := newMqlTableDataProfile(g.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlT)
	}

	return res, nil
}

func newMqlTableDataProfile(runtime *plugin.Runtime, t *dlppb.TableDataProfile) (plugin.Resource, error) {
	sensitivity, _ := protoToDict(t.SensitivityScore)
	riskLevel, _ := protoToDict(t.DataRiskLevel)
	status, _ := protoToDict(t.ProfileStatus)
	predicted, err := dlpProtoSliceToDict(t.PredictedInfoTypes)
	if err != nil {
		return nil, err
	}
	other, err := dlpProtoSliceToDict(t.OtherInfoTypes)
	if err != nil {
		return nil, err
	}
	scores, err := newMqlDlpProfileScores(runtime, t.Name, t.SensitivityScore, t.DataRiskLevel)
	if err != nil {
		return nil, err
	}
	lastProfileStatus, err := newMqlDlpProfileStatus(runtime, t.Name, t.ProfileStatus)
	if err != nil {
		return nil, err
	}

	tableArgs := map[string]*llx.RawData{
		"name":                 llx.StringData(t.Name),
		"datasetProjectId":     llx.StringData(t.DatasetProjectId),
		"datasetLocation":      llx.StringData(t.DatasetLocation),
		"datasetId":            llx.StringData(t.DatasetId),
		"tableId":              llx.StringData(t.TableId),
		"fullResource":         llx.StringData(t.FullResource),
		"state":                llx.StringData(t.State.String()),
		"sensitivityScore":     llx.DictData(sensitivity),
		"dataRiskLevel":        llx.DictData(riskLevel),
		"profileStatus":        llx.DictData(status),
		"lastProfileStatus":    lastProfileStatus,
		"predictedInfoTypes":   llx.ArrayData(predicted, types.Dict),
		"otherInfoTypes":       llx.ArrayData(other, types.Dict),
		"encryptionStatus":     llx.StringData(t.EncryptionStatus.String()),
		"resourceVisibility":   llx.StringData(t.ResourceVisibility.String()),
		"scannedColumnCount":   llx.IntData(t.ScannedColumnCount),
		"failedColumnCount":    llx.IntData(t.FailedColumnCount),
		"tableSizeBytes":       llx.IntData(t.TableSizeBytes),
		"rowCount":             llx.IntData(t.RowCount),
		"resourceLabels":       llx.MapData(strMapToAny(t.ResourceLabels), types.String),
		"profileLastGenerated": llx.TimeDataPtr(timestampAsTimePtr(t.ProfileLastGenerated)),
		"lastModifiedTime":     llx.TimeDataPtr(timestampAsTimePtr(t.LastModifiedTime)),
		"expirationTime":       llx.TimeDataPtr(timestampAsTimePtr(t.ExpirationTime)),
		"created":              llx.TimeDataPtr(timestampAsTimePtr(t.CreateTime)),
	}
	maps.Copy(tableArgs, scores)

	return CreateResource(runtime, "gcp.project.dlpService.tableDataProfile", tableArgs)
}

func strMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (g *mqlGcpProjectDlpServiceTableDataProfile) bigqueryTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	datasetId := g.DatasetId.Data
	tableId := g.TableId.Data
	projectId := g.DatasetProjectId.Data
	if datasetId == "" || tableId == "" || projectId == "" {
		g.BigqueryTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// Key on the same (id, projectId, datasetId) the bigquery table resource is
	// created with, so the computed __id
	// (gcp.project.bigqueryService.table/{project}/{dataset}/{table}) matches a
	// table already resolved via bigqueryService.datasets.tables. Passing a
	// dotted "proj.dataset.table" id with no project/dataset never matched and
	// left a husk.
	mqlTbl, err := NewResource(g.MqlRuntime, "gcp.project.bigqueryService.table", map[string]*llx.RawData{
		"id":        llx.StringData(tableId),
		"projectId": llx.StringData(projectId),
		"datasetId": llx.StringData(datasetId),
	})
	if err != nil {
		return nil, err
	}
	return mqlTbl.(*mqlGcpProjectBigqueryServiceTable), nil
}

// ---------------------------------------------------------------
// Column Data Profiles
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceColumnDataProfile) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) columnDataProfiles() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// ListColumnDataProfiles requires a filter with project_id, dataset_id,
	// and table_id; there is no project-wide list. Iterate the project's
	// table data profiles first and gather column profiles per-table.
	// This is O(tables) API calls — slow on projects with many profiled
	// tables — but it is the only path the API exposes for this collection.
	parent := fmt.Sprintf("projects/%s/locations/%s", projectId, dlpDataProfilesLocation)
	tableIt := client.ListTableDataProfiles(ctx, &dlppb.ListTableDataProfilesRequest{Parent: parent})

	var res []any
	for {
		t, err := tableIt.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP table data profiles for column profile enumeration")
				break
			}
			return nil, err
		}

		// Escape embedded double quotes so a BigQuery identifier containing
		// a literal `"` (rare but legal in some characters) can't break out
		// of the filter expression.
		filter := fmt.Sprintf(`table_id="%s" AND dataset_id="%s" AND project_id="%s"`,
			dlpFilterEscape(t.TableId), dlpFilterEscape(t.DatasetId), dlpFilterEscape(t.DatasetProjectId))
		colIt := client.ListColumnDataProfiles(ctx, &dlppb.ListColumnDataProfilesRequest{
			Parent: parent,
			Filter: filter,
		})
		for {
			c, err := colIt.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("table", t.TableId).Msg("could not list DLP column data profiles")
					break
				}
				return nil, err
			}

			sensitivity, _ := protoToDict(c.SensitivityScore)
			riskLevel, _ := protoToDict(c.DataRiskLevel)
			columnInfoType, _ := protoToDict(c.ColumnInfoType)
			otherMatches, err := dlpProtoSliceToDict(c.OtherMatches)
			if err != nil {
				return nil, err
			}

			scores, err := newMqlDlpProfileScores(g.MqlRuntime, c.Name, c.SensitivityScore, c.DataRiskLevel)
			if err != nil {
				return nil, err
			}

			columnArgs := map[string]*llx.RawData{
				"name":                 llx.StringData(c.Name),
				"column":               llx.StringData(c.Column),
				"datasetId":            llx.StringData(c.DatasetId),
				"tableId":              llx.StringData(c.TableId),
				"tableFullResource":    llx.StringData(c.TableFullResource),
				"state":                llx.StringData(c.State.String()),
				"sensitivityScore":     llx.DictData(sensitivity),
				"dataRiskLevel":        llx.DictData(riskLevel),
				"columnInfoType":       llx.DictData(columnInfoType),
				"otherMatches":         llx.ArrayData(otherMatches, types.Dict),
				"freeTextScore":        llx.FloatData(c.FreeTextScore),
				"columnType":           llx.StringData(c.ColumnType.String()),
				"policyState":          llx.StringData(c.PolicyState.String()),
				"profileLastGenerated": llx.TimeDataPtr(timestampAsTimePtr(c.ProfileLastGenerated)),
			}
			maps.Copy(columnArgs, scores)

			mqlC, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.columnDataProfile", columnArgs)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlC)
		}
	}

	return res, nil
}

// ---------------------------------------------------------------
// File Store Data Profiles
// ---------------------------------------------------------------

func (g *mqlGcpProjectDlpServiceFileStoreDataProfile) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDlpService) fileStoreDataProfiles() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListFileStoreDataProfiles(ctx, &dlppb.ListFileStoreDataProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, dlpDataProfilesLocation),
	})

	var res []any
	for {
		f, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list DLP file-store data profiles")
				break
			}
			return nil, err
		}

		mqlF, err := newMqlFileStoreDataProfile(g.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlF)
	}

	return res, nil
}

func newMqlFileStoreDataProfile(runtime *plugin.Runtime, f *dlppb.FileStoreDataProfile) (plugin.Resource, error) {
	sensitivity, _ := protoToDict(f.SensitivityScore)
	riskLevel, _ := protoToDict(f.DataRiskLevel)
	status, _ := protoToDict(f.ProfileStatus)
	dataSourceType := ""
	if f.DataSourceType != nil {
		dataSourceType = f.DataSourceType.DataSource
	}
	clusterSummaries, err := dlpProtoSliceToDict(f.FileClusterSummaries)
	if err != nil {
		return nil, err
	}
	infoTypeSummaries, err := dlpProtoSliceToDict(f.FileStoreInfoTypeSummaries)
	if err != nil {
		return nil, err
	}
	resourceAttributes := map[string]any{}
	for k, v := range f.ResourceAttributes {
		d, err := protoToDict(v)
		if err != nil {
			return nil, err
		}
		resourceAttributes[k] = d
	}

	scores, err := newMqlDlpProfileScores(runtime, f.Name, f.SensitivityScore, f.DataRiskLevel)
	if err != nil {
		return nil, err
	}
	lastProfileStatus, err := newMqlDlpProfileStatus(runtime, f.Name, f.ProfileStatus)
	if err != nil {
		return nil, err
	}

	fileStoreArgs := map[string]*llx.RawData{
		"name":                       llx.StringData(f.Name),
		"projectId":                  llx.StringData(f.ProjectId),
		"dataSourceType":             llx.StringData(dataSourceType),
		"fileStoreLocation":          llx.StringData(f.FileStoreLocation),
		"dataStorageLocations":       llx.ArrayData(stringsToAnySlice(f.DataStorageLocations), types.String),
		"locationType":               llx.StringData(f.LocationType),
		"fileStorePath":              llx.StringData(f.FileStorePath),
		"fullResource":               llx.StringData(f.FullResource),
		"profileStatus":              llx.DictData(status),
		"state":                      llx.StringData(f.State.String()),
		"resourceVisibility":         llx.StringData(f.ResourceVisibility.String()),
		"sensitivityScore":           llx.DictData(sensitivity),
		"dataRiskLevel":              llx.DictData(riskLevel),
		"lastProfileStatus":          lastProfileStatus,
		"fileClusterSummaries":       llx.ArrayData(clusterSummaries, types.Dict),
		"resourceAttributes":         llx.DictData(resourceAttributes),
		"resourceLabels":             llx.MapData(strMapToAny(f.ResourceLabels), types.String),
		"fileStoreInfoTypeSummaries": llx.ArrayData(infoTypeSummaries, types.Dict),
		"fileStoreIsEmpty":           llx.BoolData(f.FileStoreIsEmpty),
		"profileLastGenerated":       llx.TimeDataPtr(timestampAsTimePtr(f.ProfileLastGenerated)),
		"created":                    llx.TimeDataPtr(timestampAsTimePtr(f.CreateTime)),
		"lastModifiedTime":           llx.TimeDataPtr(timestampAsTimePtr(f.LastModifiedTime)),
	}
	maps.Copy(fileStoreArgs, scores)

	return CreateResource(runtime, "gcp.project.dlpService.fileStoreDataProfile", fileStoreArgs)
}

func (g *mqlGcpProjectDlpServiceFileStoreDataProfile) bucket() (*mqlGcpProjectStorageServiceBucket, error) {
	path := g.FileStorePath.Data
	bucketName := ""
	const gsPrefix = "gs://"
	if len(path) > len(gsPrefix) && path[:len(gsPrefix)] == gsPrefix {
		bucketName = path[len(gsPrefix):]
	}
	if bucketName == "" {
		g.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// The storage bucket init keys on "name" (it does a Buckets.Get(name) and
	// populates every field). Passing "id" instead no-ops the init and leaves a
	// husk, so key it on "name" like the sibling logBucket() ref does.
	mqlBucket, err := NewResource(g.MqlRuntime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"name": llx.StringData(bucketName),
	})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlGcpProjectStorageServiceBucket), nil
}

// ---------------------------------------------------------------
// Inverse traversals
// ---------------------------------------------------------------

func (g *mqlGcpProjectStorageServiceBucket) dlpDataProfile() (*mqlGcpProjectDlpServiceFileStoreDataProfile, error) {
	bucketName := g.Id.Data
	if g.ProjectNumber.Error != nil {
		g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	projectId := conn.ResourceID()
	if projectId == "" || bucketName == "" {
		g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	ctx := context.Background()
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	wantPath := "gs://" + bucketName
	it := client.ListFileStoreDataProfiles(ctx, &dlppb.ListFileStoreDataProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, dlpDataProfilesLocation),
		Filter: fmt.Sprintf("file_store_path=\"%s\"", wantPath),
	})
	for {
		f, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not look up DLP file-store data profile for bucket")
				g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		if f.FileStorePath == wantPath {
			res, err := newMqlFileStoreDataProfile(g.MqlRuntime, f)
			if err != nil {
				return nil, err
			}
			return res.(*mqlGcpProjectDlpServiceFileStoreDataProfile), nil
		}
	}

	g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (g *mqlGcpProjectBigqueryServiceTable) dlpDataProfile() (*mqlGcpProjectDlpServiceTableDataProfile, error) {
	tableId := g.Id.Data
	datasetId := g.DatasetId.Data
	projectId := g.ProjectId.Data
	if tableId == "" || datasetId == "" || projectId == "" {
		g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	ctx := context.Background()
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	currentProject := conn.ResourceID()
	if currentProject == "" {
		currentProject = projectId
	}
	it := client.ListTableDataProfiles(ctx, &dlppb.ListTableDataProfilesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", currentProject, dlpDataProfilesLocation),
		Filter: fmt.Sprintf("table_id=\"%s\" AND dataset_id=\"%s\" AND project_id=\"%s\"", tableId, datasetId, projectId),
	})
	for {
		t, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not look up DLP table data profile for BigQuery table")
				g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		if t.TableId == tableId && t.DatasetId == datasetId && t.DatasetProjectId == projectId {
			res, err := newMqlTableDataProfile(g.MqlRuntime, t)
			if err != nil {
				return nil, err
			}
			return res.(*mqlGcpProjectDlpServiceTableDataProfile), nil
		}
	}

	g.DlpDataProfile.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectDlpService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_dlp)
}

// ---------------------------------------------------------------
// Content Policies
// ---------------------------------------------------------------

// Kinds of sink a content policy records its verdicts to. LOG_TO_BIG_QUERY is
// the only destination the API models today; DESTINATION_UNSPECIFIED covers a
// logging config that names none, including one whose destination is a variant
// added after this provider was built.
const (
	dlpLogDestinationBigQuery    = "LOG_TO_BIG_QUERY"
	dlpLogDestinationUnspecified = "DESTINATION_UNSPECIFIED"
)

// dlpPolicyActionVerdict returns the verdict a content policy action produces,
// or nil when the policy sets no action for that case at all.
//
// The distinction matters: a policy that sets no action for unsupported file
// types is not the same as one that explicitly allows them, and collapsing the
// first into ALLOW would report a decision the policy never made. An action that
// exists but carries no verdict is a third state and reports the API's own
// CONTENT_POLICY_VERDICT_UNSPECIFIED rather than being flattened into either.
func dlpPolicyActionVerdict(action *dlppb.ContentPolicy_PolicyAction) *string {
	if action == nil {
		return nil
	}
	verdict := action.GetReturnVerdict().String()
	return &verdict
}

// dlpDefaultVerdict returns the verdict applied to content that matched no rule.
//
// A content policy with no default action allows such content, which the API
// documents as the default rather than reporting explicitly, so that is what
// this returns. Reporting null instead would leave the most permissive
// configuration a policy can have looking like an absence of data, and a check
// asserting the default is BLOCK would then have nothing to fail on.
func dlpDefaultVerdict(action *dlppb.ContentPolicy_PolicyAction) string {
	if action == nil {
		return "ALLOW"
	}
	return action.GetReturnVerdict().String()
}

// dlpConditionMinCount returns the number of findings a condition needs before
// it holds.
//
// The API treats an unset count as 1, so an unset count is reported as 1. A
// literal 0 would read as "no findings required", which inverts the meaning of
// the field and would let a check asserting a positive threshold pass on a
// condition that in fact fires on the first finding.
func dlpConditionMinCount(minCount int64) int64 {
	if minCount <= 0 {
		return 1
	}
	return minCount
}

// dlpLoggingDestination reports the kind of sink a logging config writes to and,
// when that sink is BigQuery, the table it names.
//
// An unrecognized or absent destination reports DESTINATION_UNSPECIFIED with no
// table rather than an error, so a policy carrying a destination variant newer
// than this provider still lists its other logging configs.
func dlpLoggingDestination(cfg *dlppb.ContentPolicy_LoggingConfig) (destination, projectID, datasetID, tableID string) {
	if bq := cfg.GetLogToBigQuery(); bq != nil {
		return dlpLogDestinationBigQuery, bq.GetProjectId(), bq.GetDatasetId(), bq.GetTableId()
	}
	return dlpLogDestinationUnspecified, "", "", ""
}

func (g *mqlGcpProjectDlpServiceContentPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDlpServiceContentPolicyLoggingConfigInternal struct {
	cacheProjectId string
	cacheDatasetId string
	cacheTableId   string
}

func (g *mqlGcpProjectDlpServiceContentPolicyLoggingConfig) bigQueryDataset() (*mqlGcpProjectBigqueryServiceDataset, error) {
	dataset, err := resolveBigqueryDataset(g.MqlRuntime, g.cacheProjectId, g.cacheDatasetId)
	if err != nil {
		return nil, err
	}
	if dataset == nil {
		g.BigQueryDataset.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return dataset, nil
}

func (g *mqlGcpProjectDlpServiceContentPolicyLoggingConfig) bigQueryTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	table, err := resolveBigqueryTable(g.MqlRuntime, g.cacheProjectId, g.cacheDatasetId, g.cacheTableId)
	if err != nil {
		return nil, err
	}
	if table == nil {
		g.BigQueryTable.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return table, nil
}

// dlpContentPolicyCondition is the flattened reading of one content policy
// condition, in the form the MQL resource reports it.
type dlpContentPolicyCondition struct {
	// Known reports whether this is a condition shape the provider models. When
	// it is false nothing about the condition was read, and every other field
	// here is meaningless: the resource reports them all as null rather than as
	// zeroes it cannot stand behind.
	Known bool
	// MinCount is the findings threshold, with the API's documented default of 1
	// already applied.
	MinCount int64
	// InfoTypeNames is the named set the condition matches on, or nil when it
	// matches every infoType. Nil is deliberate: an empty list would read as
	// "matches nothing", the opposite of what AnyInfoType means.
	InfoTypeNames []string
	// AnyInfoType reports whether the condition matches every infoType the
	// inspection looked for rather than a named set.
	AnyInfoType bool
}

// readDlpContentPolicyCondition flattens a policy condition into the values the
// MQL resource reports.
//
// A condition that is not an infoType condition (a oneof variant added after
// this provider was built) comes back with Known false, so the resource reports
// null throughout instead of a zero minCount and an empty infoType list, both of
// which would be claims this code is in no position to make.
func readDlpContentPolicyCondition(cond *dlppb.ContentPolicy_PolicyRule_PolicyCondition) dlpContentPolicyCondition {
	itc := cond.GetInfoTypeCondition()
	if itc == nil {
		return dlpContentPolicyCondition{}
	}

	out := dlpContentPolicyCondition{
		Known:       true,
		MinCount:    dlpConditionMinCount(itc.GetMinCount()),
		AnyInfoType: itc.GetAnyInfoType() != nil,
	}
	if names := itc.GetInfoTypes(); names != nil {
		out.InfoTypeNames = names.GetInfoTypeNames()
	}
	return out
}

// newMqlDlpContentPolicyCondition builds one condition of a content policy rule.
func newMqlDlpContentPolicyCondition(runtime *plugin.Runtime, id string, cond *dlppb.ContentPolicy_PolicyRule_PolicyCondition) (plugin.Resource, error) {
	read := readDlpContentPolicyCondition(cond)

	minCount := llx.NilData
	infoTypeNames := llx.NilData
	anyInfoType := llx.NilData
	if read.Known {
		minCount = llx.IntData(read.MinCount)
		anyInfoType = llx.BoolData(read.AnyInfoType)
		if read.InfoTypeNames != nil {
			infoTypeNames = llx.ArrayData(stringsToAnySlice(read.InfoTypeNames), types.String)
		}
	}

	return CreateResource(runtime, "gcp.project.dlpService.contentPolicy.rule.condition", map[string]*llx.RawData{
		"__id":          llx.StringData(id),
		"minCount":      minCount,
		"infoTypeNames": infoTypeNames,
		"anyInfoType":   anyInfoType,
	})
}

func (g *mqlGcpProjectDlpService) contentPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var res []any
	for _, loc := range dlpRegionalListLocations {
		it := client.ListContentPolicies(ctx, &dlppb.ListContentPoliciesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, loc),
		})
		for {
			cp, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				// Content policies are a newer part of the DLP API than the rest
				// of this service, so a project that can list job triggers may
				// still answer Unimplemented or PermissionDenied here. Both mean
				// this caller sees no content policies in this location, which is
				// a state to report rather than a failure that should take the
				// whole DLP resource down with it.
				if isSkippable(err) {
					log.Warn().Err(err).Str("location", loc).Msg("could not list DLP content policies")
					break
				}
				return nil, err
			}

			mqlRules := make([]any, 0, len(cp.Rules))
			for i, rule := range cp.Rules {
				ruleId := fmt.Sprintf("%s/rules/%d", cp.Name, i)

				mqlConditions := make([]any, 0, len(rule.GetConditions()))
				for j, cond := range rule.GetConditions() {
					mqlCond, err := newMqlDlpContentPolicyCondition(g.MqlRuntime,
						fmt.Sprintf("%s/conditions/%d", ruleId, j), cond)
					if err != nil {
						return nil, err
					}
					mqlConditions = append(mqlConditions, mqlCond)
				}

				mqlRule, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.contentPolicy.rule", map[string]*llx.RawData{
					"__id":       llx.StringData(ruleId),
					"verdict":    llx.StringDataPtr(dlpPolicyActionVerdict(rule.GetAction())),
					"conditions": llx.ArrayData(mqlConditions, types.Resource("gcp.project.dlpService.contentPolicy.rule.condition")),
				})
				if err != nil {
					return nil, err
				}
				mqlRules = append(mqlRules, mqlRule)
			}

			mqlLoggingConfigs := make([]any, 0, len(cp.LoggingConfigs))
			for i, lc := range cp.LoggingConfigs {
				destination, bqProject, bqDataset, bqTable := dlpLoggingDestination(lc)

				mqlLc, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.contentPolicy.loggingConfig", map[string]*llx.RawData{
					"__id":        llx.StringData(fmt.Sprintf("%s/loggingConfigs/%d", cp.Name, i)),
					"destination": llx.StringData(destination),
				})
				if err != nil {
					return nil, err
				}
				lcRes := mqlLc.(*mqlGcpProjectDlpServiceContentPolicyLoggingConfig)
				lcRes.cacheProjectId = bqProject
				lcRes.cacheDatasetId = bqDataset
				lcRes.cacheTableId = bqTable
				mqlLoggingConfigs = append(mqlLoggingConfigs, mqlLc)
			}

			inspectConfig, err := protoToDict(cp.InspectConfig)
			if err != nil {
				return nil, err
			}
			errs, err := dlpProtoSliceToDict(cp.Errors)
			if err != nil {
				return nil, err
			}

			mqlCp, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.contentPolicy", map[string]*llx.RawData{
				"name":                                 llx.StringData(cp.Name),
				"displayName":                          llx.StringData(cp.DisplayName),
				"rules":                                llx.ArrayData(mqlRules, types.Resource("gcp.project.dlpService.contentPolicy.rule")),
				"defaultVerdict":                       llx.StringData(dlpDefaultVerdict(cp.DefaultAction)),
				"unsupportedFileTypeVerdict":           llx.StringDataPtr(dlpPolicyActionVerdict(cp.UnsupportedFileType)),
				"inputTooLargeVerdict":                 llx.StringDataPtr(dlpPolicyActionVerdict(cp.InputTooLarge)),
				"failedToScanSupportedFileTypeVerdict": llx.StringDataPtr(dlpPolicyActionVerdict(cp.FailedToScanSupportedFileType)),
				"inspectConfig":                        llx.DictData(inspectConfig),
				"loggingConfigs":                       llx.ArrayData(mqlLoggingConfigs, types.Resource("gcp.project.dlpService.contentPolicy.loggingConfig")),
				"errors":                               llx.ArrayData(errs, types.Dict),
				"created":                              llx.TimeDataPtr(timestampAsTimePtr(cp.CreateTime)),
				"updated":                              llx.TimeDataPtr(timestampAsTimePtr(cp.UpdateTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCp)
		}
	}

	return res, nil
}

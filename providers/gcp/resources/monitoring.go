// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	dashboard "cloud.google.com/go/monitoring/dashboard/apiv1"
	"cloud.google.com/go/monitoring/dashboard/apiv1/dashboardpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/iterator"
	monitoringv3 "google.golang.org/api/monitoring/v3"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/durationpb"
)

// durationSeconds safely extracts the Seconds field from a *durationpb.Duration,
// returning 0 if the duration is nil.
func durationSeconds(d *durationpb.Duration) int64 {
	if d == nil {
		return 0
	}
	return d.Seconds
}

// mutationRecordTime safely extracts the MutateTime from a MutationRecord.
func mutationRecordTime(mr *monitoringpb.MutationRecord) *llx.RawData {
	if mr == nil || mr.MutateTime == nil {
		return llx.NilData
	}
	return llx.TimeData(mr.MutateTime.AsTime())
}

// mutationRecordBy safely extracts the MutatedBy from a MutationRecord.
func mutationRecordBy(mr *monitoringpb.MutationRecord) *llx.RawData {
	if mr == nil {
		return llx.StringData("")
	}
	return llx.StringData(mr.MutatedBy)
}

func (g *mqlGcpProjectMonitoringService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.monitoringService", projectId), nil
}

func initGcpProjectMonitoringService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

type mqlGcpProjectMonitoringServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) monitoring() (*mqlGcpProjectMonitoringService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_monitoring)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectMonitoringService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_monitoring).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectMonitoringService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_monitoring)
}

func (g *mqlGcpProjectMonitoringServiceAlertPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// notificationChannels resolves the alert policy's channel resource names to
// the typed notification channels listed by the parent monitoring service.
func (g *mqlGcpProjectMonitoringServiceAlertPolicy) notificationChannels() ([]any, error) {
	if g.NotificationChannelUrls.Error != nil {
		return nil, g.NotificationChannelUrls.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if len(g.NotificationChannelUrls.Data) == 0 {
		return []any{}, nil
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	channels := res.(*mqlGcpProjectMonitoringService).GetNotificationChannels()
	if channels.Error != nil {
		return nil, channels.Error
	}

	byName := make(map[string]*mqlGcpProjectMonitoringServiceNotificationChannel, len(channels.Data))
	for _, c := range channels.Data {
		ch := c.(*mqlGcpProjectMonitoringServiceNotificationChannel)
		byName[ch.Name.Data] = ch
	}

	out := make([]any, 0, len(g.NotificationChannelUrls.Data))
	for _, u := range g.NotificationChannelUrls.Data {
		if name, ok := u.(string); ok {
			if ch, found := byName[name]; found {
				out = append(out, ch)
			}
		}
	}
	return out, nil
}

func (g *mqlGcpProjectMonitoringService) alertPolicies() ([]any, error) {
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

	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	c, err := monitoring.NewAlertPolicyClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var res []any
	it := c.ListAlertPolicies(ctx, &monitoringpb.ListAlertPoliciesRequest{Name: fmt.Sprintf("projects/%s", projectId)})
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var mqlDoc any
		if p.Documentation != nil {
			mqlDoc = map[string]any{
				"content":  p.Documentation.Content,
				"mimeType": p.Documentation.MimeType,
			}
		}

		mqlConditions := make([]any, 0, len(p.Conditions))
		for _, c := range p.Conditions {
			var mqlThreshold any
			if thresh := c.GetConditionThreshold(); thresh != nil {
				mqlThreshold = map[string]any{
					"filter":                thresh.Filter,
					"denominatorFilter":     thresh.DenominatorFilter,
					"comparison":            thresh.Comparison.String(),
					"thresholdValue":        thresh.ThresholdValue,
					"duration":              durationSeconds(thresh.Duration),
					"evaluationMissingData": thresh.EvaluationMissingData.String(),
				}
			}

			var mqlAbsent any
			if absent := c.GetConditionAbsent(); absent != nil {
				mqlAbsent = map[string]any{
					"filter":   absent.Filter,
					"duration": durationSeconds(absent.Duration),
				}
			}

			var mqlMatchedLog any
			if matchedLog := c.GetConditionMatchedLog(); matchedLog != nil {
				mqlMatchedLog = map[string]any{
					"filter":          matchedLog.Filter,
					"labelExtractors": convert.MapToInterfaceMap(matchedLog.LabelExtractors),
				}
			}

			var mqlMonitoringQueryLanguage any
			if monitoringQLanguage := c.GetConditionMonitoringQueryLanguage(); monitoringQLanguage != nil {
				mqlMonitoringQueryLanguage = map[string]any{
					"query":                 monitoringQLanguage.Query,
					"duration":              durationSeconds(monitoringQLanguage.Duration),
					"evaluationMissingData": monitoringQLanguage.EvaluationMissingData.String(),
				}
			}

			mqlConditions = append(mqlConditions, map[string]any{
				"name":                    c.Name,
				"displayName":             c.DisplayName,
				"threshold":               mqlThreshold,
				"absent":                  mqlAbsent,
				"matchedLog":              mqlMatchedLog,
				"monitoringQueryLanguage": mqlMonitoringQueryLanguage,
			})
		}

		var mqlValidity any
		if p.Validity != nil {
			mqlValidity = map[string]any{
				"code":    int64(p.Validity.Code),
				"message": p.Validity.Message,
			}
		}

		var mqlAlertStrategy any
		if p.AlertStrategy != nil {
			var mqlNotifRateLimit any
			if p.AlertStrategy.NotificationRateLimit != nil {
				mqlNotifRateLimit = map[string]any{
					"period": durationSeconds(p.AlertStrategy.NotificationRateLimit.Period),
				}
			}
			var autoClose int64
			if p.AlertStrategy.AutoClose != nil {
				autoClose = p.AlertStrategy.AutoClose.Seconds
			}
			mqlAlertStrategy = map[string]any{
				"notificationRateLimit": mqlNotifRateLimit,
				"autoClose":             autoClose,
			}
		}

		mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.alertPolicy", map[string]*llx.RawData{
			"projectId":               llx.StringData(projectId),
			"name":                    llx.StringData(p.Name),
			"displayName":             llx.StringData(p.DisplayName),
			"documentation":           llx.DictData(mqlDoc),
			"labels":                  llx.MapData(convert.MapToInterfaceMap(p.UserLabels), types.String),
			"conditions":              llx.ArrayData(mqlConditions, types.Dict),
			"combiner":                llx.StringData(p.Combiner.String()),
			"enabled":                 llx.BoolData(p.Enabled.GetValue()),
			"validity":                llx.DictData(mqlValidity),
			"notificationChannelUrls": llx.ArrayData(convert.SliceAnyToInterface(p.NotificationChannels), types.String),
			"created":                 mutationRecordTime(p.CreationRecord),
			"createdBy":               mutationRecordBy(p.CreationRecord),
			"updated":                 mutationRecordTime(p.MutationRecord),
			"updatedBy":               mutationRecordBy(p.MutationRecord),
			"alertStrategy":           llx.DictData(mqlAlertStrategy),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// ---------------------------------------------------------------
// Uptime Check Configs
// ---------------------------------------------------------------

func (g *mqlGcpProjectMonitoringServiceUptimeCheckConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectMonitoringService) uptimeCheckConfigs() ([]any, error) {
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

	// Use REST API (not gRPC) because the gRPC proto doesn't expose the
	// Disabled field, which is only available via the REST API.
	client, err := conn.Client(monitoringv3.MonitoringReadScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	monitoringSvc, err := monitoringv3.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := monitoringSvc.Projects.UptimeCheckConfigs.List(fmt.Sprintf("projects/%s", projectId))
	if err := req.Pages(ctx, func(page *monitoringv3.ListUptimeCheckConfigsResponse) error {
		for _, cfg := range page.UptimeCheckConfigs {
			httpCheck, err := convert.JsonToDict(cfg.HttpCheck)
			if err != nil {
				return err
			}
			tcpCheck, err := convert.JsonToDict(cfg.TcpCheck)
			if err != nil {
				return err
			}
			monitoredResource, err := convert.JsonToDict(cfg.MonitoredResource)
			if err != nil {
				return err
			}
			resourceGroup, err := convert.JsonToDict(cfg.ResourceGroup)
			if err != nil {
				return err
			}

			contentMatchers := make([]any, 0, len(cfg.ContentMatchers))
			for _, cm := range cfg.ContentMatchers {
				d, err := convert.JsonToDict(cm)
				if err != nil {
					return err
				}
				contentMatchers = append(contentMatchers, d)
			}

			selectedRegions := convert.SliceAnyToInterface(cfg.SelectedRegions)

			var userLabels map[string]any
			if cfg.UserLabels != nil {
				userLabels = convert.MapToInterfaceMap(cfg.UserLabels)
			}

			mqlCfg, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.uptimeCheckConfig", map[string]*llx.RawData{
				"name":              llx.StringData(cfg.Name),
				"displayName":       llx.StringData(cfg.DisplayName),
				"disabled":          llx.BoolData(cfg.Disabled),
				"checkerType":       llx.StringData(cfg.CheckerType),
				"period":            llx.StringData(cfg.Period),
				"timeout":           llx.StringData(cfg.Timeout),
				"selectedRegions":   llx.ArrayData(selectedRegions, types.String),
				"httpCheck":         llx.DictData(httpCheck),
				"tcpCheck":          llx.DictData(tcpCheck),
				"contentMatchers":   llx.ArrayData(contentMatchers, types.Dict),
				"monitoredResource": llx.DictData(monitoredResource),
				"resourceGroup":     llx.DictData(resourceGroup),
				"userLabels":        llx.MapData(userLabels, types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlCfg)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Notification Channels
// ---------------------------------------------------------------

func (g *mqlGcpProjectMonitoringServiceNotificationChannel) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectMonitoringService) notificationChannels() ([]any, error) {
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
	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	c, err := monitoring.NewNotificationChannelClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var res []any
	it := c.ListNotificationChannels(ctx, &monitoringpb.ListNotificationChannelsRequest{
		Name: fmt.Sprintf("projects/%s", projectId),
	})
	for {
		ch, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlCh, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.notificationChannel", map[string]*llx.RawData{
			"name":               llx.StringData(ch.Name),
			"displayName":        llx.StringData(ch.DisplayName),
			"description":        llx.StringData(ch.Description),
			"type":               llx.StringData(ch.Type),
			"enabled":            llx.BoolData(ch.Enabled.GetValue()),
			"labels":             llx.MapData(convert.MapToInterfaceMap(ch.Labels), types.String),
			"userLabels":         llx.MapData(convert.MapToInterfaceMap(ch.UserLabels), types.String),
			"verificationStatus": llx.StringData(ch.VerificationStatus.String()),
			"created":            llx.TimeDataPtr(timestampAsTimePtr(ch.GetCreationRecord().GetMutateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCh)
	}
	return res, nil
}

// ---------------------------------------------------------------
// Groups
// ---------------------------------------------------------------

func (g *mqlGcpProjectMonitoringServiceGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectMonitoringService) groups() ([]any, error) {
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
	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	c, err := monitoring.NewGroupClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var res []any
	it := c.ListGroups(ctx, &monitoringpb.ListGroupsRequest{
		Name: fmt.Sprintf("projects/%s", projectId),
	})
	for {
		grp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlGrp, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.group", map[string]*llx.RawData{
			"name":        llx.StringData(grp.Name),
			"displayName": llx.StringData(grp.DisplayName),
			"parentName":  llx.StringData(grp.ParentName),
			"filter":      llx.StringData(grp.Filter),
			"isCluster":   llx.BoolData(grp.IsCluster),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGrp)
	}
	return res, nil
}

func (g *mqlGcpProjectMonitoringService) dashboards() ([]any, error) {
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
	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := dashboard.NewDashboardsClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDashboards(ctx, &dashboardpb.ListDashboardsRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		db, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		layoutDict, err := protoToDict(db)
		if err != nil {
			layoutDict = nil
		}
		// Extract just the layout portion from the full dashboard dict
		var layout map[string]any
		if layoutDict != nil {
			// Remove non-layout fields from the dict
			for k, v := range layoutDict {
				if k == "gridLayout" || k == "mosaicLayout" || k == "rowLayout" || k == "columnLayout" {
					layout = map[string]any{k: v}
					break
				}
			}
		}

		mqlDashboard, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.dashboard", map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"name":        llx.StringData(db.Name),
			"displayName": llx.StringData(db.DisplayName),
			"etag":        llx.StringData(db.Etag),
			"layout":      llx.DictData(layout),
			"labels":      llx.MapData(convert.MapToInterfaceMap(db.GetLabels()), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDashboard)
	}

	return res, nil
}

func (g *mqlGcpProjectMonitoringServiceDashboard) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/monitoringService.dashboard/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectMonitoringService) services() ([]any, error) {
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
	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := monitoring.NewServiceMonitoringClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListServices(ctx, &monitoringpb.ListServicesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		svc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		telemetryDict, err := protoToDict(svc.Telemetry)
		if err != nil {
			telemetryDict = nil
		}

		var userLabels map[string]any
		if len(svc.UserLabels) > 0 {
			userLabels = make(map[string]any, len(svc.UserLabels))
			for k, v := range svc.UserLabels {
				userLabels[k] = v
			}
		}

		mqlSvc, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.service", map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"name":        llx.StringData(svc.Name),
			"displayName": llx.StringData(svc.DisplayName),
			"telemetry":   llx.DictData(telemetryDict),
			"userLabels":  llx.MapData(userLabels, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSvc)
	}

	return res, nil
}

func (g *mqlGcpProjectMonitoringServiceService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/monitoringService.service/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectMonitoringServiceService) slos() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	serviceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(monitoring.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := monitoring.NewServiceMonitoringClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListServiceLevelObjectives(ctx, &monitoringpb.ListServiceLevelObjectivesRequest{
		Parent: serviceName,
	})

	var res []any
	for {
		slo, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		sliDict, err := protoToDict(slo.ServiceLevelIndicator)
		if err != nil {
			sliDict = nil
		}

		var rollingPeriod, calendarPeriod string
		if rp, ok := slo.Period.(*monitoringpb.ServiceLevelObjective_RollingPeriod); ok {
			// durationToString, not (*durationpb.Duration).String(): the latter
			// is the generated proto stringer and renders protobuf TEXT
			// ("seconds:2592000"). The .lr documents this field as "86400s".
			rollingPeriod = durationToString(rp.RollingPeriod)
		}
		if cp, ok := slo.Period.(*monitoringpb.ServiceLevelObjective_CalendarPeriod); ok {
			calendarPeriod = cp.CalendarPeriod.String()
		}

		var userLabels map[string]any
		if len(slo.UserLabels) > 0 {
			userLabels = make(map[string]any, len(slo.UserLabels))
			for k, v := range slo.UserLabels {
				userLabels[k] = v
			}
		}

		mqlSlo, err := CreateResource(g.MqlRuntime, "gcp.project.monitoringService.service.slo", map[string]*llx.RawData{
			"projectId":             llx.StringData(projectId),
			"name":                  llx.StringData(slo.Name),
			"displayName":           llx.StringData(slo.DisplayName),
			"goal":                  llx.FloatData(slo.Goal),
			"serviceLevelIndicator": llx.DictData(sliDict),
			"rollingPeriod":         llx.StringData(rollingPeriod),
			"calendarPeriod":        llx.StringData(calendarPeriod),
			"userLabels":            llx.MapData(userLabels, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSlo)
	}

	return res, nil
}

func (g *mqlGcpProjectMonitoringServiceServiceSlo) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/monitoringService.service.slo/%s", g.ProjectId.Data, g.Name.Data), nil
}

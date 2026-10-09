// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/logging"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciLogging) id() (string, error) {
	return "oci.logging", nil
}

func (o *mqlOciLogging) logGroups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Every compartment, not the root with the subtree flag: the Logging API
	// documents isCompartmentIdInSubtree but ignores it, so a log group in a
	// child compartment never came back from the root.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci logging with region %s", region)

			svc, err := conn.LoggingClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			logGroups, err := o.getLogGroupsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range logGroups {
				lg := logGroups[i]

				var created *time.Time
				if lg.TimeCreated != nil {
					created = &lg.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.logging.logGroup", stringValue(lg.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(lg.Id),
					"name":         llx.StringDataPtr(lg.DisplayName),
					"description":  llx.StringDataPtr(lg.Description),
					"state":        llx.StringData(string(lg.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(lg.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(lg.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(lg.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				// Store the region internally so logs() knows which region to query
				mqlInstance.(*mqlOciLoggingLogGroup).cacheRegion = region
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciLogging) getLogGroupsForRegion(ctx context.Context, client *logging.LoggingManagementClient, compartmentID string) ([]logging.LogGroupSummary, error) {
	entries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]logging.LogGroupSummary, *string, error) {
		request := logging.ListLogGroupsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListLogGroups(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

type mqlOciLoggingLogGroupInternal struct {
	ociCompartmentRef
	cacheRegion string
}

func initOciLoggingLogGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.logging.logGroup")
	}

	obj, err := CreateResource(runtime, "oci.logging", nil)
	if err != nil {
		return nil, nil, err
	}
	l := obj.(*mqlOciLogging)

	rawGroups := l.GetLogGroups()
	if rawGroups.Error != nil {
		return nil, nil, rawGroups.Error
	}

	for _, raw := range rawGroups.Data {
		lg := raw.(*mqlOciLoggingLogGroup)
		if lg.Id.Data == idVal {
			return args, lg, nil
		}
	}

	return nil, nil, errors.New("oci.logging.logGroup not found: " + idVal)
}

func (o *mqlOciLoggingLogGroup) id() (string, error) {
	return "oci.logging.logGroup/" + o.Id.Data, nil
}

func (o *mqlOciLoggingLogGroup) logs() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	logGroupId := o.Id.Data

	svc, err := conn.LoggingClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	logs, err := o.getLogsForGroup(ctx, svc, logGroupId)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range logs {
		l := logs[i]

		config, err := convertLogConfiguration(l.Configuration)
		if err != nil {
			return nil, err
		}

		var logCreated, logLastModified *time.Time
		if l.TimeCreated != nil {
			logCreated = &l.TimeCreated.Time
		}
		if l.TimeLastModified != nil {
			logLastModified = &l.TimeLastModified.Time
		}

		category, sourceService, sourceResource := extractLogSource(l.Configuration)

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.logging.log", map[string]*llx.RawData{
			"id":                llx.StringDataPtr(l.Id),
			"name":              llx.StringDataPtr(l.DisplayName),
			"logType":           llx.StringData(string(l.LogType)),
			"isEnabled":         llx.BoolDataPtr(l.IsEnabled),
			"state":             llx.StringData(string(l.LifecycleState)),
			"retentionDuration": llx.IntDataPtr(l.RetentionDuration),
			"configuration":     llx.DictData(config),
			"category":          llx.StringData(category),
			"sourceService":     llx.StringData(sourceService),
			"sourceResource":    llx.StringData(sourceResource),
			"created":           llx.TimeDataPtr(logCreated),
			"timeLastModified":  llx.TimeDataPtr(logLastModified),
			"freeformTags":      llx.MapData(strMapToAny(l.FreeformTags), types.String),
			"definedTags":       llx.MapData(definedTagsToAny(l.DefinedTags), types.Any),
			"systemTags":        llx.MapData(definedTagsToAny(l.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlOciLoggingLog).cacheLogGroupID = stringValue(l.LogGroupId)
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciLoggingLogGroup) getLogsForGroup(ctx context.Context, client *logging.LoggingManagementClient, logGroupId string) ([]logging.LogSummary, error) {
	entries, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]logging.LogSummary, *string, error) {
		request := logging.ListLogsRequest{
			LogGroupId: common.String(logGroupId),
			Page:       page,
		}

		response, err := client.ListLogs(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

type mqlOciLoggingLogInternal struct {
	cacheLogGroupID string
}

func (o *mqlOciLoggingLog) id() (string, error) {
	return "oci.logging.log/" + o.Id.Data, nil
}

func (o *mqlOciLoggingLog) logGroup() (*mqlOciLoggingLogGroup, error) {
	if o.cacheLogGroupID == "" {
		o.LogGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlLg, err := NewResource(o.MqlRuntime, "oci.logging.logGroup", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheLogGroupID),
	})
	if err != nil {
		return nil, err
	}
	return mqlLg.(*mqlOciLoggingLogGroup), nil
}

// extractLogSource pulls category, service, and resource out of a logging
// configuration's Source union. Any missing layer (nil configuration, nil
// source, unknown source type) yields empty strings.
func extractLogSource(cfg *logging.Configuration) (category, service, resource string) {
	if cfg == nil || cfg.Source == nil {
		return "", "", ""
	}
	svc, ok := cfg.Source.(logging.OciService)
	if !ok {
		return "", "", ""
	}
	return stringValue(svc.Category), stringValue(svc.Service), stringValue(svc.Resource)
}

func convertLogConfiguration(cfg *logging.Configuration) (map[string]interface{}, error) {
	if cfg == nil {
		return nil, nil
	}

	result := map[string]interface{}{}

	if cfg.CompartmentId != nil {
		result["compartmentId"] = *cfg.CompartmentId
	}

	if cfg.Source != nil {
		source, err := convert.JsonToDict(cfg.Source)
		if err != nil {
			return nil, err
		}
		result["source"] = source
	}

	// Archiving is the third field on the SDK's Configuration and was dropped
	// entirely, so log-archiving state read as "not configured" on every log.
	if cfg.Archiving != nil {
		archiving, err := convert.JsonToDict(cfg.Archiving)
		if err != nil {
			return nil, err
		}
		result["archiving"] = archiving
	}

	return result, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
)

func (g *mqlGcpLoggingSettings) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// loggingHTTPClient returns an authenticated HTTP client for the Cloud Logging
// REST API.
//
// Only the HTTP client is shared, not the logging.Service: the permissions
// extractor tracks REST service variables per function, so a helper that
// returned the service would hide logging.NewService from every caller and drop
// their permissions from the manifest. Each accessor constructs the service
// itself for that reason.
func loggingHTTPClient(runtime *plugin.Runtime) (*http.Client, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Client(logging.CloudPlatformReadOnlyScope, logging.LoggingReadScope)
}

// newMqlLoggingSettings maps Log Router settings onto the shared resource.
//
// The settings come from GetSettings, not GetCmekSettings: the two are separate
// endpoints and only GetSettings carries disableDefaultSink and
// storageLocation. Settings exist at every level of the resource hierarchy and
// have the same shape at each, so one mapper serves projects, folders, and
// organizations; reading a parent's settings is how you find out what a project
// created below it will inherit.
func newMqlLoggingSettings(runtime *plugin.Runtime, settings *logging.Settings, fallbackName string) (*mqlGcpLoggingSettings, error) {
	defaultSinkConfig, err := convert.JsonToDict(settings.DefaultSinkConfig)
	if err != nil {
		return nil, err
	}

	name := settings.Name
	if name == "" {
		// Name is output-only and can come back empty; fall back to the requested
		// node so the resource still has a stable cache key.
		name = fallbackName
	}

	defaultSink, err := newMqlDefaultSinkOverride(runtime, "gcp.loggingSettings/"+name, settings.DefaultSinkConfig)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.loggingSettings", map[string]*llx.RawData{
		"name":                    llx.StringData(name),
		"disableDefaultSink":      llx.BoolData(settings.DisableDefaultSink),
		"kmsKeyName":              llx.StringData(settings.KmsKeyName),
		"kmsServiceAccountId":     llx.StringData(settings.KmsServiceAccountId),
		"loggingServiceAccountId": llx.StringData(settings.LoggingServiceAccountId),
		"storageLocation":         llx.StringData(settings.StorageLocation),
		"defaultSinkConfig":       llx.DictData(defaultSinkConfig),
		"defaultSink":             defaultSink,
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpLoggingSettings), nil
}

func (g *mqlGcpProjectLoggingservice) settings() (*mqlGcpLoggingSettings, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		g.Settings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	parent := "projects/" + g.ProjectId.Data

	client, err := loggingHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := logging.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	settings, err := svc.Projects.GetSettings(parent).Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("project", g.ProjectId.Data).Msg("could not read Cloud Logging settings")
			g.Settings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlLoggingSettings(g.MqlRuntime, settings, parent+"/settings")
}

func (g *mqlGcpOrganizationLoggingService) settings() (*mqlGcpLoggingSettings, error) {
	if g.OrganizationName.Error != nil {
		return nil, g.OrganizationName.Error
	}
	// OrganizationName is already in "organizations/{id}" form.
	parent := g.OrganizationName.Data

	client, err := loggingHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := logging.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	settings, err := svc.Organizations.GetSettings(parent).Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("organization", parent).Msg("could not read Cloud Logging settings")
			g.Settings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlLoggingSettings(g.MqlRuntime, settings, parent+"/settings")
}

func (g *mqlGcpFolderLoggingService) settings() (*mqlGcpLoggingSettings, error) {
	if g.FolderName.Error != nil {
		return nil, g.FolderName.Error
	}
	// FolderName is already in "folders/{id}" form.
	parent := g.FolderName.Data

	client, err := loggingHTTPClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := logging.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	settings, err := svc.Folders.GetSettings(parent).Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("folder", parent).Msg("could not read Cloud Logging settings")
			g.Settings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlLoggingSettings(g.MqlRuntime, settings, parent+"/settings")
}

// newMqlDefaultSinkOverride promotes the overrides a folder or organization
// applies to the built-in _Default sink.
//
// Returns llx.NilData for a node that leaves the sink exactly as Cloud Logging
// builds it, which is a different claim from a node that overrides it with an
// empty filter.
func newMqlDefaultSinkOverride(runtime *plugin.Runtime, parentID string, cfg *logging.DefaultSinkConfig) (*llx.RawData, error) {
	if cfg == nil {
		return llx.NilData, nil
	}

	exclusions, err := newMqlLogExclusions(runtime, parentID+"/defaultSink", cfg.Exclusions)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.loggingSettings.defaultSinkOverride", map[string]*llx.RawData{
		"__id":       llx.StringData(parentID + "/defaultSink"),
		"filter":     llx.StringData(cfg.Filter),
		"mode":       llx.StringData(cfg.Mode),
		"exclusions": llx.ArrayData(exclusions, types.Resource("gcp.project.loggingservice.sink.exclusion")),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.loggingSettings.defaultSinkOverride"), nil
}

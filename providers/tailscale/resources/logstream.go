// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	tsclient "tailscale.com/client/tailscale/v2"
)

func createTailscaleLogstreamResource(runtime *plugin.Runtime, tailnet string, logType tsclient.LogType, cfg *tsclient.LogstreamConfiguration) (plugin.Resource, error) {
	return CreateResource(runtime, "tailscale.logstream", map[string]*llx.RawData{
		"__id":                 llx.StringData(tailnet + "/logstream/" + string(logType)),
		"logType":              llx.StringData(string(logType)),
		"destinationType":      llx.StringData(string(cfg.DestinationType)),
		"url":                  llx.StringData(cfg.URL),
		"user":                 llx.StringData(cfg.User),
		"s3Bucket":             llx.StringData(cfg.S3Bucket),
		"s3Region":             llx.StringData(cfg.S3Region),
		"s3KeyPrefix":          llx.StringData(cfg.S3KeyPrefix),
		"s3AuthenticationType": llx.StringData(string(cfg.S3AuthenticationType)),
		"s3AccessKeyId":        llx.StringData(cfg.S3AccessKeyID),
		"s3RoleArn":            llx.StringData(cfg.S3RoleARN),
		"s3ExternalId":         llx.StringData(cfg.S3ExternalID),
	})
}

// logstreams returns the configured log streams for the tailnet. There are at
// most two, one for configuration audit logs and one for network flow logs.
// A 404 from the Tailscale API means no destination is configured for that
// log type, and a 403 means the tailnet's plan does not include log streaming
// or the credential lacks the log_streaming:read scope. The API returning an
// empty struct (DestinationType == "") means the same as a 404. Every such
// case is skipped so the field degrades to an empty list rather than failing
// the whole query.
func (t *mqlTailscale) logstreams() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	ctx := context.Background()

	tailnet := t.GetTailnet()
	if tailnet.Error != nil {
		return nil, tailnet.Error
	}

	resources := []any{}
	for _, logType := range []tsclient.LogType{tsclient.LogTypeConfig, tsclient.LogTypeNetwork} {
		cfg, err := conn.Client().Logging().LogstreamConfiguration(ctx, logType)
		if err != nil {
			if connection.IsUnavailable(err) {
				log.Debug().Err(err).Str("logType", string(logType)).
					Msg("tailscale> no log stream available for this tailnet")
				continue
			}
			return nil, err
		}
		if cfg == nil || cfg.DestinationType == "" {
			continue
		}
		resource, err := createTailscaleLogstreamResource(t.MqlRuntime, tailnet.Data, logType, cfg)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

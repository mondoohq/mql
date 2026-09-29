// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

func (r *mqlDigitaloceanDatabase) logsinks() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	databaseID := r.Id.Data
	sinks, err := paginate(context.Background(), func(ctx context.Context, opt *godo.ListOptions) ([]godo.DatabaseLogsink, *godo.Response, error) {
		return client.Databases.ListLogsinks(ctx, databaseID, opt)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(sinks))
	for i := range sinks {
		args, err := logsinkArgs(databaseID, &sinks[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.database.logsink", args)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// logsinkArgs maps a log sink to its MQL fields.
//
// The transport settings a sink does not use stay empty, and the two numeric
// settings stay null when the API reports no value: port 0 and a retention of
// 0 days are both readings an audit would act on, and neither is what "the
// API did not say" means. The CA, client key, and client certificate the sink
// is configured with are credentials and are deliberately dropped, and so is
// a password embedded in the sink URL.
func logsinkArgs(databaseID string, s *godo.DatabaseLogsink) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.database.logsink", databaseID, s.ID)
	if err != nil {
		return nil, err
	}

	var (
		server      string
		url         string
		format      string
		indexPrefix string
		tlsEnabled  bool
		port        *int
		indexDays   *int
	)
	if cfg := s.Config; cfg != nil {
		server = cfg.Server
		url = redactURLPassword(cfg.URL)
		format = cfg.Format
		indexPrefix = cfg.IndexPrefix
		tlsEnabled = cfg.TLS
		if cfg.Port != 0 {
			p := cfg.Port
			port = &p
		}
		if cfg.IndexDaysMax != 0 {
			d := cfg.IndexDaysMax
			indexDays = &d
		}
	}

	return map[string]*llx.RawData{
		"__id":               llx.StringData(id),
		"databaseId":         llx.StringData(databaseID),
		"sinkId":             llx.StringData(s.ID),
		"name":               llx.StringData(s.Name),
		"type":               llx.StringData(s.Type),
		"server":             llx.StringData(server),
		"port":               llx.IntDataPtr(port),
		"url":                llx.StringData(url),
		"tlsEnabled":         llx.BoolData(tlsEnabled),
		"format":             llx.StringData(format),
		"indexPrefix":        llx.StringData(indexPrefix),
		"indexRetentionDays": llx.IntDataPtr(indexDays),
	}, nil
}

func (r *mqlDigitaloceanDatabaseLogsink) database() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.Database)
}

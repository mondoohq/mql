// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	bqconnection "cloud.google.com/go/bigquery/connection/apiv1"
	"cloud.google.com/go/bigquery/connection/apiv1/connectionpb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProjectBigqueryService) connections() ([]any, error) {
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
	creds, err := conn.Credentials(bqconnection.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := bqconnection.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return listBigqueryLocations(func(location string) ([]any, error) {
		var res []any
		it := client.ListConnections(ctx, &connectionpb.ListConnectionsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location),
		})
		for {
			c, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			connectionType, properties, err := connectionProperties(c)
			if err != nil {
				return nil, err
			}

			var created, modified *llx.RawData
			if c.CreationTime != 0 {
				created = llx.TimeData(time.UnixMilli(c.CreationTime))
			} else {
				created = llx.NilData
			}
			if c.LastModifiedTime != 0 {
				modified = llx.TimeData(time.UnixMilli(c.LastModifiedTime))
			} else {
				modified = llx.NilData
			}

			mqlConn, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.connection", map[string]*llx.RawData{
				"name":          llx.StringData(c.Name),
				"projectId":     llx.StringData(projectId),
				"location":      llx.StringData(location),
				"friendlyName":  llx.StringData(c.FriendlyName),
				"description":   llx.StringData(c.Description),
				"type":          llx.StringData(connectionType),
				"properties":    llx.DictData(properties),
				"created":       created,
				"modified":      modified,
				"hasCredential": llx.BoolData(c.HasCredential),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
		return res, nil
	})
}

// connectionProperties returns the connection type and a dict of the
// properties payload for the configured oneof variant.
func connectionProperties(c *connectionpb.Connection) (string, map[string]any, error) {
	switch p := c.Properties.(type) {
	case *connectionpb.Connection_CloudSql:
		d, err := protoToDict(p.CloudSql)
		return "CLOUD_SQL", d, err
	case *connectionpb.Connection_Aws:
		d, err := protoToDict(p.Aws)
		return "AWS", d, err
	case *connectionpb.Connection_Azure:
		d, err := protoToDict(p.Azure)
		return "AZURE", d, err
	case *connectionpb.Connection_CloudSpanner:
		d, err := protoToDict(p.CloudSpanner)
		return "CLOUD_SPANNER", d, err
	case *connectionpb.Connection_CloudResource:
		d, err := protoToDict(p.CloudResource)
		return "CLOUD_RESOURCE", d, err
	case *connectionpb.Connection_Spark:
		d, err := protoToDict(p.Spark)
		return "SPARK", d, err
	case *connectionpb.Connection_SalesforceDataCloud:
		d, err := protoToDict(p.SalesforceDataCloud)
		return "SALESFORCE_DATA_CLOUD", d, err
	case nil:
		return "UNKNOWN", nil, nil
	default:
		return "UNKNOWN", nil, nil
	}
}

func (g *mqlGcpProjectBigqueryServiceConnection) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

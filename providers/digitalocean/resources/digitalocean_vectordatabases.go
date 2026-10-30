// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

func (r *mqlDigitalocean) vectorDatabases() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	vdbs, err := paginate(context.Background(), client.VectorDBs.List)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(vdbs))
	for i := range vdbs {
		v := vdbs[i]

		tags := make([]any, len(v.Tags))
		for j, t := range v.Tags {
			tags[j] = t
		}

		weaviateVersion, autoSchema, quantization := "", false, ""
		if v.Config != nil {
			weaviateVersion = v.Config.WeaviateVersion
			autoSchema = v.Config.EnableAutoSchema
			quantization = v.Config.DefaultQuantization
		}

		httpEndpoint, grpcEndpoint := "", ""
		if v.Endpoints != nil {
			httpEndpoint = v.Endpoints.HTTP
			grpcEndpoint = v.Endpoints.GRPC
		}

		// The GetCredentials endpoint returns a live API token, so we
		// deliberately do not surface credentials on the resource.
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vectorDatabase", map[string]*llx.RawData{
			"id":                  llx.StringData(v.ID),
			"name":                llx.StringData(v.Name),
			"region":              llx.StringData(v.Region),
			"ownerUuid":           llx.StringData(v.OwnerUUID),
			"status":              llx.StringData(v.Status),
			"size":                llx.StringData(v.Size),
			"tags":                llx.ArrayData(tags, "\x02"),
			"createdAt":           llx.TimeData(v.CreatedAt),
			"updatedAt":           llx.TimeData(v.UpdatedAt),
			"weaviateVersion":     llx.StringData(weaviateVersion),
			"enableAutoSchema":    llx.BoolData(autoSchema),
			"defaultQuantization": llx.StringData(quantization),
			"httpEndpoint":        llx.StringData(httpEndpoint),
			"grpcEndpoint":        llx.StringData(grpcEndpoint),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanVectorDatabase) id() (string, error) {
	return "digitalocean.vectorDatabase/" + r.Id.Data, nil
}

func (r *mqlDigitaloceanVectorDatabaseBackup) id() (string, error) {
	return "digitalocean.vectorDatabase.backup/" + r.VectorDatabaseId.Data + "/" + r.BackupId.Data, nil
}

func (r *mqlDigitaloceanVectorDatabase) backups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	// The vector DB backups endpoint is not paginated: ListBackups takes no
	// ListOptions and the response carries no pagination links, so a single
	// call returns the full set.
	backups, _, err := client.VectorDBs.ListBackups(context.Background(), r.Id.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(backups))
	for i := range backups {
		b := backups[i]
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vectorDatabase.backup", map[string]*llx.RawData{
			"vectorDatabaseId": llx.StringData(r.Id.Data),
			"backupId":         llx.StringData(b.BackupID),
			"status":           llx.StringData(b.Status),
			"startedAt":        llx.TimeData(b.StartedAt),
			"completedAt":      llx.TimeData(b.CompletedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

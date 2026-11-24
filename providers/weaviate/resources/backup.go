// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/weaviate/weaviate/entities/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// backupModulePrefix marks the modules that provide a backup backend. The
// backend is addressed by the rest of the module name: backup-s3 is the s3
// backend.
const backupModulePrefix = "backup-"

// backupBackends returns the backends enabled on the server, given the names
// of its enabled modules.
func backupBackends(modules []any) []string {
	out := []string{}
	for _, m := range modules {
		name, ok := m.(string)
		if !ok || !strings.HasPrefix(name, backupModulePrefix) {
			continue
		}
		if backend := strings.TrimPrefix(name, backupModulePrefix); backend != "" {
			out = append(out, backend)
		}
	}
	return out
}

func backupResourceID(serverID, backend, id string) string {
	return serverID + "/backup/" + backend + "/" + id
}

// backupArgs builds the fields of a backup resource from one entry of a
// backend's backup list.
func backupArgs(serverID, backend string, b *models.BackupListResponseItems0) map[string]*llx.RawData {
	var size *float64
	if b.Size != 0 {
		size = &b.Size
	}
	names := make([]any, 0, len(b.Classes))
	for _, c := range b.Classes {
		names = append(names, c)
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData(backupResourceID(serverID, backend, b.ID)),
		"id":              llx.StringData(b.ID),
		"backend":         llx.StringData(backend),
		"status":          llx.StringData(b.Status),
		"startedAt":       llx.TimeDataPtr(nonZeroTime(time.Time(b.StartedAt))),
		"completedAt":     llx.TimeDataPtr(nonZeroTime(time.Time(b.CompletedAt))),
		"sizeGiB":         llx.FloatDataPtr(size),
		"collectionNames": llx.ArrayData(names, types.String),
	}
}

// backups lists the backups of every enabled backup backend. A backend this
// credential may not read is skipped, so the backups of the others still
// report.
func (r *mqlWeaviateInstance) backups() ([]any, error) {
	backends := backupBackends(r.Modules.Data)
	if len(backends) == 0 {
		return []any{}, nil
	}
	client, err := weaviateConnection(r.MqlRuntime).Client()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, backend := range backends {
		items, err := client.Backup().Lister().WithBackend(backend).Do(weaviateContext())
		if err != nil {
			if isForbidden(err) {
				log.Debug().Err(err).Str("backend", backend).Msg("weaviate> cannot list backups of backend")
				continue
			}
			return nil, err
		}
		for _, item := range items {
			if item == nil {
				continue
			}
			res, err := CreateResource(r.MqlRuntime, "weaviate.backup", backupArgs(r.__id, backend, item))
			if err != nil {
				return nil, err
			}
			b := res.(*mqlWeaviateBackup)
			b.cacheInstance = r
			list = append(list, b)
		}
	}
	return list, nil
}

// collections resolves the backup's collection names against the instance's
// collection list. A collection deleted since the backup was taken has no
// resource to point to and is reported only in collectionNames.
func (r *mqlWeaviateBackup) collections() ([]any, error) {
	if r.cacheInstance == nil {
		return []any{}, nil
	}
	byName, err := collectionsByName(r.cacheInstance)
	if err != nil {
		return nil, err
	}
	list := []any{}
	for _, n := range r.CollectionNames.Data {
		name, _ := n.(string)
		if col, ok := byName[name]; ok {
			list = append(list, col)
		}
	}
	return list, nil
}

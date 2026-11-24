// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: module names as GET /v1/meta lists them; no live server was
// checked.
func TestBackupBackends(t *testing.T) {
	got := backupBackends([]any{"backup-filesystem", "backup-s3", "text2vec-openai", "backup-", 42})
	assert.Equal(t, []string{"filesystem", "s3"}, got)
	assert.Empty(t, backupBackends(nil))
}

// Synthetic: a schema with one collection, an s3 backend whose list is shaped
// after models.BackupListResponse, and a filesystem backend that refuses the
// credential; no live server was checked.
func TestBackups(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/backups/s3":
			_, _ = w.Write([]byte(`[
				{"id":"nightly-1","status":"SUCCESS","startedAt":"2026-11-01T02:00:00.000Z","completedAt":"2026-11-01T02:05:00.000Z","size":1.5,"classes":["Article","Removed"]},
				{"id":"nightly-2","status":"STARTED","startedAt":"2026-11-02T02:00:00.000Z","classes":["Article"]}
			]`))
		case "/v1/backups/filesystem":
			w.WriteHeader(http.StatusForbidden)
		case "/v1/schema":
			_, _ = w.Write([]byte(`{"classes":[{"class":"Article"}]}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	instance := testInstance(t, serverRuntime(t, srv), "backup-filesystem", "backup-s3", "text2vec-openai")

	list, err := instance.backups()
	require.NoError(t, err)
	require.Len(t, list, 2, "the refused filesystem backend is skipped, the s3 backups still report")

	done := list[0].(*mqlWeaviateBackup)
	assert.Equal(t, "nightly-1", done.Id.Data)
	assert.Equal(t, "s3", done.Backend.Data)
	assert.Equal(t, "SUCCESS", done.Status.Data)
	assert.Equal(t, 1.5, done.SizeGiB.Data)
	assert.Equal(t, time.Date(2026, 11, 1, 2, 5, 0, 0, time.UTC), done.CompletedAt.Data.UTC())
	assert.Equal(t, []any{"Article", "Removed"}, done.CollectionNames.Data)
	assert.Equal(t, "http://weaviate.test:8080/backup/s3/nightly-1", done.MqlID())

	cols, err := done.collections()
	require.NoError(t, err)
	require.Len(t, cols, 1, "a deleted collection has no resource to point to")
	assert.Equal(t, "Article", cols[0].(*mqlWeaviateCollection).Name.Data)

	running := list[1].(*mqlWeaviateBackup)
	assert.True(t, running.CompletedAt.IsNull(), "a running backup has no completion time")
	assert.True(t, running.SizeGiB.IsNull(), "a backup without a reported size reads null")
}

// Synthetic: a server with no backup module; no live server was checked.
func TestBackupsWithoutBackend(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer srv.Close()
	list, err := testInstance(t, serverRuntime(t, srv), "text2vec-openai").backups()
	require.NoError(t, err)
	assert.Empty(t, list)
}

// Synthetic: a backend that fails for a reason other than a refusal; no live
// server was checked. The failure is reported rather than read as no backups.
func TestBackupsBackendError(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := testInstance(t, serverRuntime(t, srv), "backup-s3").backups()
	assert.Error(t, err)
}

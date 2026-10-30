// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"testing"

	objectstorage "github.com/stackitcloud/stackit-sdk-go/services/objectstorage/v2api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	complianceLockPath = "GET /v2/project/" + fakeProjectID + "/regions/" + fakeRegion + "/compliance-lock"
	serviceStatusPath  = "GET /v2/project/" + fakeProjectID + "/regions/" + fakeRegion
)

func newObjectStorage(t *testing.T, runtime *plugin.Runtime) *mqlStackitObjectStorage {
	t.Helper()
	res, err := makeNamespace(runtime, "stackit.objectStorage")
	require.NoError(t, err)
	return res.(*mqlStackitObjectStorage)
}

func TestObjectStorageComplianceLock(t *testing.T) {
	// Synthetic: a project with a 365-day compliance lock, shaped after the
	// SDK's ComplianceLockResponse; no target showed this.
	t.Run("lock present", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
			complianceLockPath: json200(`{"project":"` + fakeProjectID + `","maxRetentionDays":365}`),
		})
		got := newObjectStorage(t, runtime).GetComplianceLockMaxRetentionDays()
		require.NoError(t, got.Error)
		assert.False(t, got.IsNull())
		assert.Equal(t, int64(365), got.Data)
	})

	// Synthetic: the service answers 404 for a project without a lock.
	t.Run("no lock is null, not zero", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{complianceLockPath: jsonStatus(http.StatusNotFound)})
		got := newObjectStorage(t, runtime).GetComplianceLockMaxRetentionDays()
		require.NoError(t, got.Error)
		assert.True(t, got.IsNull())
	})

	t.Run("refusal is Forbidden", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{complianceLockPath: jsonStatus(http.StatusForbidden)})
		got := newObjectStorage(t, runtime).GetComplianceLockMaxRetentionDays()
		require.Error(t, got.Error)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(got.Error))
	})
}

func TestObjectStorageScope(t *testing.T) {
	// Synthetic: service status of a default project.
	t.Run("scope from the service status", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
			serviceStatusPath: json200(`{"project":"` + fakeProjectID + `","scope":"PUBLIC"}`),
		})
		got := newObjectStorage(t, runtime).GetScope()
		require.NoError(t, got.Error)
		assert.Equal(t, "PUBLIC", got.Data)
	})

	// Synthetic: a project not onboarded to Object Storage.
	t.Run("not onboarded is null", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{serviceStatusPath: jsonStatus(http.StatusNotFound)})
		got := newObjectStorage(t, runtime).GetScope()
		require.NoError(t, got.Error)
		assert.True(t, got.IsNull())
	})
}

func TestObjectStorageScopeHelper(t *testing.T) {
	decode := func(body string) *objectstorage.ProjectStatus {
		var s objectstorage.ProjectStatus
		require.NoError(t, json.Unmarshal([]byte(body), &s))
		return &s
	}
	// Synthetic: the two scopes the SDK knows, and one it does not.
	assert.Equal(t, "SCHWARZ", objectStorageScope(decode(`{"project":"p","scope":"SCHWARZ"}`)))
	assert.Equal(t, "", objectStorageScope(decode(`{"project":"p","scope":"SOVEREIGN"}`)),
		"a scope the SDK folds into its placeholder is not reported as that placeholder")
	assert.Equal(t, "", objectStorageScope(nil))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/together/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// volumesFixture is shaped like the documented list response for
// GET compute/clusters/storage/volumes. The values are invented; only the field
// names have to match the API.
const volumesFixture = `{
  "volumes": [
    {
      "volume_id": "vol-0000000000000000",
      "volume_name": "example-volume",
      "size_tib": 4,
      "status": "bound"
    }
  ]
}`

// storageStub records what the provider asked the API for. projectFilter is the
// value of the projectId query parameter on the volumes call, and listCalls
// counts how often the volumes endpoint was reached at all.
type storageStub struct {
	projectFilter  string
	filterWasSent  bool
	listCalls      int32
	whoamiCalls    int32
	whoamiStatus   int
	whoamiResponse string
}

func newStorageTogether(t *testing.T, cliProject string, stub *storageStub) *mqlTogether {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/whoami"):
			atomic.AddInt32(&stub.whoamiCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stub.whoamiStatus)
			_, _ = w.Write([]byte(stub.whoamiResponse))
		case strings.HasSuffix(r.URL.Path, "/storage/volumes"):
			atomic.AddInt32(&stub.listCalls, 1)
			stub.projectFilter = r.URL.Query().Get("projectId")
			_, stub.filterWasSent = r.URL.Query()["projectId"]
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(volumesFixture))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	conn, err := connection.NewTogetherConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OptionToken:   "not-a-real-key",
			connection.OptionBaseURL: srv.URL,
			connection.OptionProject: cliProject,
		},
	})
	require.NoError(t, err)

	return &mqlTogether{MqlRuntime: &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}}
}

func okStub() *storageStub {
	return &storageStub{whoamiStatus: http.StatusOK, whoamiResponse: whoamiFixture}
}

// Without --project the list call has to carry the project the key resolves to.
// Reading conn.Project() instead of the identity, as the code did before, sends
// no filter at all and the account sees other projects' volumes.
func TestClusterStorageFiltersByIdentityProjectWhenFlagIsAbsent(t *testing.T) {
	stub := okStub()
	r := newStorageTogether(t, "", stub)

	project, err := r.scopedProjectID()
	require.NoError(t, err)
	assert.Equal(t, "proj-2222222222222222", project)

	_, err = r.clusterStorageVolumes()
	require.NoError(t, err)

	assert.True(t, stub.filterWasSent, "volumes were listed without a project filter")
	assert.Equal(t, "proj-2222222222222222", stub.projectFilter)
}

// An operator naming a project must get that project, not the key's default.
func TestClusterStorageFlagWinsOverIdentityProject(t *testing.T) {
	stub := okStub()
	r := newStorageTogether(t, "proj-9999999999999999", stub)

	_, err := r.clusterStorageVolumes()
	require.NoError(t, err)

	assert.Equal(t, "proj-9999999999999999", stub.projectFilter)
}

// A key that resolves to no project has nothing to filter by, so the call goes
// out unfiltered and every volume it returns belongs to that key's account.
func TestClusterStorageListsUnfilteredWhenIdentityCarriesNoProject(t *testing.T) {
	stub := okStub()
	stub.whoamiResponse = `{"api_key_id": "key-0000000000000000", "organization_id": "org-1111111111111111"}`
	r := newStorageTogether(t, "", stub)

	vols, err := r.clusterStorageVolumes()
	require.NoError(t, err)

	assert.Len(t, vols, 1)
	assert.False(t, stub.filterWasSent, "an empty project must not be sent as a filter")
}

// When the identity cannot be read there is no project to scope to, and a list
// call sent anyway would be unfiltered. It must not be sent.
func TestClusterStorageFailsClosedWhenIdentityIsUnavailable(t *testing.T) {
	stub := okStub()
	stub.whoamiStatus = http.StatusInternalServerError
	stub.whoamiResponse = `{"error": "boom"}`
	r := newStorageTogether(t, "", stub)

	_, err := r.clusterStorageVolumes()
	assert.Error(t, err)
	assert.Zero(t, atomic.LoadInt32(&stub.listCalls), "volumes were listed unfiltered after the identity lookup failed")
}

// The identity is fetched once for the whole resource, so scoping the list does
// not add a round trip to a scan that already read an identity field.
func TestClusterStorageReusesTheMemoizedIdentity(t *testing.T) {
	stub := okStub()
	r := newStorageTogether(t, "", stub)

	_, err := r.projectId()
	require.NoError(t, err)

	_, err = r.clusterStorageVolumes()
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&stub.whoamiCalls),
		"scoping the list call cost a second identity round trip")
}

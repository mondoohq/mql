// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	networksecurity "google.golang.org/api/networksecurity/v1"
)

func newTestNetworkSecurityService(t *testing.T, env *testEnv) *mqlGcpProjectNetworkSecurityService {
	t.Helper()
	res, err := CreateResource(env.Runtime, "gcp.project.networkSecurityService", map[string]*llx.RawData{
		"projectId": llx.StringData(testProjectId),
	})
	require.NoError(t, err)
	svc := res.(*mqlGcpProjectNetworkSecurityService)
	// The gate itself is exercised by servicegate_project_test.go; these tests
	// are about the lister.
	svc.recordEnabled(true)
	return svc
}

// ListClientTlsPolicies is the one method in this API that rejects the
// locations=- wildcard the rest of the file uses. Before the fix the lister
// asked for it anyway and the field failed on every project with
// "aggregated list (locations=-) is not supported ... for
// method=ListClientTlsPolicies".
//
// So the lister must enumerate locations and ask each one, and it must not ask
// for a zone: a zonal parent is rejected as a malformed name.
func TestClientTlsPoliciesListsPerNonZonalLocation(t *testing.T) {
	env := setupTestEnv(t, []string{networksecurity.CloudPlatformScope})

	var (
		mu      sync.Mutex
		queried []string
	)

	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// A region, a zone in that region, global, and another zone: the
			// shape the real endpoint returns (171 entries, 127 of them zonal).
			fmt.Fprint(w, `{"locations":[
				{"locationId":"us-central1"},
				{"locationId":"us-central1-a"},
				{"locationId":"global"},
				{"locationId":"europe-west1"},
				{"locationId":"europe-west1-b"}
			]}`)
		})

	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations/",
		func(w http.ResponseWriter, r *http.Request) {
			// path: /v1/projects/<p>/locations/<loc>/clientTlsPolicies
			var loc string
			_, err := fmt.Sscanf(r.URL.Path,
				"/v1/projects/"+testProjectId+"/locations/%s", &loc)
			require.NoError(t, err)
			loc = loc[:len(loc)-len("/clientTlsPolicies")]

			mu.Lock()
			queried = append(queried, loc)
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if loc == "us-central1" {
				fmt.Fprint(w, `{"clientTlsPolicies":[{"name":"projects/p/locations/us-central1/clientTlsPolicies/one","sni":"example.com"}]}`)
				return
			}
			fmt.Fprint(w, `{}`)
		})

	svc := newTestNetworkSecurityService(t, env)
	policies, err := svc.clientTlsPolicies()
	require.NoError(t, err)

	sort.Strings(queried)
	assert.Equal(t, []string{"europe-west1", "global", "us-central1"}, queried,
		"every non-zonal location must be asked, and no zone: a zonal parent is a malformed name")

	require.Len(t, policies, 1, "the policy found in one location must be returned")
	p := policies[0].(*mqlGcpProjectNetworkSecurityServiceClientTlsPolicy)
	assert.Equal(t, "example.com", p.Sni.Data)
}

// The zone filter is the part that would silently turn every per-location call
// into a 400, so it gets its own table.
func TestZonalLocationSuffix(t *testing.T) {
	for _, tc := range []struct {
		loc   string
		zonal bool
	}{
		{"us-central1-a", true},
		{"europe-west1-b", true},
		{"africa-south1-c", true},
		{"us-central1", false},
		{"europe-west10", false},
		{"northamerica-northeast1", false},
		{"global", false},
		{"me-central2", false},

		// The digit in the pattern is what keeps these out. A region whose last
		// segment is a single letter is not a zone, and treating one as a zone
		// would drop the whole region from the walk without saying so.
		{"europe-west", false},
		{"some-region-x", false},
	} {
		t.Run(tc.loc, func(t *testing.T) {
			assert.Equal(t, tc.zonal, zonalLocationSuffix.MatchString(tc.loc))
		})
	}
}

// A location that refuses the read says nothing about the others, and the
// policies already collected are real. Abandoning the walk on the first failure
// reported a field populated in most regions as empty because one region
// refused, which is what this pins.
func TestClientTlsPoliciesKeepWhatOtherLocationsReturned(t *testing.T) {
	env := setupTestEnv(t, []string{networksecurity.CloudPlatformScope})

	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"locations":[
				{"locationId":"europe-west1"},
				{"locationId":"global"},
				{"locationId":"us-central1"}
			]}`)
		})

	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations/",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(r.URL.Path, "/locations/europe-west1/"):
				// The kind of per-region gap that used to zero the field.
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":{"code":403,"message":"permission denied","status":"PERMISSION_DENIED"}}`)
			case strings.Contains(r.URL.Path, "/locations/us-central1/"):
				fmt.Fprint(w, `{"clientTlsPolicies":[{"name":"projects/p/locations/us-central1/clientTlsPolicies/one","sni":"example.com"}]}`)
			default:
				fmt.Fprint(w, `{}`)
			}
		})

	svc := newTestNetworkSecurityService(t, env)
	policies, err := svc.clientTlsPolicies()
	require.NoError(t, err, "one unreadable location must not fail the field")
	require.Len(t, policies, 1, "the policy from the readable location must survive")
	assert.Equal(t, "example.com",
		policies[0].(*mqlGcpProjectNetworkSecurityServiceClientTlsPolicy).Sni.Data)
}

// A failure that is not skippable is a real failure and still has to propagate,
// or a broken walk would read as a short list.
func TestClientTlsPoliciesPropagateNonSkippableFailure(t *testing.T) {
	env := setupTestEnv(t, []string{networksecurity.CloudPlatformScope})

	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"locations":[{"locationId":"us-central1"}]}`)
		})
	env.Mux.HandleFunc("/v1/projects/"+testProjectId+"/locations/",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":{"code":500,"message":"backend error","status":"INTERNAL"}}`)
		})

	svc := newTestNetworkSecurityService(t, env)
	_, err := svc.clientTlsPolicies()
	require.Error(t, err)
}

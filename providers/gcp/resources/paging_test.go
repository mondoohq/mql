// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/cloudresourcemanager/v3"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
)

// Pagination coverage for the REST listers.
//
// Nothing in this provider used to exercise a lister's request/decode path, so
// a truncated listing -- the single most common defect class here, and the one
// users cannot see, because it surfaces as a short list rather than an error --
// was only ever caught in production. These tests drive the real Google client
// against a local server and assert that every page reaches the caller.

// pagedHandler serves a sequence of JSON bodies, one per request, and records
// the pageToken each request carried. It fails the test if the client asks for
// more pages than were staged.
type pagedHandler struct {
	mu       sync.Mutex
	bodies   []string
	tokens   []string // the pageToken query value seen on each request, in order
	requests int
}

func (h *pagedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.tokens = append(h.tokens, r.URL.Query().Get("pageToken"))
	if h.requests >= len(h.bodies) {
		http.Error(w, `{"error":{"code":500,"message":"requested more pages than staged"}}`, http.StatusInternalServerError)
		return
	}
	body := h.bodies[h.requests]
	h.requests++
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

func (h *pagedHandler) seenTokens() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.tokens...)
}

// TestComputeZonesFollowsEveryPage is the core case: three pages, and all three
// pages' worth of zones must reach the caller.
//
// It also pins that the client echoes the cursor back, because a lister that
// loops without advancing the token would otherwise pass this test by fetching
// page one three times.
func TestComputeZonesFollowsEveryPage(t *testing.T) {
	env := setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope})

	pages := &pagedHandler{bodies: []string{
		`{"items":[{"id":"1","name":"us-central1-a","status":"UP"},
		           {"id":"2","name":"us-central1-b","status":"UP"}],
		  "nextPageToken":"cursor-2"}`,
		`{"items":[{"id":"3","name":"europe-west1-c","status":"UP"}],
		  "nextPageToken":"cursor-3"}`,
		`{"items":[{"id":"4","name":"asia-east1-a","status":"DOWN"}]}`,
	}}
	env.Mux.Handle("/compute/v1/projects/"+testProjectId+"/zones", pages)

	svc := newTestComputeService(t, env)
	zones, err := svc.zones()
	require.NoError(t, err)

	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.(*mqlGcpProjectComputeServiceZone).Name.Data)
	}
	assert.Equal(t,
		[]string{"us-central1-a", "us-central1-b", "europe-west1-c", "asia-east1-a"},
		names,
		"every page must reach the caller; a short list here is a silently truncated listing")

	assert.Equal(t, []string{"", "cursor-2", "cursor-3"}, pages.seenTokens(),
		"each request must carry the previous page's cursor")
}

// TestComputeZonesStopsWithoutACursor covers the other end: a single page with
// no nextPageToken must not provoke a second request.
func TestComputeZonesStopsWithoutACursor(t *testing.T) {
	env := setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope})

	pages := &pagedHandler{bodies: []string{
		`{"items":[{"id":"1","name":"us-central1-a","status":"UP"}]}`,
	}}
	env.Mux.Handle("/compute/v1/projects/"+testProjectId+"/zones", pages)

	svc := newTestComputeService(t, env)
	zones, err := svc.zones()
	require.NoError(t, err)
	require.Len(t, zones, 1)
	assert.Len(t, pages.seenTokens(), 1, "a page with no cursor must end the loop")
}

// TestComputeZonesSurfacesAMidPaginationFailure pins the safety property: when
// page two fails, the lister must not quietly hand back page one.
//
// A short list is indistinguishable from a small project, so returning the
// first page alone would report a truncated inventory as a complete one and let
// a posture check pass over zones it never saw. An error is the correct answer
// here even though it costs the partial result.
func TestComputeZonesSurfacesAMidPaginationFailure(t *testing.T) {
	env := setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope})

	// atomic, not a plain int: the handler runs on the test server's goroutine
	// and the counter is read from the request goroutine, so a bare int is an
	// unsynchronized pair even though -race does not happen to flag it.
	var requests atomic.Int32
	env.Mux.HandleFunc("/compute/v1/projects/"+testProjectId+"/zones", func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"items":[{"id":"1","name":"us-central1-a","status":"UP"}],"nextPageToken":"cursor-2"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":{"code":500,"message":"backend error"}}`)
	})

	svc := newTestComputeService(t, env)
	zones, err := svc.zones()
	require.Error(t, err, "a failed page must not be reported as the end of the list")
	assert.Nil(t, zones)
}

// TestComputeZonesReportsADeniedListing is the vacuous-pass guard. A 403 on the
// listing itself must surface, not degrade to an empty list: `zones` coming
// back empty reads as "this project has no zones", and every assertion over it
// passes.
func TestComputeZonesReportsADeniedListing(t *testing.T) {
	env := setupTestEnv(t, []string{cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope})

	env.Mux.HandleFunc("/compute/v1/projects/"+testProjectId+"/zones", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"Required 'compute.zones.list' permission"}}`)
	})

	svc := newTestComputeService(t, env)
	zones, err := svc.zones()
	require.Error(t, err)
	assert.Nil(t, zones)
}

// TestDnsManagedZonesFollowsEveryPage runs the same shape through a second
// service, on a different scope set and a different SDK package, to show the
// seam is not compute-specific. It also exercises the serviceGate's record
// path, since dns gates through it.
func TestDnsManagedZonesFollowsEveryPage(t *testing.T) {
	env := setupTestEnv(t, []string{dns.CloudPlatformReadOnlyScope})

	pages := &pagedHandler{bodies: []string{
		`{"managedZones":[{"id":"1","name":"example-com","dnsName":"example.com.","visibility":"public"}],
		  "nextPageToken":"cursor-2"}`,
		`{"managedZones":[{"id":"2","name":"internal","dnsName":"internal.example.","visibility":"private"}]}`,
	}}
	env.Mux.Handle("/dns/v1/projects/"+testProjectId+"/managedZones", pages)

	svc := newTestDnsService(t, env)
	zones, err := svc.managedZones()
	require.NoError(t, err)

	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.(*mqlGcpProjectDnsServiceManagedzone).Name.Data)
	}
	assert.Equal(t, []string{"example-com", "internal"}, names)
	assert.Equal(t, []string{"", "cursor-2"}, pages.seenTokens())
}

// TestDnsManagedZonesSkipsADisabledService checks the gate short-circuits
// before any request is made -- the API must not be called at all when the
// service is off.
func TestDnsManagedZonesSkipsADisabledService(t *testing.T) {
	env := setupTestEnv(t, []string{dns.CloudPlatformReadOnlyScope})

	var called atomic.Bool
	env.Mux.HandleFunc("/dns/v1/projects/"+testProjectId+"/managedZones", func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
	})

	res, err := CreateResource(env.Runtime, "gcp.project.dnsService", map[string]*llx.RawData{
		"projectId": llx.StringData(testProjectId),
	})
	require.NoError(t, err)
	svc := res.(*mqlGcpProjectDnsService)
	svc.recordEnabled(false)

	zones, err := svc.managedZones()
	require.NoError(t, err)
	assert.Nil(t, zones)
	assert.False(t, called.Load(), "a disabled service must not be called at all")
}

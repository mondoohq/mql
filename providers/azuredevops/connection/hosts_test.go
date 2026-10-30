// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEachServiceHasItsOwnHostInProduction(t *testing.T) {
	c, err := NewClient("mondoo-ado-scan-test", patAuth(t, "x"), ClientOptions{})
	require.NoError(t, err)

	assert.Equal(t,
		"https://dev.azure.com/mondoo-ado-scan-test/scan-test/_apis/policy/configurations?api-version=7.1",
		c.urlFor(request{segments: []string{"scan-test", "_apis", "policy", "configurations"}}))
	assert.Equal(t,
		"https://advsec.dev.azure.com/mondoo-ado-scan-test/scan-test/_apis/management/repositories/r/enablement?api-version=7.2-preview.1",
		c.urlFor(request{
			host:       hostAdvSec,
			segments:   []string{"scan-test", "_apis", "management", "repositories", "r", "enablement"},
			apiVersion: AdvSecAPIVersion,
		}))
	assert.Equal(t,
		"https://vssps.dev.azure.com/mondoo-ado-scan-test/_apis/identities?api-version=7.1",
		c.urlFor(request{host: hostVSSPS, segments: []string{"_apis", "identities"}}))
}

func TestALoopbackEndpointServesEveryServiceUnderAPathPrefix(t *testing.T) {
	c, err := NewClient("mondoo-ado-scan-test", patAuth(t, "x"), ClientOptions{Endpoint: "http://127.0.0.1:9"})
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:9/advsec/mondoo-ado-scan-test/_apis/x?api-version=7.2-preview.1",
		c.urlFor(request{host: hostAdvSec, segments: []string{"_apis", "x"}, apiVersion: AdvSecAPIVersion}))
	assert.Equal(t, "http://127.0.0.1:9/vssps/mondoo-ado-scan-test/_apis/x?api-version=7.1",
		c.urlFor(request{host: hostVSSPS, segments: []string{"_apis", "x"}}))
}

// The continuation page used to be rebuilt from the segments and query alone,
// which sent it to the main host with the default api-version.
func TestAContinuationPageKeepsTheHostAndTheAPIVersion(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		first := len(seen) == 1
		mu.Unlock()
		if first {
			w.Header().Set(continuationHeader, "next")
		}
		_, _ = w.Write([]byte(`{"count":1,"value":[{"id":"1a"}]}`))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient("any-org", patAuth(t, "x"), ClientOptions{Endpoint: srv.URL})
	require.NoError(t, err)

	type row struct {
		ID string `json:"id"`
	}
	rows, err := listAll[row](context.Background(), c, request{
		host:       hostAdvSec,
		segments:   []string{"p", "_apis", "alert", "repositories", "r", "alerts"},
		apiVersion: AdvSecAPIVersion,
	}, 0)
	require.NoError(t, err)
	assert.Len(t, rows, 2)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, seen, 2)
	for _, s := range seen {
		assert.Contains(t, s, "/advsec/any-org/p/_apis/alert/repositories/r/alerts?")
		assert.Contains(t, s, "api-version=7.2-preview.1")
	}
	assert.Contains(t, seen[1], "continuationToken=next")
}

func TestIsAdvSecDisabled(t *testing.T) {
	off := &APIError{Status: http.StatusBadRequest, Message: "VS2150009: Advanced Security is not enabled for this repository."}
	assert.True(t, IsAdvSecDisabled(off))
	assert.True(t, IsAdvSecDisabled(&APIError{Status: http.StatusBadRequest, TypeKey: "VS2150009"}))
	assert.False(t, IsAdvSecDisabled(&APIError{Status: http.StatusBadRequest, Message: "VS402337: api-version"}))
	assert.False(t, IsAdvSecDisabled(&APIError{Status: http.StatusForbidden, Message: "VS2150009"}))
	assert.False(t, IsAdvSecDisabled(nil))
}

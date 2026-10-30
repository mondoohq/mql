// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestRequestTimeoutApplies proves a Hetzner API call cannot hang forever.
//
// hcloud.NewClient defaults to &http.Client{}, which has no timeout, and the
// plugin runtime gives resources no context to carry a deadline instead, so
// without an explicit client timeout an unanswered request blocks the scan
// indefinitely. This points the connection at a server that never replies and
// requires the call to come back.
func TestRequestTimeoutApplies(t *testing.T) {
	blocked := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked // hold the request open until the test finishes
	}))
	// Order matters: srv.Close waits for in-flight handlers, so the handler
	// has to be released first. Defers run last-registered-first, so this
	// pair must be registered in this order.
	defer srv.Close()
	defer close(blocked)

	origTimeout, origRetries := requestTimeout, maxRetries
	requestTimeout, maxRetries = 150*time.Millisecond, 1
	defer func() { requestTimeout, maxRetries = origTimeout, origRetries }()

	conn, err := NewHetznerConnection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OPTION_TOKEN:    "test-token",
			OPTION_ENDPOINT: srv.URL,
		},
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- conn.Verify() }()

	select {
	case err := <-done:
		assert.Error(t, err, "a request that never answers must fail, not succeed")
		elapsed := time.Since(start)
		t.Logf("bounded after %s", elapsed)
		assert.Less(t, elapsed, 10*time.Second,
			"the call must be bounded rather than hanging")
	case <-time.After(10 * time.Second):
		t.Fatal("the request hung: no timeout is being applied")
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tlsshake

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A probe whose SYN is never answered must give up after probeDialTimeout
// instead of blocking the scan. 192.0.2.1 (TEST-NET-1, RFC 5737) is never
// routed, so with a default route the SYN goes unanswered like a peer that
// drops it; without one the dial fails at once. Either way testTLS returns an
// error quickly, and only an unbounded dial fails this test.
func TestTestTLS_GivesUpOnAnUnansweredConnect(t *testing.T) {
	prev := probeDialTimeout
	probeDialTimeout = 200 * time.Millisecond
	t.Cleanup(func() { probeDialTimeout = prev })

	tester := New("tcp", "example.com", "192.0.2.1", 443)
	done := make(chan error, 1)
	go func() {
		_, err := tester.testTLS("tcp", "192.0.2.1:443", &ScanConfig{version: "tls1.2", ciphersFilter: func(string) bool { return true }})
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect to target")
	case <-time.After(5 * time.Second):
		t.Fatal("testTLS still connecting after 5s; the probe dial is not bounded")
	}
}

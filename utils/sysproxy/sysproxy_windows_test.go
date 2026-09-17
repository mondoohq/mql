// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package sysproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These run against the real WinHTTP API of whatever machine executes them.
// The machine's settings are not known, so they pin what can be pinned: the
// calls return, the strings are read and freed without faulting, and a script
// that cannot be fetched fails within the timeout instead of hanging.

func TestDetectWindows(t *testing.T) {
	s, err := detect()
	require.NoError(t, err)
	t.Logf("settings: %s", s)
	if s != nil {
		for _, entry := range append(append([]string{}, s.Bypass...), s.MachineBypass...) {
			assert.NotEmpty(t, entry, "SplitList must not produce empty entries")
		}
	}
}

func TestReadMachineInternetSettingsDoesNotFault(t *testing.T) {
	// nil on a machine without the per-machine policy, a Settings otherwise
	_ = readMachineInternetSettings()
}

func TestScriptEvaluationFailsFastForUnreachableScript(t *testing.T) {
	start := time.Now()
	res := script.evaluate(&Settings{AutoConfigURL: "http://127.0.0.1:9/proxy.pac"}, mustURL(t, "https://example.com/"))
	require.Error(t, res.err)
	assert.Less(t, time.Since(start), scriptTimeout)

	// The failed answer is cached for the origin, so the second ask is immediate.
	start = time.Now()
	res = script.evaluate(&Settings{AutoConfigURL: "http://127.0.0.1:9/proxy.pac"}, mustURL(t, "https://example.com/"))
	require.Error(t, res.err)
	assert.Less(t, time.Since(start), time.Second)
}

func TestScriptEvaluationTerminatesForAutoDetect(t *testing.T) {
	// The Windows default configuration. Whether WPAD exists on the runner's
	// network is unknown; what must hold is that the call comes back.
	start := time.Now()
	res := script.evaluate(&Settings{AutoDetect: true}, mustURL(t, "https://autodetect.example/"))
	assert.Less(t, time.Since(start), scriptTimeout+time.Second)
	if res.err != nil {
		t.Logf("auto-detect: %v", res.err)
	} else {
		t.Logf("auto-detect proxies: %q", res.proxies)
	}
}

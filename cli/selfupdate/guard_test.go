// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuard_HealthyUpdateNeverQuarantined(t *testing.T) {
	bin := t.TempDir()

	// First activation of a new version proceeds.
	require.True(t, recordActivationAttempt(bin, "13.5.0"))
	// The new binary confirms it ran healthy.
	confirmActivation(bin, "13.5.0")

	// Any number of subsequent activations proceed and never increment toward
	// quarantine, because the version is confirmed.
	for i := 0; i < 10; i++ {
		require.True(t, recordActivationAttempt(bin, "13.5.0"))
	}
	assert.False(t, isVersionQuarantined(bin, "13.5.0"))
}

func TestGuard_CrashLoopGetsQuarantined(t *testing.T) {
	bin := t.TempDir()
	version := "13.6.0"

	// It is activated repeatedly but never confirms (it keeps crashing).
	proceed := true
	activations := 0
	for i := 0; i < 10 && proceed; i++ {
		proceed = recordActivationAttempt(bin, version)
		if proceed {
			activations++
		}
	}

	// After maxActivationAttempts activations it stops proceeding.
	assert.Equal(t, maxActivationAttempts, activations)
	assert.False(t, proceed)
	assert.True(t, isVersionQuarantined(bin, version))

	// A quarantined version never proceeds again.
	assert.False(t, recordActivationAttempt(bin, version))
}

func TestGuard_ConfirmBeforeBudgetPreventsQuarantine(t *testing.T) {
	bin := t.TempDir()
	version := "13.7.0"

	// Two shaky starts...
	require.True(t, recordActivationAttempt(bin, version))
	require.True(t, recordActivationAttempt(bin, version))
	// ...then it confirms healthy.
	confirmActivation(bin, version)

	// Now it can never be quarantined.
	for i := 0; i < 10; i++ {
		require.True(t, recordActivationAttempt(bin, version))
	}
	assert.False(t, isVersionQuarantined(bin, version))
}

func TestGuard_NewVersionResetsCounter(t *testing.T) {
	bin := t.TempDir()

	// An old version burns two attempts.
	require.True(t, recordActivationAttempt(bin, "13.8.0"))
	require.True(t, recordActivationAttempt(bin, "13.8.0"))

	// A newly staged version starts its own budget from scratch.
	for i := 0; i < maxActivationAttempts; i++ {
		require.True(t, recordActivationAttempt(bin, "13.9.0"))
	}
	// The (maxAttempts+1)th activation of the new version quarantines it,
	// proving the counter reset rather than carrying over.
	assert.False(t, recordActivationAttempt(bin, "13.9.0"))
	assert.True(t, isVersionQuarantined(bin, "13.9.0"))
	assert.False(t, isVersionQuarantined(bin, "13.8.0"))
}

func TestGuard_ConfirmIsVersionScoped(t *testing.T) {
	bin := t.TempDir()

	require.True(t, recordActivationAttempt(bin, "13.10.0"))
	// Confirming a different version does nothing to the pending one.
	confirmActivation(bin, "99.0.0")

	st := readUpdateState(bin)
	assert.Equal(t, "13.10.0", st.StagedVersion)
	assert.Equal(t, stateActivationPending, st.Activation)
}

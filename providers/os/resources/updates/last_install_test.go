// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Every resolved timestamp passes this gate before any field reads it, so a
// rejection here is what makes lastUpdate, lastUpdateAge and lastUpdateSource
// all read null together on a broken clock. Without it a future timestamp
// stays visible through lastUpdate while its age clamps to zero, and the asset
// appears patched moments ago.
func TestValidateLastInstalledUpdate(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	t.Run("a past install passes through untouched", func(t *testing.T) {
		update := &LastInstalledUpdate{
			Time:   now.Add(-24 * time.Hour),
			Source: LastUpdateSourceAptSecurity,
		}
		assert.Same(t, update, ValidateLastInstalledUpdate(update, now))
	})

	t.Run("no record stays no record", func(t *testing.T) {
		assert.Nil(t, ValidateLastInstalledUpdate(nil, now))
	})

	t.Run("a zero time is not a record", func(t *testing.T) {
		update := &LastInstalledUpdate{Source: LastUpdateSourceDnfRpmLog}
		assert.Nil(t, ValidateLastInstalledUpdate(update, now))
	})

	t.Run("ordinary clock skew is tolerated", func(t *testing.T) {
		update := &LastInstalledUpdate{
			Time:   now.Add(2 * time.Minute),
			Source: LastUpdateSourceWindowsUpdate,
		}
		assert.Same(t, update, ValidateLastInstalledUpdate(update, now))
	})

	t.Run("a materially future install is rejected", func(t *testing.T) {
		update := &LastInstalledUpdate{
			Time:   now.Add(time.Hour),
			Source: LastUpdateSourceAptHistory,
		}
		assert.Nil(t, ValidateLastInstalledUpdate(update, now))
	})

	t.Run("the tolerance is a boundary, not a suggestion", func(t *testing.T) {
		inside := &LastInstalledUpdate{Time: now.Add(lastUpdateSkewTolerance)}
		assert.NotNil(t, ValidateLastInstalledUpdate(inside, now))

		outside := &LastInstalledUpdate{Time: now.Add(lastUpdateSkewTolerance + time.Second)}
		assert.Nil(t, ValidateLastInstalledUpdate(outside, now))
	})
}

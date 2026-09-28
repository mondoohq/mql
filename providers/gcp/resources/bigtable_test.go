// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/bigtable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBigtableAutomatedBackupPolicyDict(t *testing.T) {
	t.Run("no policy", func(t *testing.T) {
		assert.Nil(t, bigtableAutomatedBackupPolicyDict(nil))
	})

	// A disabled policy carries no durations; before the fix it rendered as a
	// dict of "<nil>" strings that read as a configured policy.
	t.Run("disabled", func(t *testing.T) {
		assert.Nil(t, bigtableAutomatedBackupPolicyDict(&bigtable.TableAutomatedBackupPolicy{Disabled: true}))
	})

	t.Run("configured", func(t *testing.T) {
		got := bigtableAutomatedBackupPolicyDict(&bigtable.TableAutomatedBackupPolicy{
			RetentionPeriod: 72 * time.Hour,
			Frequency:       24 * time.Hour,
			KeepHotDuration: 48 * time.Hour,
			Locations:       []string{"projects/p/locations/us-central1-a"},
		})
		assert.Equal(t, map[string]any{
			"retentionPeriod": "72h0m0s",
			"frequency":       "24h0m0s",
			"keepHotDuration": "48h0m0s",
			"locations":       []any{"projects/p/locations/us-central1-a"},
		}, got)
	})

	t.Run("unset durations are omitted", func(t *testing.T) {
		got := bigtableAutomatedBackupPolicyDict(&bigtable.TableAutomatedBackupPolicy{
			RetentionPeriod: 72 * time.Hour,
		})
		require.NotNil(t, got)
		assert.Equal(t, "72h0m0s", got["retentionPeriod"])
		assert.NotContains(t, got, "frequency")
		assert.NotContains(t, got, "keepHotDuration")
		for k, v := range got {
			assert.NotEqual(t, "<nil>", v, k)
		}
	})
}

func TestBigtableBackupPolicyArgs(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		args := bigtableBackupPolicyArgs(&bigtable.TableAutomatedBackupPolicy{
			RetentionPeriod: 72 * time.Hour,
			Frequency:       24 * time.Hour,
			KeepHotDuration: 36 * time.Hour,
			Locations:       []string{"projects/p/locations/us-east1-b"},
		})
		assert.Equal(t, int64(259200), args["retentionPeriodSeconds"].Value)
		assert.Equal(t, int64(86400), args["frequencySeconds"].Value)
		assert.Equal(t, int64(129600), args["keepHotDurationSeconds"].Value)
		assert.Equal(t, []any{"projects/p/locations/us-east1-b"}, args["locations"].Value)
		assert.Equal(t, false, args["disabled"].Value)
	})

	t.Run("disabled with no durations", func(t *testing.T) {
		args := bigtableBackupPolicyArgs(&bigtable.TableAutomatedBackupPolicy{Disabled: true})
		assert.Equal(t, true, args["disabled"].Value)
		assert.Nil(t, args["retentionPeriodSeconds"].Value)
		assert.Nil(t, args["frequencySeconds"].Value)
		assert.Nil(t, args["keepHotDurationSeconds"].Value)
		assert.Equal(t, []any{}, args["locations"].Value)
	})
}

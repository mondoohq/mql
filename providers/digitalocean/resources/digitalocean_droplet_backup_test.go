// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndexBackupPolicies(t *testing.T) {
	t.Run("maps a weekly policy", func(t *testing.T) {
		idx := map[int64]dropletBackupPolicy{}
		indexBackupPolicies(map[int]*godo.DropletBackupPolicy{
			7: {
				DropletID:     7,
				BackupEnabled: true,
				BackupPolicy: &godo.DropletBackupPolicyConfig{
					Plan:                "weekly",
					Weekday:             "SUN",
					Hour:                20,
					WindowLengthHours:   4,
					RetentionPeriodDays: 28,
				},
			},
		}, idx)

		policy, ok := idx[7]
		require.True(t, ok)
		assert.Equal(t, "weekly", policy.plan)
		assert.Equal(t, "SUN", policy.weekday)
		assert.Equal(t, int64(20), policy.hour)
		assert.Equal(t, int64(4), policy.windowLengthHours)
		assert.Equal(t, int64(28), policy.retentionPeriodDays)
	})

	t.Run("daily policy carries no weekday", func(t *testing.T) {
		idx := map[int64]dropletBackupPolicy{}
		indexBackupPolicies(map[int]*godo.DropletBackupPolicy{
			8: {
				DropletID:     8,
				BackupEnabled: true,
				BackupPolicy: &godo.DropletBackupPolicyConfig{
					Plan:                "daily",
					Hour:                4,
					WindowLengthHours:   4,
					RetentionPeriodDays: 7,
				},
			},
		}, idx)

		policy, ok := idx[8]
		require.True(t, ok)
		assert.Equal(t, "daily", policy.plan)
		assert.Empty(t, policy.weekday)
		assert.Equal(t, int64(7), policy.retentionPeriodDays)
	})

	// A droplet with backups disabled must stay out of the index so its
	// fields resolve to null. Indexing it as a zero value would report a
	// never-configured droplet as having zero-day backup retention.
	t.Run("skips droplets with no schedule", func(t *testing.T) {
		idx := map[int64]dropletBackupPolicy{}
		indexBackupPolicies(map[int]*godo.DropletBackupPolicy{
			9:  {DropletID: 9, BackupEnabled: false},
			10: nil,
		}, idx)

		assert.Empty(t, idx)
	})

	t.Run("accumulates across pages", func(t *testing.T) {
		idx := map[int64]dropletBackupPolicy{}
		indexBackupPolicies(map[int]*godo.DropletBackupPolicy{
			1: {BackupPolicy: &godo.DropletBackupPolicyConfig{Plan: "daily"}},
		}, idx)
		indexBackupPolicies(map[int]*godo.DropletBackupPolicy{
			2: {BackupPolicy: &godo.DropletBackupPolicyConfig{Plan: "weekly"}},
		}, idx)

		assert.Len(t, idx, 2)
		assert.Equal(t, "daily", idx[1].plan)
		assert.Equal(t, "weekly", idx[2].plan)
	})
}

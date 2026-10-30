// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== parseInfluxdbExpiry =====

func TestParseInfluxdbExpiry(t *testing.T) {
	tests := []struct {
		title string
		value *string
		want  *time.Time
	}{
		{"nil", nil, nil},
		{"empty", new(""), nil},
		{"not a time", new("tomorrow"), nil},
		// the API reports the expiry as a string, not as a timestamp
		{"utc", new("2026-08-06T14:35:11Z"), new(time.Date(2026, 8, 6, 14, 35, 11, 0, time.UTC))},
		{"with offset", new("2026-08-06T07:35:11-07:00"), new(time.Date(2026, 8, 6, 14, 35, 11, 0, time.UTC))},
		// a unix timestamp is not RFC 3339, and must not be read as one
		{"unix timestamp", new("1786026911"), nil},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			got := parseInfluxdbExpiry(test.value)
			if test.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.True(t, test.want.Equal(*got), "want %s, got %s", test.want, got)
		})
	}
}

// ===== backup typed-ref null-state =====

func TestInfluxdbBackupDbInstanceNullWhenNoResourceId(t *testing.T) {
	for _, cached := range []*string{nil, new("")} {
		b := &mqlAwsTimestreamInfluxdbBackup{}
		b.cacheDbResourceId = cached
		got, err := b.dbInstance()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, b.DbInstance.IsNull())
		assert.True(t, b.DbInstance.IsSet())
	}
}

func TestInfluxdbBackupKmsKeyNullWhenNoKeyId(t *testing.T) {
	for _, cached := range []*string{nil, new("")} {
		b := &mqlAwsTimestreamInfluxdbBackup{}
		b.cacheKmsKeyId = cached
		got, err := b.kmsKey()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.True(t, b.KmsKey.IsNull())
		assert.True(t, b.KmsKey.IsSet())
	}
}

//go:fix inline
func ptrStr(s string) *string { return new(s) }

//go:fix inline
func timePtr(t time.Time) *time.Time { return new(t) }

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	influxdbtypes "github.com/aws/aws-sdk-go-v2/service/timestreaminfluxdb/types"
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

// Synthetic: an InfluxDB 3 Enterprise topology within the documented node
// limits, and a cluster of another engine; no cluster was scanned.
func TestInfluxdbNodeGroups(t *testing.T) {
	cfg := &influxdbtypes.DeploymentConfigurationMemberInfluxDBv3Enterprise{
		Value: influxdbtypes.InfluxDBv3EnterpriseDeploymentConfiguration{
			NodeGroups: []influxdbtypes.NodeGroup{
				{
					Count:         aws.Int32(2),
					InstanceType:  influxdbtypes.DbInstanceTypeDbInfluxMedium,
					InstanceModes: []influxdbtypes.InstanceMode{influxdbtypes.InstanceModeIngest, influxdbtypes.InstanceModeQuery},
				},
				{
					Count:         aws.Int32(1),
					InstanceType:  influxdbtypes.DbInstanceTypeDbInfluxLarge,
					InstanceModes: []influxdbtypes.InstanceMode{influxdbtypes.InstanceModeCompact},
				},
			},
		},
	}
	assert.Equal(t, []any{
		map[string]any{"count": int64(2), "instanceType": "db.influx.medium", "instanceModes": []any{"INGEST", "QUERY"}},
		map[string]any{"count": int64(1), "instanceType": "db.influx.large", "instanceModes": []any{"COMPACT"}},
	}, influxdbNodeGroups(cfg))

	assert.Equal(t, []any{}, influxdbNodeGroups(nil))
	assert.Equal(t, []any{}, influxdbNodeGroups(&influxdbtypes.DeploymentConfigurationMemberInfluxDBv3Enterprise{}))
}

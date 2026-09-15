// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DescribeClusters omits LoggingPublishStatus entirely on a cluster that has
// not configured system table publishing. Every scalar has to stay nil there,
// so the schema reports null: a false would claim the cluster is configured and
// publishing nothing, which is a different fact.
func TestRedshiftSystemTablesAbsent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cluster redshifttypes.Cluster
	}{
		{name: "no logging publish status", cluster: redshifttypes.Cluster{}},
		{
			name:    "logging publish status without s3 tables",
			cluster: redshifttypes.Cluster{LoggingPublishStatus: &redshifttypes.LoggingPublishStatus{}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redshiftSystemTables(tc.cluster)

			assert.Nil(t, got.enabledAll)
			assert.Nil(t, got.granularity)
			assert.Nil(t, got.namespace)

			// Collections stay empty rather than nil so the schema reports an
			// empty list instead of failing to serialize.
			require.NotNil(t, got.tables)
			require.NotNil(t, got.lastIngestion)
			assert.Empty(t, got.tables)
			assert.Empty(t, got.lastIngestion)
		})
	}
}

func TestRedshiftSystemTablesPopulated(t *testing.T) {
	cluster := redshifttypes.Cluster{
		LoggingPublishStatus: &redshifttypes.LoggingPublishStatus{
			S3Tables: &redshifttypes.S3TablePublishStatus{
				EnabledAll:         aws.Bool(true),
				S3TableGranularity: aws.String("account"),
				S3TableNamespace:   aws.String("redshift_system"),
				S3Tables:           []string{"stl_connection_log", "stl_userlog"},
				LastIngestionTimes: map[string]string{
					"stl_connection_log": "2026-08-20T10:00:00Z",
				},
			},
		},
	}

	got := redshiftSystemTables(cluster)

	require.NotNil(t, got.enabledAll)
	assert.True(t, *got.enabledAll)
	require.NotNil(t, got.granularity)
	assert.Equal(t, "account", *got.granularity)
	require.NotNil(t, got.namespace)
	assert.Equal(t, "redshift_system", *got.namespace)
	assert.ElementsMatch(t, []any{"stl_connection_log", "stl_userlog"}, got.tables)
	assert.Equal(t, map[string]any{"stl_connection_log": "2026-08-20T10:00:00Z"}, got.lastIngestion)
}

// Publishing that is configured but switched off must read as false, not null.
// The distinction is the whole point of keeping these as pointers.
func TestRedshiftSystemTablesDisabledIsFalseNotNull(t *testing.T) {
	cluster := redshifttypes.Cluster{
		LoggingPublishStatus: &redshifttypes.LoggingPublishStatus{
			S3Tables: &redshifttypes.S3TablePublishStatus{
				EnabledAll: aws.Bool(false),
			},
		},
	}

	got := redshiftSystemTables(cluster)

	require.NotNil(t, got.enabledAll, "a reported false must not collapse to null")
	assert.False(t, *got.enabledAll)
}

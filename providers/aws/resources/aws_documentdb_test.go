// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	docdb_types "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/stretchr/testify/assert"
)

func TestDocdbLogExportsEnabled(t *testing.T) {
	cases := []struct {
		name         string
		exports      []string
		wantAudit    bool
		wantProfiler bool
	}{
		{"empty", nil, false, false},
		{"audit only", []string{"audit"}, true, false},
		{"profiler only", []string{"profiler"}, false, true},
		{"both", []string{"audit", "profiler"}, true, true},
		{"both plus unrelated", []string{"audit", "general", "profiler", "slowquery"}, true, true},
		{"unrelated only", []string{"general", "slowquery"}, false, false},
		// case-sensitive: AWS sends lowercase, anything else should not match
		{"wrong case", []string{"AUDIT", "Profiler"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit, profiler := docdbLogExportsEnabled(tc.exports)
			assert.Equal(t, tc.wantAudit, audit, "audit mismatch")
			assert.Equal(t, tc.wantProfiler, profiler, "profiler mismatch")
		})
	}
}

func TestDocdbInstancePendingModifiedValues(t *testing.T) {
	t.Run("nil input returns empty map", func(t *testing.T) {
		out := docdbInstancePendingModifiedValues(nil)
		assert.NotNil(t, out)
		assert.Empty(t, out)
	})

	t.Run("populated fields are stringified", func(t *testing.T) {
		in := &docdb_types.PendingModifiedValues{
			AllocatedStorage:        aws.Int32(200),
			BackupRetentionPeriod:   aws.Int32(7),
			CACertificateIdentifier: aws.String("rds-ca-rsa2048-g1"),
			DBInstanceClass:         aws.String("db.r6g.large"),
			DBInstanceIdentifier:    aws.String("docdb-1"),
			DBSubnetGroupName:       aws.String("default"),
			EngineVersion:           aws.String("5.0.0"),
			Iops:                    aws.Int32(3000),
			LicenseModel:            aws.String("postgresql-license"),
			MultiAZ:                 aws.Bool(true),
			Port:                    aws.Int32(27017),
			StorageType:             aws.String("standard"),
		}
		out := docdbInstancePendingModifiedValues(in)
		assert.Equal(t, "200", out["allocatedStorage"])
		assert.Equal(t, "7", out["backupRetentionPeriod"])
		assert.Equal(t, "rds-ca-rsa2048-g1", out["caCertificateIdentifier"])
		assert.Equal(t, "db.r6g.large", out["dbInstanceClass"])
		assert.Equal(t, "docdb-1", out["dbInstanceIdentifier"])
		assert.Equal(t, "default", out["dbSubnetGroupName"])
		assert.Equal(t, "5.0.0", out["engineVersion"])
		assert.Equal(t, "3000", out["iops"])
		assert.Equal(t, "postgresql-license", out["licenseModel"])
		assert.Equal(t, "true", out["multiAZ"])
		assert.Equal(t, "27017", out["port"])
		assert.Equal(t, "standard", out["storageType"])
	})

	t.Run("master password is redacted, never returned verbatim", func(t *testing.T) {
		in := &docdb_types.PendingModifiedValues{
			MasterUserPassword: aws.String("super-secret-actual-password"),
		}
		out := docdbInstancePendingModifiedValues(in)
		assert.Equal(t, "<redacted>", out["masterUserPassword"])
		assert.NotContains(t, out["masterUserPassword"], "super-secret")
	})

	t.Run("pending log exports populate enable/disable lists", func(t *testing.T) {
		in := &docdb_types.PendingModifiedValues{
			PendingCloudwatchLogsExports: &docdb_types.PendingCloudwatchLogsExports{
				LogTypesToEnable:  []string{"audit"},
				LogTypesToDisable: []string{"profiler"},
			},
		}
		out := docdbInstancePendingModifiedValues(in)
		assert.Contains(t, out, "logTypesToEnable")
		assert.Contains(t, out, "logTypesToDisable")
		assert.Contains(t, out["logTypesToEnable"].(string), "audit")
		assert.Contains(t, out["logTypesToDisable"].(string), "profiler")
	})

	t.Run("only set fields appear in output", func(t *testing.T) {
		in := &docdb_types.PendingModifiedValues{
			Port: aws.Int32(27017),
		}
		out := docdbInstancePendingModifiedValues(in)
		assert.Equal(t, "27017", out["port"])
		assert.NotContains(t, out, "engineVersion")
		assert.NotContains(t, out, "dbInstanceClass")
		assert.NotContains(t, out, "masterUserPassword")
	})
}

func TestDocdbIsArn(t *testing.T) {
	cases := map[string]bool{
		"":                                      false,
		"arn":                                   false,
		"arn:":                                  false,
		"arn:a":                                 true,
		"arn:aws:rds:us-east-1:123:cluster/foo": true,
		"my-cluster":                            false,
		"https://example.com":                   false,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, docdbIsArn(input))
		})
	}
}

func TestServerlessV2Capacity(t *testing.T) {
	// Measured: DocumentDB 8.0.2 cluster in us-east-1, 2026-11-02, created with
	// MinCapacity=0.5 and MaxCapacity=2; DescribeDBClusters returned the same
	// bounds and the live scan reported 0.5 and 2.
	cfg := &docdb_types.ServerlessV2ScalingConfigurationInfo{
		MinCapacity: aws.Float64(0.5),
		MaxCapacity: aws.Float64(2),
	}
	assert.Equal(t, 0.5, serverlessV2Capacity(cfg, false).Value)
	assert.Equal(t, 2.0, serverlessV2Capacity(cfg, true).Value)

	// Synthetic: a provisioned cluster with no serverless scaling, and a
	// configuration naming only one bound; no cluster showed these.

	assert.Nil(t, serverlessV2Capacity(nil, false).Value)
	assert.Nil(t, serverlessV2Capacity(nil, true).Value)
	onlyMax := &docdb_types.ServerlessV2ScalingConfigurationInfo{MaxCapacity: aws.Float64(16)}
	assert.Nil(t, serverlessV2Capacity(onlyMax, false).Value)
	assert.Equal(t, 16.0, serverlessV2Capacity(onlyMax, true).Value)
}

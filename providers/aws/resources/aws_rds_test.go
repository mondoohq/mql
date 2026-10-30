// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	rds_types "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRdsKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		db := &mqlAwsRdsDbinstance{}
		result, err := db.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, db.KmsKey.IsNull())
		assert.True(t, db.KmsKey.IsSet())
	})

	t.Run("empty key ID sets null state", func(t *testing.T) {
		db := &mqlAwsRdsDbinstance{}
		empty := ""
		db.cacheKmsKeyId = &empty
		result, err := db.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, db.KmsKey.IsNull())
		assert.True(t, db.KmsKey.IsSet())
	})
}

func TestRdsPerformanceInsightsKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		db := &mqlAwsRdsDbinstance{}
		// cachePerformanceInsightsKmsKeyId is nil by default
		result, err := db.performanceInsightsKmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, db.PerformanceInsightsKmsKey.IsNull())
		assert.True(t, db.PerformanceInsightsKmsKey.IsSet())
	})

	t.Run("empty key ID sets null state", func(t *testing.T) {
		db := &mqlAwsRdsDbinstance{}
		empty := ""
		db.cachePerformanceInsightsKmsKeyId = &empty
		result, err := db.performanceInsightsKmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, db.PerformanceInsightsKmsKey.IsNull())
		assert.True(t, db.PerformanceInsightsKmsKey.IsSet())
	})
}

func TestRdsClusterMonitoringRole(t *testing.T) {
	t.Run("empty arn sets null state", func(t *testing.T) {
		c := &mqlAwsRdsDbcluster{}
		result, err := c.monitoringRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.MonitoringRole.IsNull())
		assert.True(t, c.MonitoringRole.IsSet())
	})
}

func TestRdsClusterDbClusterParameterGroup(t *testing.T) {
	t.Run("empty parameter group name sets null state", func(t *testing.T) {
		c := &mqlAwsRdsDbcluster{}
		result, err := c.dbClusterParameterGroup()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.DbClusterParameterGroup.IsNull())
		assert.True(t, c.DbClusterParameterGroup.IsSet())
	})
}

func TestRdsDbInstanceActivityStreamKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		db := &mqlAwsRdsDbinstance{}
		result, err := db.activityStreamKmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, db.ActivityStreamKmsKey.IsNull())
		assert.True(t, db.ActivityStreamKmsKey.IsSet())
	})
}

func TestRdsClusterKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		c := &mqlAwsRdsDbcluster{}
		result, err := c.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.KmsKey.IsNull())
		assert.True(t, c.KmsKey.IsSet())
	})
}

func TestRdsClusterActivityStreamKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		c := &mqlAwsRdsDbcluster{}
		result, err := c.activityStreamKmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, c.ActivityStreamKmsKey.IsNull())
		assert.True(t, c.ActivityStreamKmsKey.IsSet())
	})
}

func TestRdsSnapshotKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		s := &mqlAwsRdsSnapshot{}
		result, err := s.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, s.KmsKey.IsNull())
		assert.True(t, s.KmsKey.IsSet())
	})
}

func TestRdsBackupSettingKmsKey(t *testing.T) {
	t.Run("nil key ID sets null state", func(t *testing.T) {
		b := &mqlAwsRdsBackupsetting{}
		result, err := b.kmsKey()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, b.KmsKey.IsNull())
		assert.True(t, b.KmsKey.IsSet())
	})
}

func TestRdsProxyVpc(t *testing.T) {
	t.Run("nil VPC ID sets null state", func(t *testing.T) {
		p := &mqlAwsRdsProxy{}
		result, err := p.vpc()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, p.Vpc.IsNull())
		assert.True(t, p.Vpc.IsSet())
	})
}

func TestRdsProxyIamRole(t *testing.T) {
	t.Run("nil role ARN sets null state", func(t *testing.T) {
		p := &mqlAwsRdsProxy{}
		result, err := p.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, p.IamRole.IsNull())
		assert.True(t, p.IamRole.IsSet())
	})
}

func TestRdsEventSubscriptionSnsTopic(t *testing.T) {
	t.Run("empty SNS topic ARN sets null state", func(t *testing.T) {
		e := &mqlAwsRdsEventSubscription{}
		result, err := e.snsTopic()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, e.SnsTopic.IsNull())
		assert.True(t, e.SnsTopic.IsSet())
	})
}

func TestRdsDbInstanceAssociatedRoleIamRole(t *testing.T) {
	t.Run("empty role ARN sets null state", func(t *testing.T) {
		r := &mqlAwsRdsDbinstanceAssociatedRole{}
		result, err := r.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, r.IamRole.IsNull())
		assert.True(t, r.IamRole.IsSet())
	})
}

func TestNewMqlAwsRdsRecommendation(t *testing.T) {
	runtime := testRuntime()
	createdAt := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)

	recommendation := rds_types.DBRecommendation{
		RecommendationId:   aws.String("rec-123"),
		TypeId:             aws.String("engine-version-upgrade"),
		Severity:           aws.String("high"),
		Status:             aws.String("active"),
		CreatedTime:        &createdAt,
		UpdatedTime:        &updatedAt,
		Detection:          aws.String("The instance is not running the latest minor engine version"),
		Recommendation:     aws.String("Upgrade to the latest minor engine version"),
		Description:        aws.String("The latest minor version includes security fixes"),
		Reason:             aws.String("A newer minor engine version is available"),
		Impact:             aws.String("Data security is at risk"),
		Category:           aws.String("security"),
		Source:             aws.String("RDS"),
		TypeDetection:      aws.String("Database resources are not running the latest minor version"),
		TypeRecommendation: aws.String("Upgrade database resources to the latest minor version"),
		AdditionalInfo:     aws.String("Minor upgrades are backward-compatible"),
		Links: []rds_types.DocLink{{
			Text: aws.String("Upgrade documentation"),
			Url:  aws.String("https://docs.aws.amazon.com/rds/"),
		}},
		RecommendedActions: []rds_types.RecommendedAction{{
			ActionId:    aws.String("action-123"),
			Title:       aws.String("Upgrade the instance"),
			Description: aws.String("Modify the DB instance engine version"),
			Operation:   aws.String("ModifyDBInstance"),
			Parameters: []rds_types.RecommendedActionParameter{{
				Key:   aws.String("EngineVersion"),
				Value: aws.String("16.4"),
			}},
			ApplyModes: []string{"immediately", "next-maintenance-window"},
			Status:     aws.String("ready"),
			ContextAttributes: []rds_types.ContextAttribute{{
				Key:   aws.String("CurrentEngineVersion"),
				Value: aws.String("16.3"),
			}},
		}},
	}

	got, err := newMqlAwsRdsRecommendation(runtime, "arn:aws:rds:us-east-1:123456789012:db:test", 0, recommendation)
	require.NoError(t, err)

	assert.Equal(t, "rec-123", got.Id.Data)
	assert.Equal(t, "security", got.Category.Data)
	assert.Equal(t, "high", got.Severity.Data)
	assert.Equal(t, "active", got.Status.Data)
	assert.Equal(t, createdAt, *got.CreatedAt.Data)
	require.Len(t, got.Links.Data, 1)
	assert.Equal(t, "https://docs.aws.amazon.com/rds/", got.Links.Data[0].(map[string]any)["url"])

	require.Len(t, got.Actions.Data, 1)
	action := got.Actions.Data[0].(*mqlAwsRdsRecommendationAction)
	assert.Equal(t, "ModifyDBInstance", action.Operation.Data)
	assert.Equal(t, "16.4", action.Parameters.Data["EngineVersion"])
	assert.Equal(t, "16.3", action.ContextAttributes.Data["CurrentEngineVersion"])
	assert.Equal(t, []any{"immediately", "next-maintenance-window"}, action.ApplyModes.Data)
}

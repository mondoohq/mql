// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	mwaatypes "github.com/aws/aws-sdk-go-v2/service/mwaa/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMwaaLogModules(t *testing.T) {
	assert.Nil(t, mwaaLogModules(nil))

	mods := mwaaLogModules(&mwaatypes.LoggingConfiguration{
		TaskLogs: &mwaatypes.ModuleLoggingConfiguration{
			Enabled:               aws.Bool(true),
			LogLevel:              mwaatypes.LoggingLevelInfo,
			CloudWatchLogGroupArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:airflow-env-Task:*"),
		},
		DagProcessingLogs: &mwaatypes.ModuleLoggingConfiguration{Enabled: aws.Bool(false)},
	})
	require.Len(t, mods, 2, "components the environment reports nothing for are skipped")

	assert.Equal(t, "DagProcessing", mods[0].module)
	require.NotNil(t, mods[0].enabled)
	assert.False(t, *mods[0].enabled)
	assert.Nil(t, mods[0].logLevel, "an unset level reads null")
	assert.Empty(t, mods[0].logGroupArn)

	assert.Equal(t, "Task", mods[1].module)
	assert.True(t, *mods[1].enabled)
	assert.Equal(t, "INFO", *mods[1].logLevel)
	assert.Equal(t, "arn:aws:logs:us-east-1:123456789012:log-group:airflow-env-Task", mods[1].logGroupArn,
		"the trailing log stream wildcard is not part of the log group ARN")
}

func TestMwaaBucketName(t *testing.T) {
	assert.Equal(t, "my-dags", mwaaBucketName("arn:aws:s3:::my-dags"))
	assert.Empty(t, mwaaBucketName("my-dags"))
	assert.Empty(t, mwaaBucketName("arn:aws:iam::123456789012:role/x"))
}

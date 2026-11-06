// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/backupdr/apiv1/backupdrpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestRestoreVerificationCleanup(t *testing.T) {
	// Synthetic: a plan that sets no cleanup rule reads null for both values.
	delay, skip := restoreVerificationCleanup(nil)
	assert.Nil(t, delay)
	assert.Nil(t, skip)

	// Synthetic: a rule with a delay and skip_cleanup left unset keeps skip null
	// rather than reporting false.
	delay, skip = restoreVerificationCleanup(&backupdrpb.RestoreVerificationCleanupRule{
		CleanupDelay: durationpb.New(3600_000_000_000),
	})
	require.NotNil(t, delay)
	assert.Equal(t, int64(3600), *delay)
	assert.Nil(t, skip)

	// Synthetic: skip_cleanup explicitly false is reported as false, not null.
	f := false
	delay, skip = restoreVerificationCleanup(&backupdrpb.RestoreVerificationCleanupRule{SkipCleanup: &f})
	assert.Nil(t, delay)
	require.NotNil(t, skip)
	assert.False(t, *skip)
}

func TestRestoreVerificationPlanDecode(t *testing.T) {
	// Synthetic: the plan as the REST surface of the API documents it; no live
	// plan was available to measure.
	raw := `{
		"name": "projects/p/locations/us-central1/restoreVerificationPlans/daily",
		"state": "ACTIVE",
		"schedule": "0 3 * * *",
		"timeZone": "Europe/Berlin",
		"successCleanupRule": {"cleanupDelay": "600s"},
		"failureCleanupRule": {"skipCleanup": true}
	}`
	var plan backupdrpb.RestoreVerificationPlan
	require.NoError(t, protojson.Unmarshal([]byte(raw), &plan))

	assert.Equal(t, "ACTIVE", plan.State.String())
	assert.Equal(t, "0 3 * * *", plan.Schedule)
	assert.Equal(t, "Europe/Berlin", plan.TimeZone)

	delay, skip := restoreVerificationCleanup(plan.GetSuccessCleanupRule())
	require.NotNil(t, delay)
	assert.Equal(t, int64(600), *delay)
	assert.Nil(t, skip)

	delay, skip = restoreVerificationCleanup(plan.GetFailureCleanupRule())
	assert.Nil(t, delay)
	require.NotNil(t, skip)
	assert.True(t, *skip)
}

func TestRestoreVerificationTriggerError(t *testing.T) {
	// Synthetic: no trigger summary, or a summary without an error, is null.
	assert.Nil(t, restoreVerificationTriggerError(nil))
	assert.Nil(t, restoreVerificationTriggerError(&backupdrpb.TriggerSummary{}))

	// Synthetic: an OK status with no message is not an error.
	assert.Nil(t, restoreVerificationTriggerError(&backupdrpb.TriggerSummary{
		LastTriggerError: &status.Status{},
	}))

	// Synthetic: the message is reported as is.
	msg := restoreVerificationTriggerError(&backupdrpb.TriggerSummary{
		LastTriggerError: &status.Status{Code: 9, Message: "no backup available"},
	})
	require.NotNil(t, msg)
	assert.Equal(t, "no backup available", *msg)

	// Synthetic: a failure carrying only a code still reads as a failure.
	msg = restoreVerificationTriggerError(&backupdrpb.TriggerSummary{
		LastTriggerError: &status.Status{Code: 7},
	})
	require.NotNil(t, msg)
	assert.Equal(t, "PermissionDenied", *msg)
}

func TestRestoreTemplateLastExecution(t *testing.T) {
	// Synthetic: a template that never ran has no summary.
	exec, state := restoreTemplateLastExecution(nil)
	assert.Nil(t, exec)
	assert.Nil(t, state)

	// Synthetic: a summary naming no execution carries only the enum zero,
	// which must not read as a state.
	exec, state = restoreTemplateLastExecution(&backupdrpb.ExecutionSummary{})
	assert.Nil(t, exec)
	assert.Nil(t, state)

	// Synthetic: a failed last execution.
	exec, state = restoreTemplateLastExecution(&backupdrpb.ExecutionSummary{
		LastExecution:      "projects/p/locations/us-central1/restoreTemplates/t/executions/5d437b06",
		LastExecutionState: backupdrpb.RestoreTemplateExecution_FAILED,
	})
	require.NotNil(t, exec)
	require.NotNil(t, state)
	assert.Equal(t, "projects/p/locations/us-central1/restoreTemplates/t/executions/5d437b06", *exec)
	assert.Equal(t, "FAILED", *state)
}

func TestBackupdrResourceName(t *testing.T) {
	name := "projects/p/locations/us-central1/backupVaults/v/dataSources/d"
	// Synthetic: the bare name and both service-prefixed URI forms.
	assert.Equal(t, name, backupdrResourceName(name))
	assert.Equal(t, name, backupdrResourceName("//backupdr.googleapis.com/"+name))
	assert.Equal(t, name, backupdrResourceName("https://backupdr.googleapis.com/v1/"+name))
	assert.Equal(t, "", backupdrResourceName(""))
}

func TestBackupVaultOfDataSource(t *testing.T) {
	// Synthetic: a data source name yields its vault.
	vault, ok := backupVaultOfDataSource("projects/p/locations/us-central1/backupVaults/v/dataSources/d")
	assert.True(t, ok)
	assert.Equal(t, "projects/p/locations/us-central1/backupVaults/v", vault)

	// Synthetic: shapes that name no data source in a vault.
	for _, name := range []string{
		"",
		"projects/p/locations/us-central1/backupVaults/v",
		"projects/p/locations/us-central1/backupVaults/v/dataSources/",
		"projects/p/locations/us-central1/managementServers/m/dataSources/d",
	} {
		_, ok := backupVaultOfDataSource(name)
		assert.False(t, ok, name)
	}
}

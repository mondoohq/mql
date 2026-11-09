// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	athena_types "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/stretchr/testify/assert"
)

func TestAthenaSystemTablesNotConfigured(t *testing.T) {
	// Measured: GetSystemTableConfiguration in an account without a system
	// tables configuration, 2026-11-09, failed with ResourceNotFoundException
	// "No configuration exists for table type ALL." The SDK wraps it in an
	// OperationError, so the check must unwrap.
	notFound := &athena_types.ResourceNotFoundException{Message: aws.String("No configuration exists for table type ALL.")}
	assert.True(t, athenaSystemTablesNotConfigured(notFound))
	assert.True(t, athenaSystemTablesNotConfigured(fmt.Errorf("operation error Athena: GetSystemTableConfiguration: %w", notFound)))

	// Synthetic: other failures are not "disabled".
	assert.False(t, athenaSystemTablesNotConfigured(&athena_types.InvalidRequestException{Message: aws.String("bad")}))
	assert.False(t, athenaSystemTablesNotConfigured(errors.New("connection reset")))
}

func TestAthenaSystemTableStatusMap(t *testing.T) {
	// Measured: `aws athena list-system-table-statuses` in an account without a
	// system tables configuration, 2026-11-09, returned exactly this item.
	measured := athenaSystemTableStatusMap([]athena_types.SystemTableStatus{
		{TableName: athena_types.SystemTableTypeQueryExecutions, Enabled: aws.Bool(false)},
	})
	assert.Equal(t, map[string]any{"QUERY_EXECUTIONS": false}, measured)

	// Synthetic: one enabled and one disabled table, plus an entry without an
	// Enabled value that must be left out rather than read as false.
	got := athenaSystemTableStatusMap([]athena_types.SystemTableStatus{
		{TableName: athena_types.SystemTableTypeQueryExecutions, Enabled: aws.Bool(true)},
		{TableName: "FUTURE_TABLE", Enabled: aws.Bool(false)},
		{TableName: "UNKNOWN_STATE"},
	})
	assert.Equal(t, map[string]any{
		"QUERY_EXECUTIONS": true,
		"FUTURE_TABLE":     false,
	}, got)

	assert.Empty(t, athenaSystemTableStatusMap(nil))
}

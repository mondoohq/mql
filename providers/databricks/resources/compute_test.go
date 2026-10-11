// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWarehouseFields(t *testing.T) {
	decode := func(t *testing.T, raw string) sql.EndpointInfo {
		t.Helper()
		var w sql.EndpointInfo
		require.NoError(t, json.Unmarshal([]byte(raw), &w))
		return w
	}

	t.Run("a warehouse timeout is reported in seconds", func(t *testing.T) {
		got := plainValues(warehouseFields(decode(t, `{
			"id": "abc123",
			"name": "bi",
			"auto_stop_mins": 10,
			"statement_timeout": 3600
		}`)))
		assert.Equal(t, "databricks.warehouse/abc123", got["__id"])
		assert.Equal(t, int64(10), got["autoStopMinutes"])
		assert.Equal(t, int64(3600), got["statementTimeoutSeconds"])
	})

	t.Run("no warehouse timeout is null, not 0", func(t *testing.T) {
		// The workspace STATEMENT_TIMEOUT applies, so 0 would claim statements
		// never time out.
		absent := plainValues(warehouseFields(decode(t, `{"id": "a"}`)))
		assert.Nil(t, absent["statementTimeoutSeconds"])

		zero := plainValues(warehouseFields(decode(t, `{"id": "b", "statement_timeout": 0}`)))
		assert.Nil(t, zero["statementTimeoutSeconds"])
	})
}

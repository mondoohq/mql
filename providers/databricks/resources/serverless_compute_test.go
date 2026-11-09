// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	sdktime "github.com/databricks/databricks-sdk-go/common/types/time"
	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerlessComputeFields(t *testing.T) {
	// Synthetic: the record shape the SDK documents for /api/2.0/serverless-compute.
	t.Run("a populated compute maps every field", func(t *testing.T) {
		created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
		got := plainValues(serverlessComputeFields(compute.ServerlessCompute{
			ServerlessComputeId: "0b7c4f0e-8f61-4b8a-9d0d-6f7c2a1e9a10",
			Name:                "Serverless",
			IsDefault:           true,
			CanUse:              true,
			CreateTime:          sdktime.New(created),
		}))

		assert.Equal(t, "databricks.serverlessCompute/0b7c4f0e-8f61-4b8a-9d0d-6f7c2a1e9a10", got["__id"])
		assert.Equal(t, "0b7c4f0e-8f61-4b8a-9d0d-6f7c2a1e9a10", got["id"])
		assert.Equal(t, "Serverless", got["name"])
		assert.Equal(t, true, got["isDefault"])
		assert.Equal(t, true, got["canUse"])
		assert.Equal(t, false, got["canManage"])
		gotCreated, ok := got["createTime"].(*time.Time)
		require.True(t, ok)
		assert.True(t, created.Equal(*gotCreated))
	})

	// Synthetic: no compute showed a missing creation time.
	t.Run("an absent creation time is null, not the year 1", func(t *testing.T) {
		got := plainValues(serverlessComputeFields(compute.ServerlessCompute{ServerlessComputeId: "x"}))
		assert.Nil(t, got["createTime"])
	})
}

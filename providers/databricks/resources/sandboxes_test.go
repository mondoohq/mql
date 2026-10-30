// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/databricks/databricks-sdk-go/common/types/duration"
	sdktime "github.com/databricks/databricks-sdk-go/common/types/time"
	"github.com/databricks/databricks-sdk-go/service/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandboxFields(t *testing.T) {
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

	t.Run("a running sandbox with a timeout maps every field", func(t *testing.T) {
		got := plainValues(sandboxFields(sandbox.Sandbox{
			Name:        "sandboxes/etl-dev",
			DisplayName: "ETL dev",
			Spec: &sandbox.SandboxSpec{
				Compute: &sandbox.ComputeSpec{
					InactivityTimeout: duration.New(30 * time.Minute),
				},
			},
			Status:     &sandbox.SandboxStatus{State: sandbox.SandboxStateSandboxStateRunning},
			CreateTime: sdktime.New(created),
		}))

		assert.Equal(t, "databricks.sandbox/sandboxes/etl-dev", got["__id"])
		assert.Equal(t, "sandboxes/etl-dev", got["name"])
		assert.Equal(t, "ETL dev", got["displayName"])
		assert.Equal(t, "SANDBOX_STATE_RUNNING", got["state"])
		assert.Equal(t, int64(1800), got["inactivityTimeoutSeconds"])

		gotCreated, ok := got["createTime"].(*time.Time)
		require.True(t, ok)
		assert.True(t, created.Equal(*gotCreated))
		assert.Nil(t, got["updateTime"])
	})

	t.Run("missing status, spec, and timestamps read as null", func(t *testing.T) {
		// A sandbox with no timeout never auto-stops. That must read as null,
		// not as 0 seconds, which a policy checking `< 3600` would pass.
		got := plainValues(sandboxFields(sandbox.Sandbox{Name: "sandboxes/bare"}))

		assert.Nil(t, got["state"])
		assert.Nil(t, got["inactivityTimeoutSeconds"])
		assert.Nil(t, got["createTime"])
		assert.Nil(t, got["updateTime"])
	})

	t.Run("a spec without compute and a zero timeout both read as null", func(t *testing.T) {
		noCompute := plainValues(sandboxFields(sandbox.Sandbox{
			Name: "sandboxes/a",
			Spec: &sandbox.SandboxSpec{},
		}))
		assert.Nil(t, noCompute["inactivityTimeoutSeconds"])

		zero := plainValues(sandboxFields(sandbox.Sandbox{
			Name: "sandboxes/b",
			Spec: &sandbox.SandboxSpec{Compute: &sandbox.ComputeSpec{InactivityTimeout: duration.New(0)}},
		}))
		assert.Nil(t, zero["inactivityTimeoutSeconds"])
	})

	t.Run("an empty status state reads as null rather than an empty string", func(t *testing.T) {
		got := plainValues(sandboxFields(sandbox.Sandbox{
			Name:   "sandboxes/c",
			Status: &sandbox.SandboxStatus{},
		}))
		assert.Nil(t, got["state"])
	})
}

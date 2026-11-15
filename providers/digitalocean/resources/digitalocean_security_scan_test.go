// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRealScan(t *testing.T) {
	// Shape the latest-scan endpoint returns for an account that has never
	// enabled CSPM: no ID, only a status.
	var placeholder godo.Scan
	require.NoError(t, json.Unmarshal([]byte(`{"status":"CSPM_NOT_ENABLED"}`), &placeholder))
	assert.False(t, isRealScan(&placeholder))

	var completed godo.Scan
	require.NoError(t, json.Unmarshal([]byte(`{"id":"00000000-0000-0000-0000-000000000001","status":"COMPLETED"}`), &completed))
	assert.True(t, isRealScan(&completed))

	assert.False(t, isRealScan(nil))
}

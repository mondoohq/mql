// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: public IP entries shaped like GitHub's documented response; no
// target showed these.
func TestHostedRunnerPublicIPs(t *testing.T) {
	got := hostedRunnerPublicIPs([]*github.HostedRunnerPublicIP{
		{Enabled: true, Prefix: "20.80.208.150", Length: 28},
		{Enabled: false, Prefix: "20.80.208.200", Length: 31},
		nil,
		{Enabled: true, Prefix: "", Length: 32},
	})
	assert.Equal(t, []any{"20.80.208.150/28"}, got)
	assert.Empty(t, hostedRunnerPublicIPs(nil))
}

// Synthetic: a runner without machine or image details; no target showed this.
func TestHostedRunnerArgsAbsentDetailsAreNull(t *testing.T) {
	var h github.HostedRunner
	require.NoError(t, json.Unmarshal([]byte(`{"id": 5, "name": "big", "runner_group_id": 2}`), &h))
	args := hostedRunnerArgs("o", &h)
	assert.Equal(t, llx.NilData, args["machineSize"])
	assert.Equal(t, llx.NilData, args["cpuCores"], "an absent machine size is null, not 0 cores")
	assert.Equal(t, llx.NilData, args["imageId"])
	assert.Equal(t, llx.NilData, args["publicIpEnabled"])

	require.NoError(t, json.Unmarshal([]byte(`{"id": 5, "machine_size_details": {"id": "8-core", "cpu_cores": 8, "memory_gb": 32, "storage_gb": 300}}`), &h))
	args = hostedRunnerArgs("o", &h)
	assert.Equal(t, "8-core", args["machineSize"].Value)
	assert.Equal(t, int64(32), args["memoryGb"].Value)
	assert.NotEqual(t, hostedRunnerArgs("a", &h)["__id"].Value, hostedRunnerArgs("b", &h)["__id"].Value)
}

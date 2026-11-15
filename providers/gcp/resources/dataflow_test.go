// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	dataflow "google.golang.org/api/dataflow/v1b3"
)

func TestDataflowWorkerIpConfiguration(t *testing.T) {
	// Measured: two streaming jobs (2026-11-15) read with JOB_VIEW_DESCRIPTION.
	// The one launched with --disable-public-ips carried WORKER_IP_PRIVATE on
	// its worker pool; the default one carried no ipConfiguration at all.
	t.Run("private worker IPs", func(t *testing.T) {
		env := &dataflow.Environment{WorkerPools: []*dataflow.WorkerPool{{IpConfiguration: "WORKER_IP_PRIVATE"}}}
		assert.Equal(t, "WORKER_IP_PRIVATE", dataflowWorkerIpConfiguration(env))
	})
	t.Run("default worker IPs leave the field unset", func(t *testing.T) {
		env := &dataflow.Environment{WorkerPools: []*dataflow.WorkerPool{{}}}
		assert.Equal(t, "", dataflowWorkerIpConfiguration(env))
	})
	// Synthetic: shapes no target showed.
	t.Run("first pool that sets it wins", func(t *testing.T) {
		env := &dataflow.Environment{WorkerPools: []*dataflow.WorkerPool{nil, {}, {IpConfiguration: "WORKER_IP_PUBLIC"}}}
		assert.Equal(t, "WORKER_IP_PUBLIC", dataflowWorkerIpConfiguration(env))
	})
	t.Run("no environment", func(t *testing.T) {
		assert.Equal(t, "", dataflowWorkerIpConfiguration(nil))
	})
}

func TestDataflowEnvironmentSummary(t *testing.T) {
	// Measured shape: a streaming job read with JOB_VIEW_DESCRIPTION
	// (2026-11-15) carried sdkPipelineOptions, userAgent and worker pool
	// metadata next to the settings below. The secret-looking values are
	// synthetic.
	env := &dataflow.Environment{
		ServiceAccountEmail: "sa@example.iam.gserviceaccount.com",
		ServiceKmsKeyName:   "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		SdkPipelineOptions:  []byte(`{"options":{"dbPassword":"hunter2"}}`),
		UserAgent:           []byte(`{"name":"Apache Beam SDK for Java"}`),
		InternalExperiments: []byte(`{"token":"abc"}`),
		Experiments:         []string{"secret_flag=abc"},
		WorkerPools: []*dataflow.WorkerPool{{
			IpConfiguration: "WORKER_IP_PRIVATE",
			Network:         "vpc",
			Metadata:        map[string]string{"startup": "export TOKEN=abc"},
			PoolArgs:        []byte(`{"token":"abc"}`),
		}, nil},
	}
	m, err := convert.JsonToDict(dataflowEnvironmentSummary(env))
	require.NoError(t, err)
	assert.Equal(t, "sa@example.iam.gserviceaccount.com", m["serviceAccountEmail"])
	assert.Equal(t, "projects/p/locations/l/keyRings/r/cryptoKeys/k", m["serviceKmsKeyName"])
	for _, k := range []string{"sdkPipelineOptions", "userAgent", "internalExperiments", "experiments"} {
		assert.NotContains(t, m, k)
	}
	pools := m["workerPools"].([]any)
	require.Len(t, pools, 1)
	pool := pools[0].(map[string]any)
	assert.Equal(t, "WORKER_IP_PRIVATE", pool["ipConfiguration"])
	assert.NotContains(t, pool, "metadata")
	assert.NotContains(t, pool, "poolArgs")

	// Synthetic: the default, public worker IPs leave ipConfiguration unset.
	m, err = convert.JsonToDict(dataflowEnvironmentSummary(&dataflow.Environment{WorkerPools: []*dataflow.WorkerPool{{}}}))
	require.NoError(t, err)
	assert.NotContains(t, m["workerPools"].([]any)[0].(map[string]any), "ipConfiguration")
}

func TestDataflowPipelineSummary(t *testing.T) {
	// Synthetic: display data with a launch argument on the pipeline and on a transform.
	pd := &dataflow.PipelineDescription{
		StepNamesHash: "h",
		DisplayData:   []*dataflow.DisplayData{{Key: "jdbcUrl", StrValue: "jdbc:postgresql://db?password=hunter2"}},
		OriginalPipelineTransform: []*dataflow.TransformSummary{{
			Id: "t1", Name: "Read", Kind: "PAR_DO_KIND",
			DisplayData: []*dataflow.DisplayData{{Key: "token", StrValue: "abc"}},
		}},
		ExecutionPipelineStage: []*dataflow.ExecutionStageSummary{{Id: "s1", Name: "F0", Kind: "PAR_DO_KIND"}},
	}
	m, err := convert.JsonToDict(dataflowPipelineSummary(pd))
	require.NoError(t, err)
	assert.Equal(t, "h", m["stepNamesHash"])
	assert.NotContains(t, m, "displayData")
	tr := m["originalPipelineTransform"].([]any)[0].(map[string]any)
	assert.Equal(t, "Read", tr["name"])
	assert.NotContains(t, tr, "displayData")
	assert.Len(t, m["executionPipelineStage"].([]any), 1)
}

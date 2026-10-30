// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/dataproc/v1"
)

func TestDetermineDataprocJobType(t *testing.T) {
	t.Run("hadoop job", func(t *testing.T) {
		job := &dataproc.Job{HadoopJob: &dataproc.HadoopJob{}}
		assert.Equal(t, "hadoop", determineDataprocJobType(job))
	})

	t.Run("spark job", func(t *testing.T) {
		job := &dataproc.Job{SparkJob: &dataproc.SparkJob{}}
		assert.Equal(t, "spark", determineDataprocJobType(job))
	})

	t.Run("pyspark job", func(t *testing.T) {
		job := &dataproc.Job{PysparkJob: &dataproc.PySparkJob{}}
		assert.Equal(t, "pyspark", determineDataprocJobType(job))
	})

	t.Run("hive job", func(t *testing.T) {
		job := &dataproc.Job{HiveJob: &dataproc.HiveJob{}}
		assert.Equal(t, "hive", determineDataprocJobType(job))
	})

	t.Run("pig job", func(t *testing.T) {
		job := &dataproc.Job{PigJob: &dataproc.PigJob{}}
		assert.Equal(t, "pig", determineDataprocJobType(job))
	})

	t.Run("sparkR job", func(t *testing.T) {
		job := &dataproc.Job{SparkRJob: &dataproc.SparkRJob{}}
		assert.Equal(t, "sparkR", determineDataprocJobType(job))
	})

	t.Run("sparkSql job", func(t *testing.T) {
		job := &dataproc.Job{SparkSqlJob: &dataproc.SparkSqlJob{}}
		assert.Equal(t, "sparkSql", determineDataprocJobType(job))
	})

	t.Run("presto job", func(t *testing.T) {
		job := &dataproc.Job{PrestoJob: &dataproc.PrestoJob{}}
		assert.Equal(t, "presto", determineDataprocJobType(job))
	})

	t.Run("flink job", func(t *testing.T) {
		job := &dataproc.Job{FlinkJob: &dataproc.FlinkJob{}}
		assert.Equal(t, "flink", determineDataprocJobType(job))
	})

	t.Run("trino job", func(t *testing.T) {
		job := &dataproc.Job{TrinoJob: &dataproc.TrinoJob{}}
		assert.Equal(t, "trino", determineDataprocJobType(job))
	})

	t.Run("unknown job type", func(t *testing.T) {
		job := &dataproc.Job{}
		assert.Equal(t, "unknown", determineDataprocJobType(job))
	})

	t.Run("first match wins when multiple set", func(t *testing.T) {
		job := &dataproc.Job{
			HadoopJob: &dataproc.HadoopJob{},
			SparkJob:  &dataproc.SparkJob{},
		}
		assert.Equal(t, "hadoop", determineDataprocJobType(job))
	})
}

func TestNodePoolTargetToMql(t *testing.T) {
	t.Run("nil NodePoolConfig does not panic", func(t *testing.T) {
		npt := &dataproc.GkeNodePoolTarget{
			NodePool:       "my-pool",
			NodePoolConfig: nil,
			Roles:          []string{"DEFAULT"},
		}
		result := nodePoolTargetToMql(npt)
		assert.Equal(t, "my-pool", result.NodePool)
		assert.Equal(t, []string{"DEFAULT"}, result.Roles)
	})

	t.Run("nil Config and Autoscaling within NodePoolConfig", func(t *testing.T) {
		npt := &dataproc.GkeNodePoolTarget{
			NodePool: "my-pool",
			NodePoolConfig: &dataproc.GkeNodePoolConfig{
				Config:      nil,
				Autoscaling: nil,
				Locations:   []string{"us-central1-a"},
			},
			Roles: []string{"DEFAULT"},
		}
		result := nodePoolTargetToMql(npt)
		assert.Equal(t, "my-pool", result.NodePool)
		assert.Equal(t, []string{"us-central1-a"}, result.NodePoolConfig.Locations)
	})

	t.Run("fully populated does not panic", func(t *testing.T) {
		npt := &dataproc.GkeNodePoolTarget{
			NodePool: "my-pool",
			NodePoolConfig: &dataproc.GkeNodePoolConfig{
				Config: &dataproc.GkeNodeConfig{
					MachineType: "e2-standard-4",
					Accelerators: []*dataproc.GkeNodePoolAcceleratorConfig{
						{AcceleratorCount: 1, AcceleratorType: "nvidia-tesla-t4"},
					},
				},
				Autoscaling: &dataproc.GkeNodePoolAutoscalingConfig{
					MinNodeCount: 1,
					MaxNodeCount: 10,
				},
			},
			Roles: []string{"DEFAULT"},
		}
		result := nodePoolTargetToMql(npt)
		assert.Equal(t, "e2-standard-4", result.NodePoolConfig.Config.MachineType)
		assert.Equal(t, int64(1), result.NodePoolConfig.Autoscaling.MinNodeCount)
		assert.Equal(t, int64(10), result.NodePoolConfig.Autoscaling.MaxNodeCount)
		assert.Len(t, result.NodePoolConfig.Config.Accelerators, 1)
	})
}

func TestDataprocResourceNameFromUri(t *testing.T) {
	cases := map[string]string{
		"https://dataproc.googleapis.com/v1/projects/p/regions/r/autoscalingPolicies/ap": "projects/p/regions/r/autoscalingPolicies/ap",
		"projects/p/regions/r/autoscalingPolicies/ap":                                    "projects/p/regions/r/autoscalingPolicies/ap",
		"just-a-name": "just-a-name",
		"":            "",
	}
	for in, want := range cases {
		assert.Equal(t, want, dataprocResourceNameFromUri(in), "dataprocResourceNameFromUri(%q)", in)
	}
}

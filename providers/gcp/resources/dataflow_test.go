// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

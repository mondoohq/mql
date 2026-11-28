// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	neptunegraph_types "github.com/aws/aws-sdk-go-v2/service/neptunegraph/types"
	"github.com/stretchr/testify/assert"
)

// Synthetic: compute configuration shapes from the API model; no live graph session was scanned.
func TestNeptuneGraphCompute(t *testing.T) {
	t.Run("provisioned graph", func(t *testing.T) {
		kind, minMem := neptuneGraphCompute(&neptunegraph_types.ComputeConfigurationMemberProvisionedGraph{
			Value: neptunegraph_types.ProvisionedGraphConfiguration{Memory: aws.Int32(128)},
		})
		assert.Equal(t, "ProvisionedGraph", kind.Value)
		assert.Nil(t, minMem.Value)
	})

	t.Run("graph session", func(t *testing.T) {
		kind, minMem := neptuneGraphCompute(&neptunegraph_types.ComputeConfigurationMemberGraphSession{
			Value: neptunegraph_types.GraphSessionConfiguration{MinMemory: aws.Int32(8)},
		})
		assert.Equal(t, "GraphSession", kind.Value)
		assert.Equal(t, int64(8), minMem.Value)
	})

	t.Run("graph session without minimum", func(t *testing.T) {
		kind, minMem := neptuneGraphCompute(&neptunegraph_types.ComputeConfigurationMemberGraphSession{})
		assert.Equal(t, "GraphSession", kind.Value)
		assert.Nil(t, minMem.Value)
	})

	t.Run("not reported", func(t *testing.T) {
		kind, minMem := neptuneGraphCompute(nil)
		assert.Nil(t, kind.Value)
		assert.Nil(t, minMem.Value)
	})

	t.Run("kind the SDK does not know", func(t *testing.T) {
		kind, _ := neptuneGraphCompute(&neptunegraph_types.UnknownUnionMember{Tag: "serverless"})
		assert.Equal(t, "serverless", kind.Value)
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestPrioritizeNode(t *testing.T) {
	// ┌──────┐┌───┐
	// │eq1   ││eq2│
	// └┬────┬┘└──┬┘
	// ┌▽──┐┌▽──┐┌▽──┐
	// │dp1││dp2││dp3│
	// └─┬┬┘└─┬┬┘└┬─┬┘
	//   ││   ││  │ │
	//  ┌││───││──┘ │
	//  ││└──┐││    │
	//  ││┌──│┘│    │
	// ┌▽▽▽┐┌▽─▽┐┌──▽┐
	// │dps││rj1││rj2│
	// └───┘└┬──┘└┬──┘
	// ┌─────▽────▽┐
	// │scores     │
	// └───────────┘

	nodes := map[NodeID]*Node{
		"eq1":    {id: "eq1"},
		"eq2":    {id: "eq1"},
		"dp1":    {id: "eq1"},
		"dp2":    {id: "eq1"},
		"dp3":    {id: "eq1"},
		"rj1":    {id: "rj1"},
		"rj2":    {id: "rj2"},
		"scores": {id: "scores"},
		"dps":    {id: "dps"},
	}
	edges := map[NodeID][]NodeID{
		"eq1": {"dp1", "dp2"},
		"eq2": {"dp3"},
		"dp1": {"rj1", "dps"},
		"dp2": {"rj1", "dps"},
		"dp3": {"rj2", "dps"},
		"rj1": {"scores"},
		"rj2": {"scores"},
	}

	priorityMap := map[NodeID]int{}
	for n := range nodes {
		prioritizeNode(nodes, edges, priorityMap, n)
	}

	require.Equal(t, len(nodes), len(priorityMap))
	assert.Equal(t, 1, priorityMap["scores"])
	assert.Equal(t, 1, priorityMap["dps"])
	assert.Greater(t, priorityMap["eq1"], priorityMap["dp1"])
	assert.Greater(t, priorityMap["eq1"], priorityMap["dp2"])
	assert.Greater(t, priorityMap["eq2"], priorityMap["dp3"])
	assert.Greater(t, priorityMap["dp1"], priorityMap["dps"])
	assert.Greater(t, priorityMap["dp1"], priorityMap["rj1"])
	assert.Greater(t, priorityMap["dp2"], priorityMap["dps"])
	assert.Greater(t, priorityMap["dp2"], priorityMap["rj1"])
	assert.Greater(t, priorityMap["dp3"], priorityMap["dps"])
	assert.Greater(t, priorityMap["dp3"], priorityMap["rj2"])
	assert.Greater(t, priorityMap["rj1"], priorityMap["scores"])
	assert.Greater(t, priorityMap["rj2"], priorityMap["scores"])
}

func TestBuilder(t *testing.T) {
	b := NewBuilder()

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "propertyquery",
				Blocks: []*llx.Block{{
					Entrypoints: []uint64{1},
					Datapoints:  []uint64{2},
				}},
				Checksums: map[uint64]string{1: "checksum1", 2: "pqep"},
			},
		}, nil, nil)

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "query1",
				Blocks: []*llx.Block{{
					Entrypoints: []uint64{1},
				}},
				Checksums: map[uint64]string{1: "checksum2"},
			},
		}, map[string]string{"prop": "checksum1"}, nil)

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "query2",
				Blocks: []*llx.Block{{
					Entrypoints: []uint64{1},
					Datapoints:  []uint64{2},
				}},
				Checksums: map[uint64]string{1: "checksum3", 2: "checksum4"},
			},
		}, nil, map[string]*llx.Primitive{
			"resolvedprop": llx.StringPrimitive("hello"),
		})
	b.AddDatapointType("checksum3", string(types.Bool))

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "query3",
				Blocks: []*llx.Block{{
					Datapoints: []uint64{1},
				}},
				Checksums: map[uint64]string{1: "checksum5"},
			},
		}, nil, nil)
	b.CollectDatapoint("checksum5")

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "query4",
				Blocks: []*llx.Block{{
					Datapoints: []uint64{1},
				}},
				Checksums: map[uint64]string{1: "checksum6"},
			},
		}, nil, nil)

	b.AddQuery(
		&llx.CodeBundle{
			CodeV2: &llx.CodeV2{
				Id: "query5",
				Blocks: []*llx.Block{{
					Datapoints: []uint64{1, 2},
				}},
				Checksums: map[uint64]string{1: "checksum5", 2: "checksum7"},
			},
		}, nil, nil)

	ge, err := b.Build(nil, nil, "assetMrn")
	require.NoError(t, err)

	hasNode(t, ge, "execution_query/propertyquery", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/propertyquery", "checksum1", "pqep")

	hasNode(t, ge, "execution_query/query1", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/query1", "checksum2")

	hasNode(t, ge, "execution_query/query2", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/query2", "checksum3", "checksum4")

	hasNode(t, ge, "execution_query/query3", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/query3", "checksum5")

	hasNode(t, ge, "execution_query/query4", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/query4", "checksum6")

	hasNode(t, ge, "execution_query/query5", ExecutionQueryNodeType)
	hasOutEdges(t, ge, "execution_query/query5", "checksum5", "checksum7")

	hasNode(t, ge, "pqep", DatapointNodeType)
	hasOutEdges(t, ge, "pqep", CollectionFinisherID)

	hasNode(t, ge, "checksum1", DatapointNodeType)
	hasOutEdges(t, ge, "checksum1", "execution_query/query1", CollectionFinisherID)

	hasNode(t, ge, "checksum2", DatapointNodeType)
	hasOutEdges(t, ge, "checksum2", CollectionFinisherID)

	hasNode(t, ge, "checksum3", DatapointNodeType)
	hasOutEdges(t, ge, "checksum3", CollectionFinisherID)

	hasNode(t, ge, "checksum4", DatapointNodeType)
	hasOutEdges(t, ge, "checksum4", CollectionFinisherID)

	hasNode(t, ge, "checksum5", DatapointNodeType)
	hasOutEdges(t, ge, "checksum5", DatapointCollectorID, CollectionFinisherID)

	hasNode(t, ge, "checksum6", DatapointNodeType)
	hasOutEdges(t, ge, "checksum6", CollectionFinisherID)

	hasNode(t, ge, "checksum7", DatapointNodeType)
	hasOutEdges(t, ge, "checksum7", CollectionFinisherID)
}

func hasNode(t *testing.T, ge *GraphExecutor, nodeID NodeID, nodeType NodeType) {
	t.Helper()
	if assert.Contains(t, ge.nodes, nodeID) {
		assert.Equal(t, nodeType, ge.nodes[nodeID].nodeType)
	}
}

func hasOutEdges(t *testing.T, ge *GraphExecutor, nodeID NodeID, edges ...NodeID) {
	t.Helper()
	require.Len(t, ge.edges[nodeID], len(edges))
	assert.ElementsMatch(t, ge.edges[nodeID], edges)
}

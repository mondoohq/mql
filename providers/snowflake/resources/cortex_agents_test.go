// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: shaped after the agent specification in Snowflake's CREATE AGENT
// reference, as JSON the way DESCRIBE AGENT returns it. No test account had an
// agent.
const testAgentSpec = `{
	"models": {"orchestration": "claude-4-sonnet"},
	"orchestration": {"budget": {"seconds": 30, "tokens": 16000}},
	"instructions": {"response": "Be brief."},
	"tools": [
		{"tool_spec": {"type": "cortex_analyst_text_to_sql", "name": "Analyst1", "description": "Sales data"}},
		{"tool_spec": {"type": "cortex_search", "name": "Search1", "description": "Docs"}},
		{"tool_spec": {"type": "generic", "name": "Lookup", "description": "Custom lookup"}}
	],
	"tool_resources": {
		"Analyst1": {"semantic_view": "DB.SCH.SALES_SV", "execution_environment": {"type": "warehouse", "warehouse": "ANALYST_WH"}},
		"Search1": {"name": "DB.SCH.DOCS_SEARCH", "max_results": 5},
		"Lookup": {"type": "function", "identifier": "DB.SCH.LOOKUP", "execution_environment": {"type": "warehouse", "warehouse": "TOOLS_WH"}}
	}
}`

func TestParseCortexAgentSpec(t *testing.T) {
	spec, err := parseCortexAgentSpec(testAgentSpec)
	require.NoError(t, err)

	assert.Equal(t, "claude-4-sonnet", spec.Models.Orchestration)
	require.NotNil(t, spec.Orchestration.Budget.Seconds)
	assert.Equal(t, int64(30), *spec.Orchestration.Budget.Seconds)
	require.NotNil(t, spec.Orchestration.Budget.Tokens)
	assert.Equal(t, int64(16000), *spec.Orchestration.Budget.Tokens)

	require.Len(t, spec.Tools, 3)
	assert.Equal(t, cortexAgentToolSpec{Type: "cortex_search", Name: "Search1", Description: "Docs"}, spec.Tools[1].ToolSpec)

	assert.Equal(t, "", cortexAgentToolSearchService(spec.ToolResources["Analyst1"]))
	assert.Equal(t, "ANALYST_WH", cortexAgentToolWarehouse(spec.ToolResources["Analyst1"]))
	assert.Equal(t, "DB.SCH.DOCS_SEARCH", cortexAgentToolSearchService(spec.ToolResources["Search1"]))
	assert.Equal(t, "", cortexAgentToolWarehouse(spec.ToolResources["Search1"]))
	assert.Equal(t, "TOOLS_WH", cortexAgentToolWarehouse(spec.ToolResources["Lookup"]))
}

func TestParseCortexAgentSpecMinimal(t *testing.T) {
	// Synthetic: an agent with only instructions has no model, budget, or tools.
	spec, err := parseCortexAgentSpec(`{"instructions": {"response": "hi"}}`)
	require.NoError(t, err)
	assert.Equal(t, "", spec.Models.Orchestration)
	assert.Nil(t, spec.Orchestration.Budget.Seconds, "absent budget is null, not 0")
	assert.Nil(t, spec.Orchestration.Budget.Tokens)
	assert.Empty(t, spec.Tools)

	empty, err := parseCortexAgentSpec("")
	require.NoError(t, err)
	assert.Empty(t, empty.Tools)

	_, err = parseCortexAgentSpec("{not json")
	assert.Error(t, err)
}

func TestCortexAgentToolSearchService(t *testing.T) {
	// Synthetic: both keys a specification may use.
	assert.Equal(t, "DB.SCH.SVC", cortexAgentToolSearchService(map[string]any{"search_service": "DB.SCH.SVC"}))
	assert.Equal(t, "DB.SCH.SVC", cortexAgentToolSearchService(map[string]any{"name": "DB.SCH.SVC"}))
	assert.Equal(t, "", cortexAgentToolSearchService(map[string]any{"name": "Search1"}), "a bare name is not a service reference")
	assert.Equal(t, "", cortexAgentToolSearchService(map[string]any{"search_service": 5}))
	assert.Equal(t, "", cortexAgentToolSearchService(nil))
}

func TestCortexAgentToolWarehouse(t *testing.T) {
	assert.Equal(t, "", cortexAgentToolWarehouse(map[string]any{"execution_environment": "WH"}))
	assert.Equal(t, "", cortexAgentToolWarehouse(map[string]any{"execution_environment": map[string]any{"type": "warehouse"}}))
	assert.Equal(t, "", cortexAgentToolWarehouse(nil))
}

func TestSplitObjectFQN(t *testing.T) {
	ref, ok := splitObjectFQN("db.sch.svc")
	require.True(t, ok)
	assert.Equal(t, [3]string{"db", "sch", "svc"}, ref)

	ref, ok = splitObjectFQN(`"My DB"."S.1".SVC`)
	require.True(t, ok)
	assert.Equal(t, [3]string{"My DB", "S.1", "SVC"}, ref)

	_, ok = splitObjectFQN("sch.svc")
	assert.False(t, ok)
	_, ok = splitObjectFQN("a.b.c.d")
	assert.False(t, ok)
	_, ok = splitObjectFQN("a..c")
	assert.False(t, ok)
	_, ok = splitObjectFQN("")
	assert.False(t, ok)
}

func TestSameObjectFQN(t *testing.T) {
	ref, _ := splitObjectFQN("db.sch.docs_search")
	assert.True(t, sameObjectFQN(ref, "DB", "SCH", "DOCS_SEARCH"), "unquoted names resolve case-insensitively")
	assert.False(t, sameObjectFQN(ref, "DB", "OTHER", "DOCS_SEARCH"))
	assert.False(t, sameObjectFQN(ref, "DB", "SCH", "DOCS"))
}

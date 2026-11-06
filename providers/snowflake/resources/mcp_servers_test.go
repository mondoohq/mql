// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMcpServerSpec(t *testing.T) {
	// Synthetic: shaped after Snowflake's CREATE MCP SERVER reference, as the
	// JSON DESCRIBE MCP SERVER returns. No test account had an MCP server.
	spec, err := parseMcpServerSpec(`{"tools": [
		{"title": "SQL", "name": "sql_exec_tool", "type": "SYSTEM_EXECUTE_SQL", "description": "Runs SQL."},
		{"title": "Docs", "name": "docs", "type": "CORTEX_SEARCH_SERVICE_QUERY", "identifier": "DB.SCH.DOCS_SEARCH"},
		{"title": "Fn", "name": "fn", "type": "GENERIC", "identifier": "DB.SCH.FN", "config": {"type": "function", "warehouse": "WH", "input_schema": {"type": "object"}}}
	]}`)
	require.NoError(t, err)
	require.Len(t, spec.Tools, 3)

	sql := spec.Tools[0]
	assert.Equal(t, "sql_exec_tool", sql.Name)
	assert.Equal(t, "SQL", sql.Title)
	assert.Equal(t, "SYSTEM_EXECUTE_SQL", sql.Type)
	assert.Equal(t, "Runs SQL.", sql.Description)
	assert.Equal(t, "", sql.Identifier)
	assert.Nil(t, sql.Config)

	assert.Equal(t, "DB.SCH.DOCS_SEARCH", spec.Tools[1].Identifier)
	assert.Equal(t, "WH", spec.Tools[2].Config["warehouse"])
	assert.Equal(t, map[string]any{"type": "object"}, spec.Tools[2].Config["input_schema"])
}

func TestParseMcpServerSpecEmpty(t *testing.T) {
	spec, err := parseMcpServerSpec("")
	require.NoError(t, err)
	assert.Empty(t, spec.Tools)

	_, err = parseMcpServerSpec("tools: [")
	assert.Error(t, err)
}

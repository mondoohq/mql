// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestElasticPoolNameFromID(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, elasticPoolNameFromID(nil))
	})
	t.Run("full ARM id returns last segment", func(t *testing.T) {
		id := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/elasticPools/mypool"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "mypool", *got)
	})
	t.Run("bare name returns itself", func(t *testing.T) {
		id := "mypool"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "mypool", *got)
	})
	t.Run("empty string returns empty", func(t *testing.T) {
		id := ""
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "", *got)
	})
	t.Run("trailing slash returns empty last segment", func(t *testing.T) {
		id := "/subscriptions/sub/elasticPools/"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "", *got)
	})
}

func TestParseSqlVulnerabilityAssessmentState(t *testing.T) {
	// Measured: GET .../sqlVulnerabilityAssessments/default, api-version
	// 2025-01-01, Azure SQL Database logical server, 2026-11-14.
	t.Run("enabled", func(t *testing.T) {
		body := `{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/sqlVulnerabilityAssessments/Default","name":"Default","properties":{"state":"Enabled"},"type":"Microsoft.Sql/servers/sqlVulnerabilityAssessments"}`
		got, err := parseSqlVulnerabilityAssessmentState([]byte(body))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, *got)
	})
	// Measured: same request against a server without express configuration.
	t.Run("disabled", func(t *testing.T) {
		body := `{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/sqlVulnerabilityAssessments/Default","name":"Default","properties":{"state":"Disabled"},"type":"Microsoft.Sql/servers/sqlVulnerabilityAssessments"}`
		got, err := parseSqlVulnerabilityAssessmentState([]byte(body))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.False(t, *got)
	})
	// Synthetic: the state casing differs; no target showed this.
	t.Run("state is matched case-insensitively", func(t *testing.T) {
		got, err := parseSqlVulnerabilityAssessmentState([]byte(`{"properties":{"state":"enabled"}}`))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, *got)
	})
	// Synthetic: response without properties or state; no target showed this.
	t.Run("absent state is null", func(t *testing.T) {
		got, err := parseSqlVulnerabilityAssessmentState([]byte(`{"name":"Default"}`))
		require.NoError(t, err)
		assert.Nil(t, got)
		got, err = parseSqlVulnerabilityAssessmentState([]byte(`{"properties":{}}`))
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	// Synthetic: a state outside the documented Enabled/Disabled; no target showed this.
	t.Run("unknown state is an error", func(t *testing.T) {
		got, err := parseSqlVulnerabilityAssessmentState([]byte(`{"properties":{"state":"Pending"}}`))
		assert.Error(t, err)
		assert.Nil(t, got)
	})
	// Synthetic: malformed body; no target showed this.
	t.Run("malformed body is an error", func(t *testing.T) {
		_, err := parseSqlVulnerabilityAssessmentState([]byte(`<html>`))
		assert.Error(t, err)
	})
}

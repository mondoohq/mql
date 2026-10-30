// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstanceSettingsFrom(t *testing.T) {
	f, tr := false, true

	// Measured: audit.json, a local n8n 2.44.6 with default settings, 2026-10-25.
	reports, err := decodeAudit(fixture(t, "audit.json"))
	require.NoError(t, err)
	s, ok := InstanceSettingsFrom(reports)
	require.True(t, ok)
	assert.Equal(t, InstanceSettings{
		CommunityPackagesEnabled:    &tr,
		PublicAPIEnabled:            &tr,
		TemplatesEnabled:            &tr,
		VersionNotificationsEnabled: &tr,
		DiagnosticsEnabled:          &f,
		ExcludedNodes:               []string{"n8n-nodes-base.executeCommand", "n8n-nodes-base.localFileTrigger", "n8n-nodes-base.e2eTest", "n8n-nodes-base.dynamicCredentialCheck"},
		IncludedNodes:               []string{},
	}, s)

	// Measured: audit-hardened.json, the same release started with community
	// packages, templates, and version notifications off, diagnostics on, and
	// NODES_EXCLUDE set. A custom exclude list replaces the default one, so
	// localFileTrigger is no longer excluded.
	reports, err = decodeAudit(fixture(t, "audit-hardened.json"))
	require.NoError(t, err)
	s, ok = InstanceSettingsFrom(reports)
	require.True(t, ok)
	assert.Equal(t, InstanceSettings{
		CommunityPackagesEnabled:    &f,
		PublicAPIEnabled:            &tr,
		TemplatesEnabled:            &f,
		VersionNotificationsEnabled: &f,
		DiagnosticsEnabled:          &tr,
		ExcludedNodes:               []string{"n8n-nodes-base.executeCommand", "n8n-nodes-base.code", "n8n-nodes-base.ssh", "n8n-nodes-base.e2eTest", "n8n-nodes-base.dynamicCredentialCheck"},
		IncludedNodes:               []string{},
	}, s)
}

func TestInstanceSettingsFromWithoutFinding(t *testing.T) {
	// Synthetic: an audit with no instance report, as when it finds no risk.
	_, ok := InstanceSettingsFrom([]AuditReport{{Risk: "credentials", Sections: []AuditSection{{Title: "x"}}}})
	assert.False(t, ok)
	_, ok = InstanceSettingsFrom(nil)
	assert.False(t, ok)
}

func TestInstanceSettingsNodeAllowlist(t *testing.T) {
	// Synthetic: NODES_INCLUDE set; the local instances never had one.
	s, ok := InstanceSettingsFrom([]AuditReport{{Risk: "instance", Sections: []AuditSection{{
		Title: "Security settings",
		Settings: map[string]any{
			"features": map[string]any{},
			"nodes":    map[string]any{"nodesExclude": "none", "nodesInclude": "n8n-nodes-base.webhook, n8n-nodes-base.set"},
		},
	}}}})
	require.True(t, ok)
	assert.Equal(t, []string{}, s.ExcludedNodes)
	assert.Equal(t, []string{"n8n-nodes-base.webhook", "n8n-nodes-base.set"}, s.IncludedNodes)
	assert.Nil(t, s.CommunityPackagesEnabled)
}

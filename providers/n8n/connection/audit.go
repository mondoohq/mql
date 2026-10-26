// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

// InstanceSettings are the security-relevant instance settings the audit's
// instance report lists in its "Security settings" finding. They come from
// the instance's environment (N8N_COMMUNITY_PACKAGES_ENABLED, NODES_EXCLUDE,
// and so on). Booleans the report leaves out stay nil.
type InstanceSettings struct {
	CommunityPackagesEnabled    *bool
	PublicAPIEnabled            *bool
	TemplatesEnabled            *bool
	VersionNotificationsEnabled *bool
	DiagnosticsEnabled          *bool
	ExcludedNodes               []string
	IncludedNodes               []string
}

// InstanceSettingsFrom finds the instance settings in an audit. It reports
// false when the audit has no settings finding.
//
// The finding's settings, measured on n8n 2.44.6:
//
//	{"features": {"communityPackagesEnabled": true, "versionNotificationsEnabled": true,
//	              "templatesEnabled": true, "publicApiEnabled": true},
//	 "nodes": {"nodesExclude": "n8n-nodes-base.executeCommand, ...", "nodesInclude": "none"},
//	 "telemetry": {"diagnosticsEnabled": false}}
func InstanceSettingsFrom(reports []AuditReport) (InstanceSettings, bool) {
	for _, r := range reports {
		if r.Risk != "instance" {
			continue
		}
		for _, s := range r.Sections {
			features, ok := s.Settings["features"].(map[string]any)
			if !ok {
				continue
			}
			nodes, _ := s.Settings["nodes"].(map[string]any)
			telemetry, _ := s.Settings["telemetry"].(map[string]any)
			return InstanceSettings{
				CommunityPackagesEnabled:    optBool(features, "communityPackagesEnabled"),
				PublicAPIEnabled:            optBool(features, "publicApiEnabled"),
				TemplatesEnabled:            optBool(features, "templatesEnabled"),
				VersionNotificationsEnabled: optBool(features, "versionNotificationsEnabled"),
				DiagnosticsEnabled:          optBool(telemetry, "diagnosticsEnabled"),
				ExcludedNodes:               nodeList(nodes, "nodesExclude"),
				IncludedNodes:               nodeList(nodes, "nodesInclude"),
			}, true
		}
	}
	return InstanceSettings{}, false
}

func optBool(m map[string]any, key string) *bool {
	b, ok := m[key].(bool)
	if !ok {
		return nil
	}
	return &b
}

// nodeList reads a node type list from the report. The report writes "none"
// for an unset list.
func nodeList(m map[string]any, key string) []string {
	s, _ := m[key].(string)
	if s == "none" {
		return []string{}
	}
	out := splitList(s)
	if out == nil {
		out = []string{}
	}
	return out
}

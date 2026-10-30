// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

func TestStructSliceToDictSlice_ACLEntries(t *testing.T) {
	entries := []tsclient.ACLEntry{
		{
			Action:        "accept",
			Source:        []string{"group:eng"},
			Destination:   []string{"tag:prod:22"},
			Protocol:      "tcp",
			Ports:         []string{"22"},
			Users:         []string{"root"},
			SourcePosture: []string{"posture:latestMac"},
		},
		// An entry where every optional field is empty must still round-trip,
		// since `omitempty` drops the keys entirely.
		{Action: "accept"},
	}

	out, err := structSliceToDictSlice(entries)
	require.NoError(t, err)
	require.Len(t, out, 2)

	first, ok := out[0].(map[string]any)
	require.True(t, ok, "entries must decode to map[string]any so MQL can index them")
	// Keys are the SDK's JSON tags, which is the contract the .lr docs promise.
	assert.Equal(t, "accept", first["action"])
	assert.Equal(t, []any{"group:eng"}, first["src"])
	assert.Equal(t, []any{"tag:prod:22"}, first["dst"])
	assert.Equal(t, "tcp", first["proto"])
	assert.Equal(t, []any{"22"}, first["ports"])
	assert.Equal(t, []any{"root"}, first["users"])
	assert.Equal(t, []any{"posture:latestMac"}, first["srcPosture"])

	second, ok := out[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "accept", second["action"])
	assert.NotContains(t, second, "src")
}

func TestStructSliceToDictSlice_ValuesAreJSONNative(t *testing.T) {
	// llx dicts accept only JSON-native values. ACLSSH carries an
	// SSHCheckPeriod, which must arrive as a string rather than a
	// time.Duration.
	ssh := []tsclient.ACLSSH{{
		Action:          "check",
		Users:           []string{"autogroup:nonroot"},
		Source:          []string{"autogroup:member"},
		Destination:     []string{"autogroup:self"},
		CheckPeriod:     tsclient.SSHCheckPeriod(20 * time.Hour),
		EnforceRecorder: true,
	}}

	out, err := structSliceToDictSlice(ssh)
	require.NoError(t, err)
	require.Len(t, out, 1)

	entry, ok := out[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "check", entry["action"])
	assert.Equal(t, true, entry["enforceRecorder"])
	assert.IsType(t, "", entry["checkPeriod"], "checkPeriod must serialize as a string")
	assert.Equal(t, "20h0m0s", entry["checkPeriod"])
}

func TestStructSliceToDictSlice_Empty(t *testing.T) {
	out, err := structSliceToDictSlice([]tsclient.ACLEntry{})
	require.NoError(t, err)
	assert.Equal(t, []any{}, out, "an empty policy section is an empty list, not nil")

	out, err = structSliceToDictSlice[tsclient.ACLEntry](nil)
	require.NoError(t, err)
	assert.Equal(t, []any{}, out)
}

func TestStructSliceToDictSlice_NestedGrants(t *testing.T) {
	grants := []tsclient.NodeAttrGrant{{
		Target: []string{"*"},
		Attr:   []string{"funnel"},
		App: map[string][]*tsclient.NodeAttrGrantApp{
			"tailscale.com/app-connectors": {{
				Name:       "github",
				Connectors: []string{"tag:connector"},
				Domains:    []string{"github.com"},
			}},
		},
	}}

	out, err := structSliceToDictSlice(grants)
	require.NoError(t, err)
	require.Len(t, out, 1)

	entry, ok := out[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"*"}, entry["target"])

	app, ok := entry["app"].(map[string]any)
	require.True(t, ok, "nested app grants must stay traversable")
	connectors, ok := app["tailscale.com/app-connectors"].([]any)
	require.True(t, ok)
	require.Len(t, connectors, 1)
	first, ok := connectors[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "github", first["name"])
}

func TestFlattenAutoApprovers(t *testing.T) {
	tests := []struct {
		name          string
		in            *tsclient.ACLAutoApprovers
		wantExitNodes []any
		wantRoutes    map[string]any
		wantServices  map[string]any
	}{
		{
			// A policy with no autoApprovers block must read as "nothing is
			// auto-approved", not as null.
			name:          "nil block",
			in:            nil,
			wantExitNodes: []any{},
			wantRoutes:    map[string]any{},
			wantServices:  map[string]any{},
		},
		{
			name:          "empty block",
			in:            &tsclient.ACLAutoApprovers{},
			wantExitNodes: []any{},
			wantRoutes:    map[string]any{},
			wantServices:  map[string]any{},
		},
		{
			name: "exit nodes only",
			in: &tsclient.ACLAutoApprovers{
				ExitNode: []string{"tag:exit", "group:admins"},
			},
			wantExitNodes: []any{"tag:exit", "group:admins"},
			wantRoutes:    map[string]any{},
			wantServices:  map[string]any{},
		},
		{
			name: "routes and exit nodes",
			in: &tsclient.ACLAutoApprovers{
				ExitNode: []string{"tag:exit"},
				Routes: map[string][]string{
					"10.0.0.0/8":     {"group:eng", "tag:router"},
					"192.168.0.0/16": {},
				},
			},
			wantExitNodes: []any{"tag:exit"},
			wantRoutes: map[string]any{
				"10.0.0.0/8":     []any{"group:eng", "tag:router"},
				"192.168.0.0/16": []any{},
			},
			wantServices: map[string]any{},
		},
		{
			// The services bucket names who may stand up a tailnet service
			// under its stable VIP with no administrator approving the
			// advertisement. It has to survive the flatten alongside the
			// other two buckets rather than being dropped.
			name: "services alongside routes and exit nodes",
			in: &tsclient.ACLAutoApprovers{
				ExitNode: []string{"tag:exit"},
				Routes: map[string][]string{
					"10.0.0.0/8": {"group:eng"},
				},
				Services: map[string][]string{
					"svc:web":     {"tag:frontend", "group:eng"},
					"svc:noowner": {},
				},
			},
			wantExitNodes: []any{"tag:exit"},
			wantRoutes: map[string]any{
				"10.0.0.0/8": []any{"group:eng"},
			},
			wantServices: map[string]any{
				"svc:web":     []any{"tag:frontend", "group:eng"},
				"svc:noowner": []any{},
			},
		},
		{
			// A policy that auto-approves services but nothing else must not
			// read as "nothing is auto-approved".
			name: "services only",
			in: &tsclient.ACLAutoApprovers{
				Services: map[string][]string{"svc:vpn": {"autogroup:admin"}},
			},
			wantExitNodes: []any{},
			wantRoutes:    map[string]any{},
			wantServices: map[string]any{
				"svc:vpn": []any{"autogroup:admin"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitNodes, routes, services := flattenAutoApprovers(tc.in)
			assert.Equal(t, tc.wantExitNodes, exitNodes)
			assert.Equal(t, tc.wantRoutes, routes)
			assert.Equal(t, tc.wantServices, services)
		})
	}
}

func TestStringSliceMapToAny(t *testing.T) {
	out := stringSliceMapToAny(map[string][]string{
		"group:eng":   {"alice@example.com", "bob@example.com"},
		"group:empty": {},
	})

	assert.Equal(t, map[string]any{
		"group:eng":   []any{"alice@example.com", "bob@example.com"},
		"group:empty": []any{},
	}, out)

	assert.Equal(t, map[string]any{}, stringSliceMapToAny(nil))
}

func TestStringMapToAny(t *testing.T) {
	out := stringMapToAny(map[string]string{
		"vpn":  "100.64.0.1",
		"prod": "10.0.0.0/24",
	})

	assert.Equal(t, map[string]any{
		"vpn":  "100.64.0.1",
		"prod": "10.0.0.0/24",
	}, out)

	assert.Equal(t, map[string]any{}, stringMapToAny(nil))
}

func TestStringSliceToAny(t *testing.T) {
	assert.Equal(t, []any{"posture:latestMac", "posture:hasScreenLock"},
		stringSliceToAny([]string{"posture:latestMac", "posture:hasScreenLock"}))
	assert.Equal(t, []any{}, stringSliceToAny(nil))
}

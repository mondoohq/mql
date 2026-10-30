// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	ske "github.com/stackitcloud/stackit-sdk-go/services/ske/v2api"
)

// decodeCluster builds an ske.Cluster from a payload shaped like the one
// ListClusters returns, so the auto-update flags are read through the same
// JSON path the provider takes.
func decodeCluster(t *testing.T, payload string) *ske.Cluster {
	t.Helper()
	var c ske.Cluster
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("decoding cluster payload: %v", err)
	}
	return &c
}

func TestSkeAutoUpdate(t *testing.T) {
	cases := []struct {
		name             string
		payload          string
		wantKubernetes   *bool
		wantMachineImage *bool
	}{
		{
			name:    "no maintenance window at all",
			payload: `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[]}`,
		},
		{
			// The API always sends an autoUpdate object inside a maintenance
			// window, but it omits either flag it has no setting for.
			name: "maintenance window whose autoUpdate reports neither flag",
			payload: `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],` +
				`"maintenance":{"timeWindow":{"start":"2026-01-01T01:00:00Z","end":"2026-01-01T03:00:00Z"},` +
				`"autoUpdate":{}}}`,
		},
		{
			name: "both kinds of automatic patching enabled",
			payload: `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],` +
				`"maintenance":{"timeWindow":{"start":"2026-01-01T01:00:00Z","end":"2026-01-01T03:00:00Z"},` +
				`"autoUpdate":{"kubernetesVersion":true,"machineImageVersion":true}}}`,
			wantKubernetes:   new(true),
			wantMachineImage: new(true),
		},
		{
			name: "both explicitly disabled",
			payload: `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],` +
				`"maintenance":{"timeWindow":{"start":"2026-01-01T01:00:00Z","end":"2026-01-01T03:00:00Z"},` +
				`"autoUpdate":{"kubernetesVersion":false,"machineImageVersion":false}}}`,
			wantKubernetes:   new(false),
			wantMachineImage: new(false),
		},
		{
			name: "one flag reported, the other left out stays null",
			payload: `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],` +
				`"maintenance":{"timeWindow":{"start":"2026-01-01T01:00:00Z","end":"2026-01-01T03:00:00Z"},` +
				`"autoUpdate":{"kubernetesVersion":true}}}`,
			wantKubernetes: new(true),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kubernetes, machineImage := skeAutoUpdate(decodeCluster(t, tc.payload))
			assertBoolPtr(t, "autoUpdateKubernetes", kubernetes, tc.wantKubernetes)
			assertBoolPtr(t, "autoUpdateMachineImage", machineImage, tc.wantMachineImage)
		})
	}
}

func TestSkeAutoUpdateNilCluster(t *testing.T) {
	kubernetes, machineImage := skeAutoUpdate(nil)
	if kubernetes != nil || machineImage != nil {
		t.Fatalf("skeAutoUpdate(nil) = (%v, %v), want (null, null)", kubernetes, machineImage)
	}
}

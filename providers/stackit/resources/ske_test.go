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

func TestSkeAutoUpdateWindowWithoutAutoUpdate(t *testing.T) {
	// Synthetic: a maintenance window that carries no autoUpdate object; no live account was checked.
	c := decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],`+
		`"maintenance":{"timeWindow":{"start":"2026-01-01T01:00:00Z","end":"2026-01-01T03:00:00Z"}}}`)
	kubernetes, machineImage := skeAutoUpdate(c)
	if kubernetes != nil || machineImage != nil {
		t.Fatalf("got (%v, %v), want (null, null)", kubernetes, machineImage)
	}
}

func TestSkeMaintenanceWindow(t *testing.T) {
	// Synthetic: a window from 01:00 to 03:00 UTC; no live account was checked.
	c := decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],`+
		`"maintenance":{"timeWindow":{"start":"0000-01-01T01:00:00Z","end":"0000-01-01T03:00:00Z"},"autoUpdate":{}}}`)
	start, end := skeMaintenanceWindow(c)
	if start == nil || end == nil {
		t.Fatalf("got (%v, %v), want both set", start, end)
	}
	if start.Hour() != 1 || end.Hour() != 3 {
		t.Fatalf("got start %v end %v, want 01:00 and 03:00", start, end)
	}

	// Synthetic: no maintenance window; no live account was checked.
	start, end = skeMaintenanceWindow(decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[]}`))
	if start != nil || end != nil {
		t.Fatalf("no window: got (%v, %v), want (null, null)", start, end)
	}
}

func TestSkeHibernated(t *testing.T) {
	// Synthetic: status shapes after the SDK's ClusterStatus model; no live account was checked.
	got := skeHibernated(decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],"status":{"hibernated":true}}`))
	assertBoolPtr(t, "hibernated", got, new(true))
	got = skeHibernated(decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],"status":{"hibernated":false}}`))
	assertBoolPtr(t, "hibernated", got, new(false))
	got = skeHibernated(decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],"status":{"aggregated":"STATE_HEALTHY"}}`))
	assertBoolPtr(t, "hibernated", got, nil)
}

func TestSkeClusterStatusErrors(t *testing.T) {
	// Synthetic: two errors on one cluster; no live account was checked.
	runtime, _ := fakeRuntime(t, nil)
	c := decodeCluster(t, `{"name":"c1","kubernetes":{"version":"1.30.5"},"nodepools":[],"status":{"errors":[`+
		`{"code":"SKE_INFRA_SNA_NETWORK_NOT_FOUND","message":"network gone"},{"code":"SKE_QUOTA_EXCEEDED"}]}}`)
	res, err := buildSkeCluster(runtime, c)
	if err != nil {
		t.Fatal(err)
	}
	errs := res.(*mqlStackitSkeCluster).GetErrors()
	if errs.Error != nil {
		t.Fatal(errs.Error)
	}
	if len(errs.Data) != 2 {
		t.Fatalf("got %d errors, want 2", len(errs.Data))
	}
	first := errs.Data[0].(*mqlStackitSkeClusterStatusError)
	second := errs.Data[1].(*mqlStackitSkeClusterStatusError)
	if first.Code.Data != "SKE_INFRA_SNA_NETWORK_NOT_FOUND" || first.Message.Data != "network gone" {
		t.Fatalf("first error = %q %q", first.Code.Data, first.Message.Data)
	}
	if second.Code.Data != "SKE_QUOTA_EXCEEDED" {
		t.Fatalf("second error code = %q, the two errors collided", second.Code.Data)
	}
}

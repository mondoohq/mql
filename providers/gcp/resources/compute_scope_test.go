// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestComputeAggregatedScope pins the scope classification that decides which
// buckets of a Compute AggregatedList response get mapped.
//
// disks() previously matched only the "zones/" prefix and skipped everything
// else, so every regional (synchronously replicated) persistent disk was
// dropped from gcp.project.compute.disks with no error -- and regional PDs are
// the HA disk type, so encryption and source-image audits silently ran over an
// incomplete inventory. The "region" case below is the one that regressed.
func TestComputeAggregatedScope(t *testing.T) {
	tests := []struct {
		scope    string
		wantKind string
		wantName string
		wantOK   bool
	}{
		{"zones/us-central1-a", "zone", "us-central1-a", true},
		{"regions/us-central1", "region", "us-central1", true},
		{"zones/europe-west4-b", "zone", "europe-west4-b", true},
		{"regions/asia-southeast1", "region", "asia-southeast1", true},
		// The aggregated response also carries a "global" bucket, which holds
		// no zonal or regional location and must be skipped explicitly.
		{"global", "", "", false},
		// Defensive: a prefix with no name behind it must not yield an empty
		// location that silently matches nothing in zonesByName.
		{"zones/", "", "", false},
		{"regions/", "", "", false},
		{"", "", "", false},
		{"somethingelse/us-central1", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			kind, name, ok := computeAggregatedScope(tt.scope)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantKind, kind)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

// TestVertexaiRegionFromName covers the parser the new schedule init depends on
// to pick a regional aiplatform endpoint. An empty result means the init cannot
// build an endpoint at all, so the miss cases matter as much as the hits.
func TestVertexaiRegionFromName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "schedule resource name",
			in:   "projects/my-project/locations/us-central1/schedules/1234",
			want: "us-central1",
		},
		{
			name: "project number instead of id",
			in:   "projects/415104041262/locations/europe-west4/pipelineJobs/abc",
			want: "europe-west4",
		},
		{name: "no locations segment", in: "projects/my-project/schedules/1234", want: ""},
		{name: "locations is the final segment", in: "projects/p/locations", want: ""},
		{name: "empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, vertexaiRegionFromName(tt.in))
		})
	}
}

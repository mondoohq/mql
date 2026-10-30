// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestBigqueryConnectionKey pins the reduction that makes a BigLake table's
// connection resolvable at all.
//
// BigQuery reports the same connection two ways: a table's
// biglakeConfiguration.connectionId is dotted and carries the project *ID*,
// while the connections list is a resource path carrying the project *number*.
// Comparing the raw strings never matches, so bigLakeConfiguration.connection
// read null on every BigLake table until both sides were reduced to the
// (location, id) pair below. The project segment is deliberately dropped: it is
// the one part that is not comparable between the two spellings.
func TestBigqueryConnectionKey(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantLocation string
		wantID       string
		wantOK       bool
	}{
		{
			name:         "dotted form from biglakeConfiguration.connectionId",
			in:           "tim-learning-project.us.mqlv-conn-3b5g1j",
			wantLocation: "us",
			wantID:       "mqlv-conn-3b5g1j",
			wantOK:       true,
		},
		{
			name:         "resource path from the connections list",
			in:           "projects/629145041219/locations/us/connections/mqlv-conn-3b5g1j",
			wantLocation: "us",
			wantID:       "mqlv-conn-3b5g1j",
			wantOK:       true,
		},
		{
			// the pair the live bug was found on: these two must reduce equal
			name:         "regional location",
			in:           "projects/12345/locations/us-central1/connections/my-conn",
			wantLocation: "us-central1",
			wantID:       "my-conn",
			wantOK:       true,
		},
		{
			name:         "dotted form with a regional location",
			in:           "my-project.us-central1.my-conn",
			wantLocation: "us-central1",
			wantID:       "my-conn",
			wantOK:       true,
		},
		{
			name:   "empty string is not a connection",
			in:     "",
			wantOK: false,
		},
		{
			name:   "bare connection name has no location to match on",
			in:     "my-conn",
			wantOK: false,
		},
		{
			name:   "two dotted segments is not the documented shape",
			in:     "my-project.my-conn",
			wantOK: false,
		},
		{
			name:   "path without a connections segment",
			in:     "projects/12345/locations/us",
			wantOK: false,
		},
		{
			name:   "path without a locations segment",
			in:     "projects/12345/connections/my-conn",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLocation, gotID, gotOK := bigqueryConnectionKey(tc.in)
			if gotOK != tc.wantOK {
				t.Fatalf("bigqueryConnectionKey(%q) ok = %v, want %v", tc.in, gotOK, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if gotLocation != tc.wantLocation || gotID != tc.wantID {
				t.Errorf("bigqueryConnectionKey(%q) = (%q, %q), want (%q, %q)",
					tc.in, gotLocation, gotID, tc.wantLocation, tc.wantID)
			}
		})
	}
}

// TestBigqueryConnectionKeyMatchesAcrossSpellings is the regression itself: the
// dotted and path spellings of one connection must reduce to the same key.
func TestBigqueryConnectionKeyMatchesAcrossSpellings(t *testing.T) {
	dottedLoc, dottedID, ok := bigqueryConnectionKey("tim-learning-project.us.mqlv-conn-3b5g1j")
	if !ok {
		t.Fatal("dotted form did not parse")
	}
	pathLoc, pathID, ok := bigqueryConnectionKey("projects/629145041219/locations/us/connections/mqlv-conn-3b5g1j")
	if !ok {
		t.Fatal("resource path did not parse")
	}
	if dottedLoc != pathLoc || dottedID != pathID {
		t.Errorf("the same connection reduced differently: dotted=(%q,%q) path=(%q,%q)",
			dottedLoc, dottedID, pathLoc, pathID)
	}
}

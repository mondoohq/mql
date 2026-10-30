// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "slices"

import "testing"

// TestSkippedRegionsAreScopedPerKind pins the region-discovery contract.
//
// Vertex AI sub-services have very different regional footprints: the RAG data
// service is available in a handful of regions and reports the rest as
// FailedPrecondition, which isInapplicable treats as skippable.
// While the skip set was shared across all 26 accessors, running ragCorpora()
// first shrank the candidate region list for models(), endpoints() and every
// job accessor -- silently returning a fraction of the real inventory, with
// the result depending on goroutine scheduling.
func TestSkippedRegionsAreScopedPerKind(t *testing.T) {
	svc := &mqlGcpProjectVertexaiService{}

	// A narrow sub-service marks almost every region unavailable.
	narrow := "ragCorpora"
	for _, r := range vertexaiRegions {
		if r != "us-central1" {
			svc.markRegionSkipped(narrow, r)
		}
	}

	if got := len(svc.getRegions(narrow)); got != 1 {
		t.Errorf("narrow accessor sees %d regions, want 1", got)
	}

	// A broad sub-service must be unaffected by the narrow one's skips.
	if got, want := len(svc.getRegions("models")), len(vertexaiRegions); got != want {
		t.Errorf("models sees %d regions, want %d: a narrow sub-service leaked "+
			"its skipped regions into an unrelated accessor", got, want)
	}
}

// TestMarkRegionSkippedIsIsolated checks the inverse direction too.
func TestMarkRegionSkippedIsIsolated(t *testing.T) {
	svc := &mqlGcpProjectVertexaiService{}
	svc.markRegionSkipped("endpoints", "europe-west4")

	for _, r := range svc.getRegions("endpoints") {
		if r == "europe-west4" {
			t.Fatal("endpoints still lists a region it marked skipped")
		}
	}

	var found bool
	if slices.Contains(svc.getRegions("datasets"), "europe-west4") {
		found = true
	}
	if !found {
		t.Error("datasets lost europe-west4 because endpoints skipped it")
	}
}

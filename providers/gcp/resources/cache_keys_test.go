// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
)

// TestAccessEntryKeyDistinguishesReferenceEntries pins the identity of a
// BigQuery dataset access entry.
//
// The SDK decoder leaves AccessEntry.Entity EMPTY for view, routine and dataset
// entries and records the reference in the typed field instead. Keying the
// resource on Entity alone therefore produced the identical cache key for every
// authorized view on a dataset, and CreateResource returns the FIRST resource
// stored under a key -- so a dataset sharing three views reported the same view
// three times.
func TestAccessEntryKeyDistinguishesReferenceEntries(t *testing.T) {
	viewA := &bigquery.AccessEntry{
		EntityType: bigquery.ViewEntity,
		View:       &bigquery.Table{ProjectID: "p", DatasetID: "d", TableID: "view_a"},
	}
	viewB := &bigquery.AccessEntry{
		EntityType: bigquery.ViewEntity,
		View:       &bigquery.Table{ProjectID: "p", DatasetID: "d", TableID: "view_b"},
	}

	assert.NotEqual(t, accessEntryKey(viewA), accessEntryKey(viewB),
		"two authorized views on the same dataset must not share a cache key")
	assert.Equal(t, "p:d:view_a", accessEntryKey(viewA))

	t.Run("routine", func(t *testing.T) {
		r := &bigquery.AccessEntry{
			EntityType: bigquery.RoutineEntity,
			Routine:    &bigquery.Routine{ProjectID: "p", DatasetID: "d", RoutineID: "fn"},
		}
		assert.Equal(t, "p:d:fn", accessEntryKey(r))
	})

	t.Run("dataset", func(t *testing.T) {
		d := &bigquery.AccessEntry{
			EntityType: bigquery.DatasetEntity,
			Dataset: &bigquery.DatasetAccessEntry{
				Dataset: &bigquery.Dataset{ProjectID: "p", DatasetID: "shared"},
			},
		}
		assert.Equal(t, "p:shared", accessEntryKey(d))
	})

	t.Run("plain entity kinds keep using Entity", func(t *testing.T) {
		u := &bigquery.AccessEntry{EntityType: bigquery.UserEmailEntity, Entity: "a@b.com"}
		assert.Equal(t, "a@b.com", accessEntryKey(u))

		g := &bigquery.AccessEntry{EntityType: bigquery.SpecialGroupEntity, Entity: "allAuthenticatedUsers"}
		assert.Equal(t, "allAuthenticatedUsers", accessEntryKey(g))
	})
}

// TestMachineTypeIDIsZoneQualified pins the machine-type cache key.
//
// A machine type is a per-zone catalogue entry whose numeric id is a catalogue
// CONSTANT: e2-medium carries the same Id in every zone. A key of
// (project, id) therefore collapsed every zone's copy onto one cache entry, so
// machineTypes() returned N duplicates all reporting the first zone, and
// machineTypeByZoneAndName -- which indexes on zone+name -- only ever saw that
// one zone, silently falling back to a per-instance MachineTypes.Get for every
// VM elsewhere.
func TestMachineTypeIDIsZoneQualified(t *testing.T) {
	a := machineTypeID("my-project", "us-central1-a", "e2-medium")
	b := machineTypeID("my-project", "us-central1-b", "e2-medium")
	assert.NotEqual(t, a, b, "the same machine type in two zones must not share a cache key")

	// Different projects must stay distinct too.
	assert.NotEqual(t,
		machineTypeID("project-a", "us-central1-a", "e2-medium"),
		machineTypeID("project-b", "us-central1-a", "e2-medium"))

	// And different types within one zone.
	assert.NotEqual(t,
		machineTypeID("p", "us-central1-a", "e2-medium"),
		machineTypeID("p", "us-central1-a", "e2-standard-2"))

	assert.Equal(t,
		"gcp.project.computeService.machineType/p/us-central1-a/e2-medium",
		machineTypeID("p", "us-central1-a", "e2-medium"))
}

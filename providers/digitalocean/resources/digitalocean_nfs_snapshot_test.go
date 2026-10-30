// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNfsSnapshotArgs(t *testing.T) {
	args, err := nfsSnapshotArgs(&godo.NfsSnapshot{
		ID:        "snap-1",
		Name:      "nightly",
		SizeGib:   40,
		Region:    "nyc3",
		Status:    godo.NfsSnapshotStatus("AVAILABLE"),
		CreatedAt: "2026-01-02T15:04:05Z",
		ShareID:   "share-9",
	})
	require.NoError(t, err)

	assert.Equal(t, "digitalocean.nfs.snapshot/snap-1", args["__id"].Value)
	assert.Equal(t, "snap-1", args["id"].Value)
	assert.Equal(t, "nightly", args["name"].Value)
	assert.Equal(t, int64(40), args["sizeGibibytes"].Value)
	assert.Equal(t, "nyc3", args["region"].Value)
	assert.Equal(t, "AVAILABLE", args["status"].Value)
	assert.Equal(t, "share-9", args["shareId"].Value)
	assert.NotNil(t, args["createdAt"].Value)
}

func TestNfsSnapshotArgs_AbsentTimestamp(t *testing.T) {
	// An empty timestamp must stay null rather than decoding to the zero
	// time, which would date a restore point to 1 January year 1 and make a
	// freshness check pass on a snapshot whose age is unknown.
	args, err := nfsSnapshotArgs(&godo.NfsSnapshot{ID: "snap-2", ShareID: "share-9"})
	require.NoError(t, err)
	assert.Nil(t, args["createdAt"].Value)
}

func TestNfsSnapshotArgs_EmptyIDRejected(t *testing.T) {
	_, err := nfsSnapshotArgs(&godo.NfsSnapshot{Name: "no-id"})
	require.Error(t, err)
}

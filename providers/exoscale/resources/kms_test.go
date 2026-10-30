// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupeKmsKeys(t *testing.T) {
	created := time.Date(2026, 7, 7, 16, 0, 0, 0, time.UTC)
	replica := v3.ListKmsKeysResponseEntry{ID: "k1", OriginZone: "ch-gva-2"}
	origin := v3.ListKmsKeysResponseEntry{ID: "k1", OriginZone: "ch-gva-2", CreatedAT: created, Replicas: []string{"de-fra-1"}}
	local := v3.ListKmsKeysResponseEntry{ID: "k2", OriginZone: "de-fra-1"}

	// The replica is listed first; the origin zone's record must still win,
	// since only it carries the creation time and replica list.
	keys := dedupeKmsKeys([]zoned[v3.ListKmsKeysResponseEntry]{
		{zone: "de-fra-1", item: replica},
		{zone: "de-fra-1", item: local},
		{zone: "ch-gva-2", item: origin},
	})
	require.Len(t, keys, 2)
	assert.Equal(t, created, keys[0].CreatedAT)
	assert.Equal(t, []string{"de-fra-1"}, keys[0].Replicas)
	assert.Equal(t, v3.UUID("k2"), keys[1].ID)

	// With the origin zone filtered out, the replica's record is kept.
	keys = dedupeKmsKeys([]zoned[v3.ListKmsKeysResponseEntry]{{zone: "de-fra-1", item: replica}})
	require.Len(t, keys, 1)
	assert.True(t, keys[0].CreatedAT.IsZero())
}

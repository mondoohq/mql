// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loc(id int64) *hcloud.Location { return &hcloud.Location{ID: id} }

func TestLocationMatches(t *testing.T) {
	assert.True(t, locationMatches(loc(1), 1))
	assert.False(t, locationMatches(loc(2), 1))

	// A resource the API returned without a location has an unknown one.
	// Treating it as a match would put it in every location and inflate the
	// answer to a residency question with resources never actually read.
	assert.False(t, locationMatches(nil, 1))
}

func TestVolumesInLocation(t *testing.T) {
	volumes := []*hcloud.Volume{
		{ID: 1, Location: loc(1)},
		{ID: 2, Location: loc(2)},
		{ID: 3, Location: loc(1)},
		{ID: 4, Location: nil},
		nil,
	}

	got := volumesInLocation(volumes, 1)
	require.Len(t, got, 2)
	assert.Equal(t, int64(1), got[0].ID)
	assert.Equal(t, int64(3), got[1].ID)

	assert.Empty(t, volumesInLocation(volumes, 99))
	assert.Empty(t, volumesInLocation(nil, 1))
}

func TestLoadBalancersInLocation(t *testing.T) {
	balancers := []*hcloud.LoadBalancer{
		{ID: 10, Location: loc(1)},
		{ID: 20, Location: loc(3)},
		nil,
	}

	got := loadBalancersInLocation(balancers, 1)
	require.Len(t, got, 1)
	assert.Equal(t, int64(10), got[0].ID)
	assert.Empty(t, loadBalancersInLocation(balancers, 2))
}

func TestPrimaryIPsInLocation(t *testing.T) {
	ips := []*hcloud.PrimaryIP{
		{ID: 5, Location: loc(2)},
		{ID: 6, Location: loc(1)},
		{ID: 7, Location: nil},
	}

	got := primaryIPsInLocation(ips, 2)
	require.Len(t, got, 1)
	assert.Equal(t, int64(5), got[0].ID)
}

// A floating IP carries HomeLocation, not Location. Filtering on the wrong
// field would report no floating IPs anywhere, and a residency assertion would
// pass over an empty list.
func TestFloatingIPsInHomeLocation(t *testing.T) {
	ips := []*hcloud.FloatingIP{
		{ID: 8, HomeLocation: loc(1)},
		{ID: 9, HomeLocation: loc(2)},
		{ID: 10, HomeLocation: nil},
		nil,
	}

	got := floatingIPsInHomeLocation(ips, 1)
	require.Len(t, got, 1)
	assert.Equal(t, int64(8), got[0].ID)
	assert.Empty(t, floatingIPsInHomeLocation(ips, 3))
}

func TestStorageBoxesInLocation(t *testing.T) {
	boxes := []*hcloud.StorageBox{
		{ID: 11, Location: loc(4)},
		{ID: 12, Location: loc(1)},
		nil,
	}

	got := storageBoxesInLocation(boxes, 4)
	require.Len(t, got, 1)
	assert.Equal(t, int64(11), got[0].ID)
	assert.Empty(t, storageBoxesInLocation(nil, 4))
}

func TestServerHasISO(t *testing.T) {
	t.Run("attached", func(t *testing.T) {
		s := &hcloud.Server{ID: 1, ISO: &hcloud.ISO{ID: 42}}
		assert.True(t, serverHasISO(s, 42))
		assert.False(t, serverHasISO(s, 43))
	})

	t.Run("no iso attached", func(t *testing.T) {
		assert.False(t, serverHasISO(&hcloud.Server{ID: 1}, 42))
	})

	t.Run("nil server", func(t *testing.T) {
		assert.False(t, serverHasISO(nil, 42))
	})
}

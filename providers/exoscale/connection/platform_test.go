// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestSubAssetIdentifier(t *testing.T) {
	c := &ExoscaleConnection{org: &v3.Organization{ID: "org1"}}
	s := SubAssets[0]
	assert.Equal(t, PlatformIdExoscaleOrganization+"org1/"+s.Segment+"/i1", c.SubAssetIdentifier(s, "", "i1"))
	// DBaaS names are unique only per zone, so the zone is part of the id.
	assert.NotEqual(t, c.SubAssetIdentifier(s, "ch-gva-2", "db"), c.SubAssetIdentifier(s, "de-fra-1", "db"))
}

func TestSubAssetFromOptions(t *testing.T) {
	c := &ExoscaleConnection{Conf: &inventory.Config{Options: map[string]string{OptionNlb: "lb1"}}}
	s, id, ok := c.SubAsset()
	require.True(t, ok)
	assert.Equal(t, OptionNlb, s.Option)
	assert.Equal(t, "lb1", id)

	c = &ExoscaleConnection{Conf: &inventory.Config{Options: map[string]string{}}}
	_, _, ok = c.SubAsset()
	assert.False(t, ok)
}

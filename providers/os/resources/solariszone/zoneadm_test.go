// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package solariszone

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseZoneadmList(t *testing.T) {
	zones, err := ParseZoneadmList(readFixture(t, "zoneadm-list-cp.txt"))
	require.NoError(t, err)
	require.Len(t, zones, 5)

	g := zones[0]
	require.NotNil(t, g.ID)
	assert.Equal(t, int64(0), *g.ID)
	assert.Equal(t, "global", g.Name)
	assert.Equal(t, "running", g.State)
	assert.Equal(t, "/", g.Path)
	assert.Equal(t, "solaris", g.Brand)
	assert.Equal(t, "shared", g.IPType)

	r := zones[1]
	require.NotNil(t, r.ID)
	assert.Equal(t, int64(2), *r.ID)
	assert.Equal(t, "mqlzrun", r.Name)
	assert.Equal(t, "running", r.State)
	assert.Equal(t, "995317db-0855-41f7-8d10-b973dc33561e", r.UUID)

	x := zones[2]
	assert.Nil(t, x.ID, "a zone that is not running has no ID")
	assert.Equal(t, "mqlzexcl", x.Name)
	assert.Equal(t, "configured", x.State)
	assert.Equal(t, "/system/zones/mqlzexcl", x.Path)
	assert.Equal(t, "", x.UUID)
	assert.Equal(t, "exclusive", x.IPType, "zoneadm prints excl")

	assert.Equal(t, "shared", zones[3].IPType)
}

func TestParseZoneadmListNonGlobalZone(t *testing.T) {
	// inside a non-global zone, zoneadm lists only that zone, rooted at /
	zones, err := ParseZoneadmList(readFixture(t, "zoneadm-list-cp-nonglobal.txt"))
	require.NoError(t, err)
	require.Len(t, zones, 1)
	assert.Equal(t, "mqlzrun", zones[0].Name)
	assert.Equal(t, "/", zones[0].Path)
	require.NotNil(t, zones[0].ID)
	assert.Equal(t, int64(2), *zones[0].ID)
}

func TestSplitEscaped(t *testing.T) {
	assert.Equal(t, []string{"a", "b:c", `d\e`, ""}, splitEscaped(`a:b\:c:d\\e:`, ':'))
}

func TestParseZoneadmListErrors(t *testing.T) {
	_, err := ParseZoneadmList("0:global:running\n")
	assert.Error(t, err, "too few fields")
	_, err = ParseZoneadmList("x:global:running:/::solaris:shared\n")
	assert.Error(t, err, "zone ID not a number")
	_, err = ParseZoneadmList("0::running:/::solaris:shared\n")
	assert.Error(t, err, "no zone name")

	zones, err := ParseZoneadmList("")
	require.NoError(t, err)
	assert.Empty(t, zones)
}

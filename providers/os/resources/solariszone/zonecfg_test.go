// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package solariszone

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata files were captured on Oracle Solaris 11.4.86 with
// `zonecfg -z <zone> info -a` and `zoneadm list -cp`.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestParseInfo(t *testing.T) {
	cfg, err := ParseInfo(readFixture(t, "zonecfg-info-a-mqlzexcl.txt"))
	require.NoError(t, err)

	assert.Equal(t, "mqlzexcl", cfg.Props["zonename"])
	assert.Equal(t, "-m verbose", cfg.Props["bootargs"])
	// a property without a value is held, with an empty value
	v, ok := cfg.Props["pool"]
	assert.True(t, ok)
	assert.Equal(t, "", v)
	// a property derived from a resource control is printed in brackets
	assert.Equal(t, "2000", cfg.Props["max-lwps"])

	types := make([]string, 0, len(cfg.Resources))
	for _, r := range cfg.Resources {
		types = append(types, r.Type)
	}
	assert.Equal(t, []string{
		"fs", "anet", "anet", "device", "capped-cpu", "capped-memory", "dataset",
		"rctl", "rctl", "rctl", "rctl", "rctl",
	}, types)

	anets := cfg.ResourcesOf("anet")
	require.Len(t, anets, 2)
	assert.Equal(t, "net0", anets[0].Props["linkname"])
	assert.Equal(t, "net1", anets[1].Props["linkname"])
	assert.Equal(t, "42", anets[1].Props["vlan-id"])

	mem := cfg.ResourcesOf("capped-memory")
	require.Len(t, mem, 1)
	assert.Equal(t, "2G", mem[0].Props["swap"])

	rctls := cfg.ResourcesOf("rctl")
	assert.Equal(t, "zone.cpu-cap", rctls[2].Props["name"])
	assert.Equal(t, "(priv=privileged,limit=150,action=deny)", rctls[2].Props["value"])
}

func TestParseInfoGlobalZone(t *testing.T) {
	cfg, err := ParseInfo(readFixture(t, "zonecfg-info-a-global.txt"))
	require.NoError(t, err)
	assert.Empty(t, cfg.Resources)
	assert.Equal(t, map[string]string{"file-mac-profile": "", "pool": "", "fs-allowed": ""}, cfg.Props)
}

func TestParseInfoErrors(t *testing.T) {
	_, err := ParseInfo("\tlinkname: net0\n")
	assert.Error(t, err, "resource property outside a resource")
	_, err = ParseInfo("zonename web1\n")
	assert.Error(t, err, "not a property")

	cfg, err := ParseInfo("")
	require.NoError(t, err)
	assert.Empty(t, cfg.Props)
}

func TestList(t *testing.T) {
	assert.Equal(t, []string{"ro", "nodevices"}, List("[ro,nodevices]"))
	assert.Equal(t, []string{"default", "proc_priocntl"}, List("default,proc_priocntl"))
	assert.Equal(t, []string{"single"}, List("single"))
	assert.Equal(t, []string{}, List(""))
	assert.Equal(t, []string{}, List("[]"))
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"512":  512,
		"4K":   4 << 10,
		"512m": 512 << 20,
		"2G":   2 << 30,
		"1.5G": 3 << 29,
		"1T":   1 << 40,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "G", "abc", "-1G"} {
		_, err := ParseSize(in)
		assert.Error(t, err, in)
	}
}

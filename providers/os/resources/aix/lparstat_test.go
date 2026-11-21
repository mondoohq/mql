// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lparstat_i_shared_ibm.txt is the `lparstat -i` output of a shared
// partition shown in IBM's "POWER Systems Micro-Partitioning, Part 2"
// course material (2009).
func TestParseLparstatShared(t *testing.T) {
	out, err := os.ReadFile("testdata/lparstat_i_shared_ibm.txt")
	require.NoError(t, err)
	v := ParseLparstat(string(out))
	assert.Equal(t, "LPAR2", v["Partition Name"])
	assert.Equal(t, "Shared-SMT", v["Type"])
	assert.Equal(t, "0", v["Shared Pool ID"])
	assert.Equal(t, "1280 MB", v["Online Memory"])
	assert.Equal(t, "50.00%", v["Physical CPU Percentage"])
}

// lparstat_i_dedicated.txt is a dedicated partition built on the same
// layout, with the Type format IBM documents for lparstat ("Dedicated-SMT-8")
// and "-" for the values that only exist in a shared pool.
func TestParseLparstatDedicated(t *testing.T) {
	out, err := os.ReadFile("testdata/lparstat_i_dedicated.txt")
	require.NoError(t, err)
	v := ParseLparstat(string(out))
	assert.Equal(t, "Dedicated-SMT-8", v["Type"])
	assert.NotContains(t, v, "Shared Pool ID")
	assert.NotContains(t, v, "Active CPUs in Pool")
}

func TestParseLparstatSpacing(t *testing.T) {
	v := ParseLparstat("Partition  Name :   lpar 1  \n\nno colon here\n : orphan\nMode:Uncapped\nNode Name :\n")
	assert.Equal(t, map[string]string{"Partition Name": "lpar 1", "Mode": "Uncapped"}, v)
}

func TestLparSmtThreads(t *testing.T) {
	for typ, want := range map[string]int64{
		"Shared":          1,
		"Dedicated":       1,
		"Shared-SMT":      2,
		"Dedicated-SMT":   2,
		"Shared-SMT-4":    4,
		"Dedicated-SMT-8": 8,
	} {
		n, ok := LparSmtThreads(typ)
		assert.True(t, ok, typ)
		assert.Equal(t, want, n, typ)
	}
	for _, typ := range []string{"", "Unknown", "Shared-SMT-x", "Shared-SMT-0", "Shared-4"} {
		_, ok := LparSmtThreads(typ)
		assert.False(t, ok, typ)
	}
}

func TestLparMemoryBytes(t *testing.T) {
	for v, want := range map[string]int64{
		"8192 MB":      8192 * 1024 * 1024,
		"1280 MB":      1342177280,
		"2 GB":         2 * 1024 * 1024 * 1024,
		"130797952 kB": 130797952 * 1024,
	} {
		n, ok := LparMemoryBytes(v)
		assert.True(t, ok, v)
		assert.Equal(t, want, n, v)
	}
	for _, v := range []string{"", "8192", "8192 TB", "x MB", "-1 MB"} {
		_, ok := LparMemoryBytes(v)
		assert.False(t, ok, v)
	}
}

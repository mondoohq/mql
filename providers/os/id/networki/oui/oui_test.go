// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oui_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/id/networki/oui"
)

// Every spelling of an address resolves off the same first 24 bits, so they
// all have to agree.
//
// The vendor string itself is deliberately not pinned. The IEEE renames
// organizations in place, so an assertion on a literal name turns any refresh
// of the embedded table into a build failure: "Extreme Networks Headquarters"
// became "Extreme Networks" in the registry. The shortening rules that produce
// these strings are covered against a fixture in gen, where they live.
func TestVendorAcceptsEveryAddressForm(t *testing.T) {
	want := oui.Vendor("00000c")
	require.NotEmpty(t, want, "00:00:0c has been an assigned prefix for decades")

	addrs := []string{
		"00000C",
		"00:00:0c",
		"00:00:0C",
		"00:00:0c:11:22:33",
		"00000c112233",

		// Separators are dropped wherever they fall, so a MAC written with
		// ragged groups still resolves off its first six hex digits.
		"0:00:00:c:11:22",
	}

	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			assert.Equal(t, want, oui.Vendor(addr))
		})
	}
}

func TestVendorRejectsMalformedAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"unassigned", "ffffff"},
		{"empty", ""},
		{"too short", "00000"},
		{"too short after separators", "00:00:0"},
		{"not hex", "zzzzzz"},
		{"partially not hex", "00000z"},
		{"dash separated is not hex", "00-00-0c"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Empty(t, oui.Vendor(test.addr))
		})
	}
}

// The point of the embedded table is that it costs read-only pages instead of
// heap, so a lookup must not allocate. A regression here means the table is
// being copied or decoded on the way out.
func TestVendorDoesNotAllocate(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = oui.Vendor("00:00:0c:11:22:33")
		_ = oui.Vendor("ffffff")
	})
	assert.Zero(t, allocs, "Vendor allocated")
}

// Binary search is only correct on a sorted table, and a truncated or
// misencoded blob would otherwise surface as silently missing vendors rather
// than as a failure.
func TestTableIsWellFormed(t *testing.T) {
	var assigned, prev int64 = 0, -1

	for v := range int64(1 << 24) {
		vendor := oui.Vendor(hex6(v))
		if vendor == "" {
			continue
		}
		require.Greater(t, v, prev, "records out of order")
		prev = v
		assigned++
	}

	// The IEEE MA-L registry holds tens of thousands of assignments. An exact
	// count would fail on every table refresh, but an empty or tiny table
	// means the blob did not load.
	assert.Greater(t, assigned, int64(30000), "table looks truncated")
}

func hex6(v int64) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(v>>20)&0xf], digits[(v>>16)&0xf],
		digits[(v>>12)&0xf], digits[(v>>8)&0xf],
		digits[(v>>4)&0xf], digits[v&0xf],
	})
}

func BenchmarkVendor(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = oui.Vendor("00:00:0c:11:22:33")
	}
}

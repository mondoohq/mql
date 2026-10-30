// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Encoding by hand in the test would only duplicate whatever the writer does,
// so the decoder is checked against tables the writer actually produced.
func TestReadTableRoundTrip(t *testing.T) {
	csvPath := writeCSV(t, strings.Join([]string{
		`MA-L,00000C,Cisco Systems Inc,`,
		`MA-L,000000,XEROX CORPORATION,`,
		`MA-L,286FB9,"Nokia Shanghai Bell Co.,Ltd",`,

		// Repeated vendors share one string in the blob, so two records
		// resolving to the same name exercises the offset table.
		`MA-L,3C22FB,Apple Inc.,`,

		// Not 24 bits, so not reachable by an OUI lookup and not in the table.
		`MA-M,0055DA1,Sonic Technology,`,
	}, "\n")+"\n")

	binPath := filepath.Join(t.TempDir(), "oui.bin")
	require.NoError(t, run(csvPath, binPath, ""))

	data, err := os.ReadFile(binPath)
	require.NoError(t, err)

	got, err := readTable(data)
	require.NoError(t, err)
	assert.Equal(t, []entry{
		{oui: 0x000000, vendor: "XEROX"},
		{oui: 0x00000C, vendor: "Cisco Systems"},
		{oui: 0x286FB9, vendor: "Nokia Shanghai Bell"},
		{oui: 0x3C22FB, vendor: "Apple"},
	}, got)
}

func TestReadTableRejectsMalformed(t *testing.T) {
	header := func(count uint32) []byte {
		b := append([]byte{}, magic...)
		return binary.LittleEndian.AppendUint32(b, count)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", nil, "wrong magic"},
		{"shorter than the header", []byte("MQOUIv1\x00"), "wrong magic"},
		{"wrong magic", append([]byte("MQOUIv2\x00"), 0, 0, 0, 0), "wrong magic"},
		{"records truncated away", header(4), "claims 4 assignments"},
		{
			// One well-formed record whose vendor runs off the end of the blob.
			name:    "vendor past the end of the blob",
			data:    append(header(1), 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xFF),
			wantErr: "past the end of the blob",
		},
		{
			// The writer never emits a zero-length name, so one here is
			// corruption rather than an assignment with no vendor.
			name:    "empty vendor name",
			data:    append(header(1), 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00),
			wantErr: "empty vendor name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readTable(test.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantErr)
		})
	}
}

// A table that reached disk out of order would make the lockstep walk in
// diffTables report churn that never happened.
func TestReadTableSortsRecords(t *testing.T) {
	data := append([]byte{}, magic...)
	data = binary.LittleEndian.AppendUint32(data, 2)
	data = append(data, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 4) // last, first
	data = append(data, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 5) // first, last
	data = append(data, "zzzzaaaaa"...)

	got, err := readTable(data)
	require.NoError(t, err)
	assert.Equal(t, []entry{
		{oui: 0x000000, vendor: "aaaaa"},
		{oui: 0xFFFFFF, vendor: "zzzz"},
	}, got)
}

func TestDiffTables(t *testing.T) {
	tests := []struct {
		name   string
		before []entry
		after  []entry
		want   tableDiff
	}{
		{
			name:   "unchanged",
			before: []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}},
			after:  []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}},
			want:   tableDiff{},
		},
		{
			name:   "added in the middle",
			before: []entry{{oui: 1, vendor: "a"}, {oui: 3, vendor: "c"}},
			after:  []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}, {oui: 3, vendor: "c"}},
			want:   tableDiff{added: []change{{oui: 2, to: "b"}}},
		},
		{
			name:   "removed from the middle",
			before: []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}, {oui: 3, vendor: "c"}},
			after:  []entry{{oui: 1, vendor: "a"}, {oui: 3, vendor: "c"}},
			want:   tableDiff{removed: []change{{oui: 2, from: "b"}}},
		},
		{
			name:   "renamed",
			before: []entry{{oui: 1, vendor: "Nokia Bell"}},
			after:  []entry{{oui: 1, vendor: "Nokia"}},
			want:   tableDiff{renamed: []change{{oui: 1, from: "Nokia Bell", to: "Nokia"}}},
		},
		{
			// Whichever side runs out first, the rest of the other side still
			// has to be reported.
			name:   "appended past the end of the old table",
			before: []entry{{oui: 1, vendor: "a"}},
			after:  []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}, {oui: 3, vendor: "c"}},
			want:   tableDiff{added: []change{{oui: 2, to: "b"}, {oui: 3, to: "c"}}},
		},
		{
			name:   "dropped past the end of the new table",
			before: []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}, {oui: 3, vendor: "c"}},
			after:  []entry{{oui: 1, vendor: "a"}},
			want:   tableDiff{removed: []change{{oui: 2, from: "b"}, {oui: 3, from: "c"}}},
		},
		{
			name:   "empty new table",
			before: []entry{{oui: 1, vendor: "a"}},
			after:  nil,
			want:   tableDiff{removed: []change{{oui: 1, from: "a"}}},
		},
		{
			name:   "all three at once",
			before: []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}, {oui: 4, vendor: "d"}},
			after:  []entry{{oui: 1, vendor: "a"}, {oui: 3, vendor: "c"}, {oui: 4, vendor: "D"}},
			want: tableDiff{
				added:   []change{{oui: 3, to: "c"}},
				removed: []change{{oui: 2, from: "b"}},
				renamed: []change{{oui: 4, from: "d", to: "D"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := diffTables(test.before, test.after)
			assert.Equal(t, test.want, got)
			assert.Equal(t, test.want.empty(), got.empty())
		})
	}
}

func TestSummarizeInitialTable(t *testing.T) {
	got := summarize(nil, []entry{{oui: 1, vendor: "a"}, {oui: 2, vendor: "b"}})
	assert.Equal(t, "Initial table: **2 assignments**.\n", got)
}

func TestSummarizeUnchanged(t *testing.T) {
	table := []entry{{oui: 1, vendor: "a"}}
	got := summarize(table, table)
	assert.Contains(t, got, "identical to the one already committed")
	assert.NotContains(t, got, "###")
}

func TestSummarizeReportsEachSection(t *testing.T) {
	before := []entry{
		{oui: 0x000000, vendor: "XEROX"},
		{oui: 0x001B44, vendor: "SanDisk"},
		{oui: 0x8C1F64, vendor: "Nokia Bell"},
	}
	after := []entry{
		{oui: 0x000000, vendor: "XEROX"},
		{oui: 0x0CB527, vendor: "Shenzhen Yunlink Technology"},
		{oui: 0x8C1F64, vendor: "Nokia"},
	}

	got := summarize(before, after)
	assert.Contains(t, got, "**3 → 3 assignments** (1 added, 1 removed, 1 renamed)")
	assert.Contains(t, got, "### Added (1)")
	assert.Contains(t, got, "| `0C:B5:27` | Shenzhen Yunlink Technology |")
	assert.Contains(t, got, "### Removed (1)")
	assert.Contains(t, got, "| `00:1B:44` | SanDisk |")
	assert.Contains(t, got, "### Renamed (1)")
	assert.Contains(t, got, "| `8C:1F:64` | Nokia Bell | Nokia |")
	assert.NotContains(t, got, "more._")
}

// The registry lands hundreds of assignments in a single week often enough
// that an uncapped summary would be unusable as a pull request body.
func TestSummarizeCapsEachSection(t *testing.T) {
	before := []entry{{oui: 0, vendor: "keep"}}
	after := []entry{{oui: 0, vendor: "keep"}}
	for i := 1; i <= maxRows+5; i++ {
		after = append(after, entry{oui: uint32(i), vendor: fmt.Sprintf("vendor %d", i)})
	}

	got := summarize(before, after)
	assert.Contains(t, got, fmt.Sprintf("### Added (%d)", maxRows+5))
	assert.Contains(t, got, "_and 5 more._")
	assert.Contains(t, got, "| vendor 1 |")
	assert.Contains(t, got, fmt.Sprintf("| vendor %d |", maxRows))
	assert.NotContains(t, got, fmt.Sprintf("| vendor %d |", maxRows+1))
}

// Organization names are free text out of the registry, so a name carrying a
// pipe must not tear the table it is rendered into.
func TestSummarizeEscapesVendorNames(t *testing.T) {
	got := summarize(
		[]entry{{oui: 1, vendor: "old"}},
		[]entry{{oui: 1, vendor: "Pipe | Maker\nInc"}},
	)
	assert.Contains(t, got, `| `+"`00:00:01`"+` | old | Pipe \| Maker Inc |`)
}

func TestFormatOUI(t *testing.T) {
	assert.Equal(t, "00:00:0C", formatOUI(0x00000C))
	assert.Equal(t, "FF:FF:FF", formatOUI(0xFFFFFF))
	assert.Equal(t, "0C:B5:27", formatOUI(0x0CB527))
}

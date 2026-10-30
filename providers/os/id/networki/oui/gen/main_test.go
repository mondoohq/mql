// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const csvHeader = "Registry,Assignment,Organization Name,Organization Address\n"

func writeCSV(t *testing.T, rows string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "oui.csv")
	require.NoError(t, os.WriteFile(path, []byte(csvHeader+rows), 0o600))
	return path
}

// vendor is user-visible on network.interfaces, so these are the strings the
// provider has returned since before the table was embedded. They belong here
// rather than against the shipped table, where the IEEE renaming an
// organization would fail an assertion that is really about suffix handling.
func TestSimplifyName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ltd", "Nokia Shanghai Bell Co.,Ltd", "Nokia Shanghai Bell"},
		{"inc", "Cisco Systems Inc", "Cisco Systems"},
		{"inc with a period", "Apple Inc.", "Apple"},
		{"incorporated", "Belkin International Incorporated", "Belkin International"},
		{"llc", "Amazon Technologies LLC", "Amazon Technologies"},
		{"limited", "Arm Limited", "Arm"},
		{"corporation", "XEROX CORPORATION", "XEROX"},
		{"corp", "Intel Corp.", "Intel"},
		{"company", "Hewlett Packard Company", "Hewlett Packard"},
		{"gmbh", "Sennheiser electronic GmbH", "Sennheiser electronic"},

		// A name without a corporate suffix survives whole, including one that
		// merely ends in a word the patterns do not cover.
		{"kept whole", "Extreme Networks Headquarters", "Extreme Networks Headquarters"},
		{"kept whole, no suffix at all", "Espressif", "Espressif"},

		// The patterns run in a fixed order and each runs once, so a name
		// carrying two suffixes loses them outermost first.
		{"stacked suffixes", "Nokia Shanghai Bell Co., Ltd.", "Nokia Shanghai Bell"},

		// Only a trailing suffix is a suffix.
		{"suffix word in the middle", "Inc Networks Systems", "Inc Networks Systems"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, simplifyName(test.in))
		})
	}
}

func TestRunWritesSummaryAgainstTheExistingTable(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "oui.bin")
	summaryPath := filepath.Join(dir, "summary.md")

	require.NoError(t, run(writeCSV(t, "MA-L,000000,XEROX CORPORATION,\n"), binPath, ""))

	// A second pass over a registry that gained an assignment overwrites the
	// table, and the summary has to describe the table it replaced.
	refreshed := writeCSV(t, "MA-L,000000,XEROX CORPORATION,\nMA-L,00000C,Cisco Systems Inc,\n")
	require.NoError(t, run(refreshed, binPath, summaryPath))

	summary, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Contains(t, string(summary), "**1 → 2 assignments** (1 added, 0 removed, 0 renamed)")
	assert.Contains(t, string(summary), "| `00:00:0C` | Cisco Systems |")

	data, err := os.ReadFile(binPath)
	require.NoError(t, err)
	got, err := readTable(data)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

// Nothing generates into a checkout without a table, but a missing file is not
// a reason to fail the run.
func TestRunSummarizesAMissingTableAsInitial(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.md")

	require.NoError(t, run(
		writeCSV(t, "MA-L,000000,XEROX CORPORATION,\n"),
		filepath.Join(dir, "oui.bin"),
		summaryPath,
	))

	summary, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Equal(t, "Initial table: **1 assignments**.\n", string(summary))
}

// Pointing -summary at a table this generator did not write means the file was
// swapped or corrupted, which is worth failing over rather than describing as
// tens of thousands of additions.
func TestRunRejectsAnUnreadableExistingTable(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "oui.bin")
	require.NoError(t, os.WriteFile(binPath, []byte("not an oui table"), 0o600))

	err := run(
		writeCSV(t, "MA-L,000000,XEROX CORPORATION,\n"),
		binPath,
		filepath.Join(dir, "summary.md"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong magic")
}

// An organization whose whole legal name is a corporate suffix simplifies to
// nothing. Such a row has to be dropped rather than written: readTable rejects
// a zero-length name, so emitting one would produce a table this generator
// cannot read back.
func TestRunDropsRowsThatSimplifyToNothing(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "oui.bin")
	require.NoError(t, run(writeCSV(t, "MA-L,000000,XEROX CORPORATION,\nMA-L,00000C,Co.,\n"), binPath, ""))

	data, err := os.ReadFile(binPath)
	require.NoError(t, err)

	got, err := readTable(data)
	require.NoError(t, err)
	assert.Equal(t, []entry{{oui: 0x000000, vendor: "XEROX"}}, got)
}

// The header guard is what keeps an error page or an unrelated CSV from being
// encoded into a table that reports every vendor as gone.
func TestRunRejectsANonRegistryCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oui.csv")
	require.NoError(t, os.WriteFile(path, []byte("a,b,c\n1,2,3\n"), 0o600))

	err := run(path, filepath.Join(t.TempDir(), "oui.bin"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is this the IEEE oui.csv?")
}

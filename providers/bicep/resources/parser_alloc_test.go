// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// objectBody builds a resource body of `entries` single-line properties, each
// carrying a trailing comment so the comment-skipping path is exercised too.
func objectBody(entries int) string {
	var sb strings.Builder
	for i := range entries {
		n := strconv.Itoa(i)
		sb.WriteString("  property" + n + ": 'a moderately long literal value " + n + "' // trailing comment\n")
	}
	return sb.String()
}

var entriesSink []string

// An entry is a contiguous span of the body, so splitting one out must not copy
// it. This is stated as a ratio rather than a ceiling because the copy is what
// scales: the previous implementation walked every byte through a
// strings.Builder and cost ~4 allocations per entry, so tenfold the entries
// meant tenfold the allocations. Slicing leaves only the result slice's own
// growth, which is logarithmic.
func TestSplitTopLevelEntriesDoesNotAllocatePerEntry(t *testing.T) {
	small := objectBody(200)
	large := objectBody(2000)

	allocsSmall := testing.AllocsPerRun(50, func() { entriesSink = splitTopLevelEntries(small) })
	require.Len(t, entriesSink, 200, "the split still returns every entry")

	allocsLarge := testing.AllocsPerRun(50, func() { entriesSink = splitTopLevelEntries(large) })
	require.Len(t, entriesSink, 2000, "the split still returns every entry")

	assert.Less(t, allocsLarge, allocsSmall*2,
		"10x the entries allocated %.0fx as much (%.0f -> %.0f): the body is being copied per entry instead of sliced",
		allocsLarge/allocsSmall, allocsSmall, allocsLarge)
}

// twoStatementTemplate builds `pairs` single-line params and `pairs` multi-line
// vars, i.e. 2*pairs statements.
func twoStatementTemplate(pairs int) string {
	var sb strings.Builder
	for i := range pairs {
		n := strconv.Itoa(i)
		sb.WriteString("param p" + n + " string = 'value" + n + "'\n")
		sb.WriteString("var v" + n + " = {\n  key: 'value" + n + "'\n  other: 42\n}\n")
	}
	return sb.String()
}

var statementsSink []bicepStatement

// Tokenizing may allocate for a multi-line statement's joined text, but nothing
// else should scale with the statement count: the statement slice is sized up
// front from the unindented-line count, and the body scratch slice is reused.
// Growing the slice by doubling and reallocating the scratch cost ~2.5
// allocations per statement.
func TestTokenizeBicepAllocatesAtMostOncePerStatement(t *testing.T) {
	src := twoStatementTemplate(2500)

	allocs := testing.AllocsPerRun(20, func() { statementsSink = tokenizeBicep(src) })
	require.Len(t, statementsSink, 5000, "every statement is still tokenized")

	perStatement := allocs / float64(len(statementsSink))
	assert.LessOrEqual(t, perStatement, 1.0,
		"tokenizing allocated %.2f times per statement (%.0f total); only a multi-line statement's joined text may allocate",
		perStatement, allocs)
}

// The tokenizer sizes its statement slice from the number of unindented lines.
// That bound only holds if every top-level construct really does start at
// column 0, so pin it against the fixtures rather than trusting the assumption.
func TestUnindentedLinesBoundStatementCount(t *testing.T) {
	files, err := filepath.Glob("testdata/*.bicep")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			content, err := os.ReadFile(f)
			require.NoError(t, err)

			unindented := 0
			for line := range strings.SplitSeq(stripBlockComments(string(content)), "\n") {
				if line != "" && line[0] != ' ' && line[0] != '\t' {
					unindented++
				}
			}

			statements := tokenizeBicep(stripBlockComments(string(content)))
			assert.LessOrEqual(t, len(statements), unindented,
				"a statement started on an indented line, so the preallocation bound is wrong")
		})
	}
}

var parsedSink *parsedBicepFile

// BenchmarkParseBicep parses a template built by repeating the fixtures with
// per-copy unique symbol names, which approximates a real infrastructure
// repo's main template (~270 KB, ~10.9k lines) rather than a 30-line sample.
func BenchmarkParseBicep(b *testing.B) {
	files, err := filepath.Glob("testdata/*.bicep")
	require.NoError(b, err)

	var sb strings.Builder
	for c := range 40 {
		n := strconv.Itoa(c)
		for _, f := range files {
			content, err := os.ReadFile(f)
			require.NoError(b, err)
			s := strings.ReplaceAll(string(content), "param ", "param p"+n+"_")
			s = strings.ReplaceAll(s, "var ", "var v"+n+"_")
			sb.WriteString(s)
			sb.WriteString("\n")
		}
	}
	content := sb.String()
	b.Logf("input: %d bytes, %d lines", len(content), strings.Count(content, "\n"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsedSink = parseBicep(content)
	}
}

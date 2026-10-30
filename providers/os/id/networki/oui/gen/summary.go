// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// readTable decodes a table written by run. The reader in oui.go keeps its
// decoding unexported and bound to the one blob it embeds at build time, so
// comparing the table on disk against a fresh one needs a decoder here.
func readTable(data []byte) ([]entry, error) {
	if len(data) < headerSize || string(data[:len(magic)]) != magic {
		return nil, errors.New("wrong magic, this is not an encoded OUI table")
	}

	n := int(binary.LittleEndian.Uint32(data[len(magic):headerSize]))
	blobStart := headerSize + n*recordSize
	if blobStart > len(data) {
		return nil, fmt.Errorf("table claims %d assignments but is only %d bytes", n, len(data))
	}

	entries := make([]entry, 0, n)
	for i := range n {
		rec := headerSize + i*recordSize
		length := int(data[rec+7])
		off := blobStart + int(binary.LittleEndian.Uint32(data[rec+3:rec+7]))
		end := off + length

		// simplifyName can reduce an organization name to nothing, and run
		// drops those rows rather than writing them, so a length of zero here
		// means the file was corrupted. Letting it through would report the
		// assignment as renamed into an empty cell instead of failing.
		if length == 0 {
			return nil, fmt.Errorf("assignment %d has an empty vendor name", i)
		}
		if end > len(data) {
			return nil, fmt.Errorf("assignment %d names bytes %d:%d, past the end of the blob", i, off, end)
		}

		entries = append(entries, entry{
			oui:    uint32(data[rec])<<16 | uint32(data[rec+1])<<8 | uint32(data[rec+2]),
			vendor: string(data[off:end]),
		})
	}

	// The writer sorts, and diffTables walks both sides in lockstep. Sorting a
	// table that is already sorted costs nothing and keeps a hand-mangled file
	// from turning into a summary that reads plausibly and says the wrong thing.
	sort.Slice(entries, func(i, j int) bool { return entries[i].oui < entries[j].oui })
	return entries, nil
}

// change is one assignment that differs between two tables. from is empty for
// an addition, to is empty for a removal, and both are set for a rename.
type change struct {
	oui  uint32
	from string
	to   string
}

type tableDiff struct {
	added   []change
	removed []change
	renamed []change
}

func (d tableDiff) empty() bool {
	return len(d.added) == 0 && len(d.removed) == 0 && len(d.renamed) == 0
}

// diffTables compares two tables sorted by OUI.
func diffTables(before, after []entry) tableDiff {
	var d tableDiff

	i, j := 0, 0
	for i < len(before) && j < len(after) {
		switch {
		case before[i].oui < after[j].oui:
			d.removed = append(d.removed, change{oui: before[i].oui, from: before[i].vendor})
			i++
		case before[i].oui > after[j].oui:
			d.added = append(d.added, change{oui: after[j].oui, to: after[j].vendor})
			j++
		default:
			if before[i].vendor != after[j].vendor {
				d.renamed = append(d.renamed, change{
					oui:  before[i].oui,
					from: before[i].vendor,
					to:   after[j].vendor,
				})
			}
			i++
			j++
		}
	}
	for ; i < len(before); i++ {
		d.removed = append(d.removed, change{oui: before[i].oui, from: before[i].vendor})
	}
	for ; j < len(after); j++ {
		d.added = append(d.added, change{oui: after[j].oui, to: after[j].vendor})
	}

	return d
}

// maxRows bounds each section of the summary. A quiet week moves a handful of
// assignments, but the registry lands hundreds at once often enough that the
// summary has to stay readable as a pull request body.
const maxRows = 25

// summarize describes what changed between the table already on disk and the
// one just generated. An empty before means there was no table to replace.
func summarize(before, after []entry) string {
	var b strings.Builder

	if len(before) == 0 {
		fmt.Fprintf(&b, "Initial table: **%d assignments**.\n", len(after))
		return b.String()
	}

	d := diffTables(before, after)
	if d.empty() {
		fmt.Fprintf(&b, "The regenerated table is identical to the one already committed: **%d assignments**, unchanged.\n", len(after))
		return b.String()
	}

	fmt.Fprintf(&b, "**%d → %d assignments** (%d added, %d removed, %d renamed)\n",
		len(before), len(after), len(d.added), len(d.removed), len(d.renamed))

	section(&b, "Added", d.added, []string{"OUI", "Vendor"}, func(c change) []string {
		return []string{"`" + formatOUI(c.oui) + "`", escapeCell(c.to)}
	})
	section(&b, "Removed", d.removed, []string{"OUI", "Vendor"}, func(c change) []string {
		return []string{"`" + formatOUI(c.oui) + "`", escapeCell(c.from)}
	})
	section(&b, "Renamed", d.renamed, []string{"OUI", "Before", "After"}, func(c change) []string {
		return []string{"`" + formatOUI(c.oui) + "`", escapeCell(c.from), escapeCell(c.to)}
	})

	return b.String()
}

func section(b *strings.Builder, title string, changes []change, header []string, row func(change) []string) {
	if len(changes) == 0 {
		return
	}

	fmt.Fprintf(b, "\n### %s (%d)\n\n", title, len(changes))
	fmt.Fprintf(b, "| %s |\n", strings.Join(header, " | "))
	fmt.Fprintf(b, "|%s\n", strings.Repeat(" --- |", len(header)))

	shown := changes
	if len(shown) > maxRows {
		shown = shown[:maxRows]
	}
	for _, c := range shown {
		fmt.Fprintf(b, "| %s |\n", strings.Join(row(c), " | "))
	}

	if len(changes) > len(shown) {
		fmt.Fprintf(b, "\n_and %d more._\n", len(changes)-len(shown))
	}
}

func formatOUI(oui uint32) string {
	return fmt.Sprintf("%02X:%02X:%02X", byte(oui>>16), byte(oui>>8), byte(oui))
}

// escapeCell keeps a vendor name from breaking out of its table cell. The
// registry records legal entity names, which are free text.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.Join(strings.Fields(s), " ")
}

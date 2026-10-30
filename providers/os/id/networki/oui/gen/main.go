// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Command gen builds the embedded OUI table from the IEEE registry CSV.
//
// The registry is published by the IEEE Registration Authority at
// https://standards-oui.ieee.org/oui/oui.csv with the columns
// Registry,Assignment,Organization Name,Organization Address.
//
// Organization names are shortened the same way github.com/endobit/oui
// shortened them, so the vendor strings this table returns are the ones the
// provider has always returned. See simplifyName.
//
// Usage:
//
//	go run ./gen -csv oui.csv -out oui.bin
//
// The encoded table is a binary blob, so a refresh shows up in review as
// "Binary file changed" and nothing else. -summary writes a Markdown account
// of what moved between the table already on disk and the one being written:
//
//	go run ./gen -csv oui.csv -out oui.bin -summary summary.md
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	csvPath := flag.String("csv", "", "path to the IEEE oui.csv registry export")
	outPath := flag.String("out", "oui.bin", "path to write the encoded table to")
	summaryPath := flag.String("summary", "", "path to write a Markdown summary of the change to")
	flag.Parse()

	if *csvPath == "" {
		fmt.Fprintln(os.Stderr, "gen: -csv is required")
		os.Exit(1)
	}

	if err := run(*csvPath, *outPath, *summaryPath); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

type entry struct {
	oui    uint32
	vendor string
}

func run(csvPath, outPath, summaryPath string) error {
	// Read the table being replaced before it is overwritten, so the summary
	// can say what the refresh actually changed.
	var before []entry
	if summaryPath != "" {
		old, err := os.ReadFile(outPath)
		switch {
		case err == nil:
			if before, err = readTable(old); err != nil {
				return fmt.Errorf("read existing %s: %w", outPath, err)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
	}

	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if len(header) < 3 || header[0] != "Registry" || header[1] != "Assignment" {
		return fmt.Errorf("unexpected header %q, is this the IEEE oui.csv?", header)
	}

	// 080030 is registered twice; the first row wins.
	byOUI := map[uint32]string{}
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		if len(row) < 3 {
			continue
		}

		// MA-M and MA-S assignments are 28 and 36 bits, so they are not OUIs
		// and cannot be reached by a 24-bit lookup.
		assignment := strings.TrimSpace(row[1])
		if len(assignment) != 6 {
			continue
		}
		v, err := strconv.ParseUint(assignment, 16, 32)
		if err != nil {
			continue
		}
		if _, seen := byOUI[uint32(v)]; seen {
			continue
		}

		vendor := simplifyName(strings.ReplaceAll(strings.TrimSpace(row[2]), `"`, ""))
		if vendor == "" {
			continue
		}
		if len(vendor) > 255 {
			return fmt.Errorf("vendor %q exceeds the 255 byte length prefix", vendor)
		}
		byOUI[uint32(v)] = vendor
	}

	entries := make([]entry, 0, len(byOUI))
	for oui, vendor := range byOUI {
		entries = append(entries, entry{oui: oui, vendor: vendor})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].oui < entries[j].oui })

	// Vendor names repeat heavily across assignments, so the blob stores each
	// distinct name once and records point into it.
	var blob bytes.Buffer
	offsets := map[string]uint32{}

	records := make([]byte, 0, len(entries)*recordSize)
	for _, e := range entries {
		off, ok := offsets[e.vendor]
		if !ok {
			off = uint32(blob.Len())
			blob.WriteString(e.vendor)
			offsets[e.vendor] = off
		}

		var rec [recordSize]byte
		rec[0] = byte(e.oui >> 16)
		rec[1] = byte(e.oui >> 8)
		rec[2] = byte(e.oui)
		binary.LittleEndian.PutUint32(rec[3:7], off)
		rec[7] = byte(len(e.vendor))
		records = append(records, rec[:]...)
	}

	var out bytes.Buffer
	out.WriteString(magic)
	if err := binary.Write(&out, binary.LittleEndian, uint32(len(entries))); err != nil {
		return err
	}
	out.Write(records)
	out.Write(blob.Bytes())

	if err := os.WriteFile(outPath, out.Bytes(), 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %s: %d assignments, %d distinct vendors, %d bytes\n",
		outPath, len(entries), len(offsets), out.Len())

	if summaryPath != "" {
		if err := os.WriteFile(summaryPath, []byte(summarize(before, entries)), 0o644); err != nil {
			return fmt.Errorf("write summary: %w", err)
		}
	}
	return nil
}

// Kept in sync with the reader in oui.go.
const (
	magic      = "MQOUIv1\x00"
	recordSize = 8
	headerSize = len(magic) + 4
)

// The IEEE registry records legal entity names, so most of them carry a
// corporate suffix that adds nothing to a vendor label. These patterns, and
// the order they run in, are carried over verbatim from
// github.com/endobit/oui so the table keeps returning the vendor strings the
// provider returned before it was replaced. "Nokia Shanghai Bell Co., Ltd."
// loses ", Ltd." to the first pattern and then " Co." to the second.
var (
	llcRegex  = regexp.MustCompile(`(?i),?\s*(llc|ltd|limited|inc|incorporated)\.?$`)
	coRegex   = regexp.MustCompile(`(?i),?\s*(co|company|corp|corporation)\.?$`)
	gmbhRegex = regexp.MustCompile(`(?i),?\s*gmbh\.?$`)
)

func simplifyName(name string) string {
	b := []byte(name)
	b = llcRegex.ReplaceAll(b, nil)
	b = coRegex.ReplaceAll(b, nil)
	b = gmbhRegex.ReplaceAll(b, nil)
	return string(b)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package oui resolves the vendor that owns an Organizationally Unique
// Identifier, the first 24 bits of an Ethernet MAC address.
//
// The table comes from the IEEE MA-L registry and is embedded as a sorted
// binary blob that lookups binary-search in place. Nothing is decoded at
// startup, so the data sits in read-only pages instead of the heap and an
// asset that never asks for a vendor never pays for it.
//
// Regenerate the table after downloading a fresh
// https://standards-oui.ieee.org/oui/oui.csv:
//
//	go run ./gen -csv oui.csv -out oui.bin
package oui

import (
	_ "embed"
	"encoding/binary"
)

// Kept in sync with the writer in gen/main.go.
const (
	magic      = "MQOUIv1\x00"
	recordSize = 8
	headerSize = len(magic) + 4
)

//go:embed oui.bin
var table string

// count is the number of records in the table, and blobStart is where the
// vendor names begin. Both are derived from the header once, at first use.
var count, blobStart = func() (int, int) {
	if len(table) < headerSize || table[:len(magic)] != magic {
		// The table is embedded at build time, so a bad header means the
		// checked-in blob and this reader disagree. Degrade to empty lookups
		// rather than panicking inside a scan.
		return 0, 0
	}
	n := int(binary.LittleEndian.Uint32([]byte(table[len(magic):headerSize])))
	start := headerSize + n*recordSize
	if start > len(table) {
		return 0, 0
	}
	return n, start
}()

// Vendor returns the organization that registered the OUI of addr, or the
// empty string when addr is malformed or unassigned. addr may be a bare OUI or
// a full MAC address, with or without ":" separators:
//
//	00:0B:0C          00:0b:0c:01:02:03
//	000B0C            000b0c010203
func Vendor(addr string) string {
	key, ok := parseOUI(addr)
	if !ok {
		return ""
	}

	// Binary search the fixed-width records for the 24-bit key.
	lo, hi := 0, count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		rec := headerSize + mid*recordSize
		cur := uint32(table[rec])<<16 | uint32(table[rec+1])<<8 | uint32(table[rec+2])

		switch {
		case cur < key:
			lo = mid + 1
		case cur > key:
			hi = mid
		default:
			off := blobStart + int(binary.LittleEndian.Uint32([]byte(table[rec+3:rec+7])))
			return table[off : off+int(table[rec+7])]
		}
	}
	return ""
}

// parseOUI reads the first 24 bits of a MAC address. Separators are ignored
// wherever they appear, so both "00:0b:0c" and "000b0c" yield the same key,
// and anything shorter than six hex digits is rejected.
func parseOUI(addr string) (uint32, bool) {
	var key uint32
	var seen int

	for i := 0; i < len(addr) && seen < 6; i++ {
		c := addr[i]
		if c == ':' {
			continue
		}

		var nibble uint32
		switch {
		case c >= '0' && c <= '9':
			nibble = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			nibble = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			nibble = uint32(c-'A') + 10
		default:
			return 0, false
		}

		key = key<<4 | nibble
		seen++
	}

	return key, seen == 6
}

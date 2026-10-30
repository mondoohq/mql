// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import "bytes"

// buildFlatpakDeploy lays out a deploy buffer the way flatpak does: the origin
// and commit as the tuple's two leading strings, then {sv} dictionary entries
// whose values are aligned to 8 bytes.
//
// Hand-typed buffers are not good enough here. The dictionary reader derives
// the alignment gap from a key's OFFSET, so a buffer assembled by concatenating
// literals puts keys at offsets flatpak would never produce and the reader
// correctly refuses it. Building fixtures through the same alignment rule the
// format uses keeps the tests exercising real layouts.
func buildFlatpakDeploy(origin, commit string, kv ...[2]string) []byte {
	var b bytes.Buffer
	b.WriteString(origin)
	b.WriteByte(0)
	b.WriteString(commit)
	b.WriteByte(0)

	for _, entry := range kv {
		// Keys sit at an aligned offset in a real file: the captured record has
		// "appdata-version" at byte 176, preceded by the previous entry's type
		// signature and then NUL padding. Without this the builder emits a key
		// immediately after the previous 's', which no real deploy file does --
		// and a fixture that is laid out differently from the thing it stands in
		// for cannot test the reader's offset arithmetic.
		for b.Len()%flatpakGVariantAlignment != 0 {
			b.WriteByte(0)
		}
		b.WriteString(entry[0])
		b.WriteByte(0)
		for b.Len()%flatpakGVariantAlignment != 0 {
			b.WriteByte(0)
		}
		b.WriteString(entry[1])
		b.WriteByte(0)
		// The variant's type signature follows the value, as in a real file.
		b.WriteByte(0)
		b.WriteByte('s')
	}
	return b.Bytes()
}

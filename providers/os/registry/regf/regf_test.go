// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package regf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	os.Exit(m.Run())
}

// The tests that craft damaged hives each name the behaviour of the
// third-party parser this package replaced (www.velocidex.com/golang/regparser)
// that the case guards against, as found by reading its source: a fatal stack
// overflow, an index-out-of-range panic, an unbounded allocation or loop.

// fixture returns the hive saved on Windows Server 2025 for the registry
// package tests (hive version 1.3, so its 20000-byte values are single cells).
func fixture(t testing.TB) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "fixture.hiv.gz"))
	require.NoError(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	b, err := io.ReadAll(zr)
	require.NoError(t, err)
	return b
}

func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

// Field offsets inside a key node cell's data.
const (
	nkSubkeyCount = 20
	nkSubkeyList  = 28
	nkValueCount  = 36
	nkValueList   = 40
)

// patchKey sets a 32-bit field of the key's node in the hive bytes.
func patchKey(b []byte, k Key, field int, v uint32) {
	put32(b, baseBlockSize+int(k.Offset)+4+field, v)
}

// keyField reads a 32-bit field of the key's node.
func keyField(b []byte, k Key, field int) uint32 {
	return le32(b, baseBlockSize+int(k.Offset)+4+field)
}

func openBytes(b []byte, logs ...Log) (*Hive, error) {
	return Open(bytes.NewReader(b), int64(len(b)), logs...)
}

func mustOpen(t testing.TB, b []byte) *Hive {
	t.Helper()
	h, err := openBytes(b)
	require.NoError(t, err)
	return h
}

func child(t testing.TB, k Key, name string) Key {
	t.Helper()
	subs, err := k.Subkeys()
	require.NoError(t, err)
	for _, s := range subs {
		if s.Name == name {
			return s
		}
	}
	require.FailNow(t, "no subkey", "%q under %q", name, k.Name)
	return Key{}
}

func keyAt(t testing.TB, h *Hive, path ...string) Key {
	t.Helper()
	k, err := h.Root()
	require.NoError(t, err)
	for _, p := range path {
		k = child(t, k, p)
	}
	return k
}

func valueNamed(t testing.TB, k Key, name string) Value {
	t.Helper()
	vals, err := k.Values()
	require.NoError(t, err)
	for _, v := range vals {
		if v.Name == name {
			return v
		}
	}
	require.FailNow(t, "no value", "%q under %q", name, k.Name)
	return Value{}
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// within fails the test if f does not return in time (a hang would otherwise
// only show as the package test timeout).
func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		require.FailNow(t, "timeout", "did not return within %s", d)
	}
}

// allocated returns the bytes f allocates.
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// builder appends crafted cells to a hive as one more hive bin, or builds a
// small hive from scratch.
type builder struct {
	b     []byte
	start int // where the added bin starts, relative to the hive bins data
	extra []byte
}

func fromHive(b []byte) *builder {
	return &builder{b: append([]byte(nil), b...), start: len(b) - baseBlockSize}
}

// blankHive starts an empty hive of the given minor version.
func blankHive(minor uint32) *builder {
	b := make([]byte, baseBlockSize)
	copy(b, "regf")
	put32(b, 4, 1)
	put32(b, 8, 1)
	put32(b, 20, 1)
	put32(b, 24, minor)
	put32(b, 32, 1)
	return &builder{b: b}
}

// add appends an allocated cell holding data and returns its offset.
func (bl *builder) add(data []byte) uint32 {
	if bl.extra == nil {
		bl.extra = make([]byte, 32)
	}
	off := uint32(bl.start + len(bl.extra))
	n := max((len(data)+4+7)&^7, 8)
	cell := make([]byte, n)
	put32(cell, 0, uint32(-int32(n)))
	copy(cell[4:], data)
	bl.extra = append(bl.extra, cell...)
	return off
}

// bytes finishes the hive: the bin is padded with a free cell, the bins size
// and the checksum are updated.
func (bl *builder) bytes() []byte {
	if bl.extra != nil {
		total := (len(bl.extra) + 4095) &^ 4095
		if free := total - len(bl.extra); free > 0 {
			cell := make([]byte, free)
			put32(cell, 0, uint32(free))
			bl.extra = append(bl.extra, cell...)
		}
		copy(bl.extra, "hbin")
		put32(bl.extra, 4, uint32(bl.start))
		put32(bl.extra, 8, uint32(total))
		bl.b = append(bl.b, bl.extra...)
		bl.extra = nil
		put32(bl.b, 40, uint32(len(bl.b)-baseBlockSize))
	}
	setChecksum(bl.b)
	return bl.b
}

func setChecksum(b []byte) {
	var sum uint32
	for i := 0; i < 508; i += 4 {
		sum ^= le32(b, i)
	}
	switch sum {
	case 0xFFFFFFFF:
		sum = 0xFFFFFFFE
	case 0:
		sum = 1
	}
	put32(b, 508, sum)
}

func nkCell(name string, subkeys, subkeyList, values, valueList uint32) []byte {
	c := make([]byte, nkHeaderSize+len(name))
	copy(c, "nk")
	put16(c, 2, 0x20)
	put32(c, nkSubkeyCount, subkeys)
	put32(c, nkSubkeyList, subkeyList)
	put32(c, nkValueCount, values)
	put32(c, nkValueList, valueList)
	put16(c, 72, uint16(len(name)))
	copy(c[nkHeaderSize:], name)
	return c
}

func vkCell(name string, typ, size, dataOff uint32) []byte {
	c := make([]byte, vkHeaderSize+len(name))
	copy(c, "vk")
	put16(c, 2, uint16(len(name)))
	put32(c, 4, size)
	put32(c, 8, dataOff)
	put32(c, 12, typ)
	put16(c, 16, 1)
	copy(c[vkHeaderSize:], name)
	return c
}

// listCell builds an lf/lh (with name hints), li or ri list.
func listCell(sig string, offs ...uint32) []byte {
	stride := 4
	if sig == "lf" || sig == "lh" {
		stride = 8
	}
	c := make([]byte, 4+stride*len(offs))
	copy(c, sig)
	put16(c, 2, uint16(len(offs)))
	for i, o := range offs {
		put32(c, 4+stride*i, o)
	}
	return c
}

func offsets(offs ...uint32) []byte {
	c := make([]byte, 4*len(offs))
	for i, o := range offs {
		put32(c, 4*i, o)
	}
	return c
}

// attackHive is a small hive: the root "root" has the subkeys "a" and "b", "a"
// holds the values Sz, Dword and a 20000-byte Big, stored as big data. The
// returned builder has not been finished, so tests can add more cells.
func attackHive() (bl *builder, rootOff, aOff uint32) {
	bl = blankHive(5)
	big := make([]byte, 20000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	seg1 := bl.add(big[:bigDataSegmentMax])
	seg2 := bl.add(big[bigDataSegmentMax:])
	segs := bl.add(offsets(seg1, seg2))
	db := make([]byte, 8)
	copy(db, "db")
	put16(db, 2, 2)
	put32(db, 4, segs)
	dbOff := bl.add(db)
	szData := bl.add(utf16le("hello\x00"))
	vSz := bl.add(vkCell("Sz", 1, 12, szData))
	vDword := bl.add(vkCell("Dword", 4, 0x80000004, 112))
	vBig := bl.add(vkCell("Big", 3, 20000, dbOff))
	vals := bl.add(offsets(vSz, vDword, vBig))
	aOff = bl.add(nkCell("a", 0, noOffset, 3, vals))
	bOff := bl.add(nkCell("b", 0, noOffset, 0, noOffset))
	list := bl.add(listCell("lf", aOff, bOff))
	rootOff = bl.add(nkCell("root", 2, list, 0, noOffset))
	put32(bl.b, 36, rootOff)
	return bl, rootOff, aOff
}

func TestOpenFixture(t *testing.T) {
	h := mustOpen(t, fixture(t))
	assert.False(t, h.Dirty())
	assert.Zero(t, h.Replayed())

	root, err := h.Root()
	require.NoError(t, err)
	subs, err := root.Subkeys()
	require.NoError(t, err)
	var names []string
	for _, s := range subs {
		names = append(names, s.Name)
	}
	assert.ElementsMatch(t, []string{"Values", "Nested", "MixedCase", "Mime", "Many", "Empty"}, names)

	t.Run("values of every type", func(t *testing.T) {
		vals := keyAt(t, h, "Values")
		got := map[string]Value{}
		all, err := vals.Values()
		require.NoError(t, err)
		for _, v := range all {
			got[v.Name] = v
		}
		assert.Len(t, all, 15)
		data := func(name string) []byte {
			d, err := got[name].Data()
			require.NoError(t, err, name)
			return d
		}
		assert.Equal(t, uint32(1), got["Sz"].Type)
		assert.Equal(t, append(utf16le("hello world"), 0, 0), data("Sz"))
		assert.Equal(t, []byte{112, 0, 0, 0}, data("Dword"), "inline data")
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, data("Binary"))
		assert.Equal(t, uint32(0), got["NoneType"].Type)
		assert.Equal(t, uint32(1), got[""].Type, "the default value has the empty name")
		big := data("BinaryBig")
		require.Len(t, big, 20000)
		for i, b := range big {
			require.Equal(t, byte(i%251), b, "byte %d", i)
		}
	})
	t.Run("an index root lists the 1500 children", func(t *testing.T) {
		many := keyAt(t, h, "Many")
		list := mustCell(t, h, keyField(h.rawBytes(t), many, nkSubkeyList))
		sig := make([]byte, 2)
		require.NoError(t, readFull(h.r, sig, list.off))
		require.Equal(t, "ri", string(sig), "the fixture must exercise index roots")
		subs, err := many.Subkeys()
		require.NoError(t, err)
		assert.Len(t, subs, 1500)
	})
	t.Run("a slash is part of a name", func(t *testing.T) {
		assert.Equal(t, "application/json", keyAt(t, h, "Mime", "application/json").Name)
	})
	t.Run("walk visits every key once", func(t *testing.T) {
		seen := map[uint32]bool{}
		require.NoError(t, h.Walk(1_000_000, func(k Key) error {
			require.False(t, seen[k.Offset])
			seen[k.Offset] = true
			return nil
		}))
		assert.Greater(t, len(seen), 1500)
	})
}

// rawBytes returns the whole file; tests use it to read raw fields.
func (h *Hive) rawBytes(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, baseBlockSize+h.binsSize)
	require.NoError(t, readFull(h.r, b, 0))
	return b
}

func mustCell(t testing.TB, h *Hive, off uint32) cell {
	t.Helper()
	c, err := h.cell(off)
	require.NoError(t, err)
	return c
}

func TestAttackHiveIsReadable(t *testing.T) {
	// the crafted-hive builder must produce a valid hive, or the attack tests
	// below would only prove that an invalid hive is invalid
	bl, _, _ := attackHive()
	h := mustOpen(t, bl.bytes())
	a := keyAt(t, h, "a")
	assert.Equal(t, "root", func() string { r, _ := h.Root(); return r.Name }())
	vals, err := a.Values()
	require.NoError(t, err)
	require.Len(t, vals, 3)
	d, err := valueNamed(t, a, "Big").Data()
	require.NoError(t, err)
	require.Len(t, d, 20000)
	for i := range d {
		require.Equal(t, byte(i%251), d[i], "byte %d", i)
	}
	d, err = valueNamed(t, a, "Dword").Data()
	require.NoError(t, err)
	assert.Equal(t, []byte{112, 0, 0, 0}, d)
}

func TestOpenRejectsBadBaseBlock(t *testing.T) {
	good := fixture(t)
	clone := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	tests := map[string][]byte{
		"empty":               nil,
		"smaller than header": good[:100],
		"bad signature":       clone(func(b []byte) { copy(b, "regX") }),
		"bins larger than file": clone(func(b []byte) {
			put32(b, 40, uint32(len(b)))
		}),
		"bins size beyond the limit": clone(func(b []byte) { put32(b, 40, 0xFFFFF000) }),
		"root outside the bins":      clone(func(b []byte) { put32(b, 36, uint32(len(b))) }),
		"root unaligned":             clone(func(b []byte) { put32(b, 36, le32(b, 36)+1) }),
		"root points nowhere":        clone(func(b []byte) { put32(b, 36, noOffset) }),
		"root is not a key": clone(func(b []byte) {
			// the first value list of the hive is not a key node
			b[baseBlockSize+int(le32(b, 36))+4] = 'x'
		}),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := openBytes(b)
			require.Error(t, err)
		})
	}
	t.Run("unexpected version is tried anyway", func(t *testing.T) {
		b := clone(func(b []byte) { put32(b, 24, 9) })
		_, err := openBytes(b)
		require.NoError(t, err)
	})
}

func TestCellValidation(t *testing.T) {
	bl, rootOff, aOff := attackHive()
	good := bl.bytes()
	h := mustOpen(t, good)
	a := keyAt(t, h, "a")
	_ = aOff
	cellOff := func(off uint32) int { return baseBlockSize + int(off) }

	t.Run("unallocated cell", func(t *testing.T) {
		b := append([]byte(nil), good...)
		put32(b, cellOff(aOff), uint32(le32(b, cellOff(aOff))*0xFFFFFFFF)) // negate the size
		h := mustOpen(t, b)
		_, err := h.cell(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("cell smaller than 8 bytes", func(t *testing.T) {
		b := append([]byte(nil), good...)
		put32(b, cellOff(aOff), uint32(0xFFFFFFFC)) // -4
		_, err := mustOpen(t, b).cell(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("cell larger than the bins", func(t *testing.T) {
		b := append([]byte(nil), good...)
		put32(b, cellOff(aOff), uint32(0x80000001)) // -2147483647
		_, err := mustOpen(t, b).cell(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("cell larger than the cell limit", func(t *testing.T) {
		b := append([]byte(nil), good...)
		neg := int32(-(MaxCellSize + 8))
		put32(b, cellOff(aOff), uint32(neg))
		_, err := mustOpen(t, b).cell(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("offsets outside, unaligned or empty", func(t *testing.T) {
		for _, off := range []uint32{noOffset, uint32(h.binsSize), uint32(h.binsSize) - 4, aOff + 1, 0xFFFFFFF8} {
			_, err := h.cell(off)
			assert.ErrorIs(t, err, ErrCorrupt, "%#x", off)
		}
	})
	t.Run("key name longer than its cell", func(t *testing.T) {
		b := append([]byte(nil), good...)
		put16(b, cellOff(aOff)+4+72, 0xFFFF)
		_, err := mustOpen(t, b).key(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("key cell too small for a key node", func(t *testing.T) {
		b := append([]byte(nil), good...)
		size40 := int32(-40)
		put32(b, cellOff(aOff), uint32(size40))
		_, err := mustOpen(t, b).key(aOff)
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("not a key node", func(t *testing.T) {
		_, err := h.key(le32(good, cellOff(aOff)+4+nkValueList))
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	_ = a
	_ = rootOff
}

// R1: regparser follows index roots recursively without a depth limit or a
// visited set: an index root that lists itself overflows the goroutine stack
// (a fatal error that recover cannot catch), and one that lists the same leaf
// list many times multiplies the work with every level.
func TestSubkeysIndexRootCycles(t *testing.T) {
	fix := fixture(t)
	base := mustOpen(t, fix)
	many := keyAt(t, base, "Many")
	riOff := keyField(fix, many, nkSubkeyList)
	riCell := baseBlockSize + int(riOff) + 4
	require.Equal(t, "ri", string(fix[riCell:riCell+2]))
	first := le32(fix, riCell+4)
	second := le32(fix, riCell+8)

	t.Run("index root lists itself", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		put32(b, riCell+4, riOff)
		within(t, 5*time.Second, func() {
			_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
			assert.ErrorIs(t, err, ErrCorrupt)
		})
	})
	t.Run("index root lists an index root", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		copy(b[baseBlockSize+int(first)+4:], "ri") // the first leaf list becomes an index root
		_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("index root lists a leaf list twice", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		put32(b, riCell+8, first)
		_ = second
		_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("the subkey list of a key is its own index root", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		patchKey(b, many, nkSubkeyList, riOff)
		put32(b, riCell+4, riOff)
		within(t, 5*time.Second, func() {
			_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
			assert.Error(t, err)
		})
	})
	t.Run("index root count larger than its cell", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		put16(b, riCell+2, 0xFFFF)
		_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("a deep chain of index roots is rejected without recursion", func(t *testing.T) {
		bl, _, _ := attackHive()
		// ri -> ri -> ri ... : 5000 index roots, each pointing to the next
		const n = 5000
		first := bl.add(listCell("ri", 0))
		prev := first
		for i := 1; i < n; i++ {
			cur := bl.add(listCell("ri", 0))
			put32(bl.extra, int(prev)-bl.start+4+4, cur)
			prev = cur
		}
		b := bl.bytes()
		h := mustOpen(t, b)
		root, _ := h.Root()
		patchKey(b, root, nkSubkeyList, first)
		within(t, 5*time.Second, func() {
			_, err := mustOpen(t, b).keyByName(t, "root").Subkeys()
			assert.ErrorIs(t, err, ErrCorrupt)
		})
	})
}

// keyByName returns the root key when name is the root's name.
func (h *Hive) keyByName(t testing.TB, name string) Key {
	t.Helper()
	root, err := h.Root()
	require.NoError(t, err)
	if root.Name == name {
		return root
	}
	return child(t, root, name)
}

func TestSubkeysCountsAndDuplicates(t *testing.T) {
	fix := fixture(t)
	many := keyAt(t, mustOpen(t, fix), "Many")

	t.Run("never more than the key declares", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		patchKey(b, many, nkSubkeyCount, 10)
		subs, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		require.NoError(t, err)
		assert.Len(t, subs, 10)
	})
	t.Run("fewer than declared is tolerated", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		patchKey(b, many, nkSubkeyCount, 5000)
		subs, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		require.NoError(t, err)
		assert.Len(t, subs, 1500)
	})
	t.Run("count over the limit", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		patchKey(b, many, nkSubkeyCount, 0xFFFFFFFF)
		_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		assert.ErrorIs(t, err, ErrTooLarge)
	})
	t.Run("a child listed twice is returned once", func(t *testing.T) {
		bl, _, aOff := attackHive()
		list := bl.add(listCell("li", aOff, aOff, aOff))
		b := bl.bytes()
		root, _ := mustOpen(t, b).Root()
		patchKey(b, root, nkSubkeyCount, 3)
		patchKey(b, root, nkSubkeyList, list)
		subs, err := mustOpen(t, b).keyByName(t, "root").Subkeys()
		require.NoError(t, err)
		require.Len(t, subs, 1)
		assert.Equal(t, "a", subs[0].Name)
	})
	t.Run("an invalid child is skipped, the others stay", func(t *testing.T) {
		bl, _, aOff := attackHive()
		list := bl.add(listCell("lh", 0xFFFFFFF8, aOff, 12))
		b := bl.bytes()
		root, _ := mustOpen(t, b).Root()
		patchKey(b, root, nkSubkeyCount, 3)
		patchKey(b, root, nkSubkeyList, list)
		subs, err := mustOpen(t, b).keyByName(t, "root").Subkeys()
		require.NoError(t, err)
		require.Len(t, subs, 1)
		assert.Equal(t, "a", subs[0].Name)
	})
	t.Run("leaf count larger than its cell", func(t *testing.T) {
		for _, sig := range []string{"lf", "lh", "li"} {
			bl, _, aOff := attackHive()
			list := bl.add(listCell(sig, aOff))
			put16(bl.extra, int(list)-bl.start+4+2, 0xFFFF)
			b := bl.bytes()
			root, _ := mustOpen(t, b).Root()
			patchKey(b, root, nkSubkeyCount, 1)
			patchKey(b, root, nkSubkeyList, list)
			_, err := mustOpen(t, b).keyByName(t, "root").Subkeys()
			assert.ErrorIs(t, err, ErrCorrupt, sig)
		}
	})
	t.Run("subkey list of an unknown kind", func(t *testing.T) {
		bl, _, aOff := attackHive()
		list := bl.add(listCell("xx", aOff))
		b := bl.bytes()
		root, _ := mustOpen(t, b).Root()
		patchKey(b, root, nkSubkeyList, list)
		_, err := mustOpen(t, b).keyByName(t, "root").Subkeys()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("subkey list offset points nowhere", func(t *testing.T) {
		b := append([]byte(nil), fix...)
		patchKey(b, many, nkSubkeyList, noOffset)
		_, err := mustOpen(t, b).keyByName(t, "Many").Subkeys()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
}

// R12: a subkey may point to an ancestor. A recursive walk without a visited
// set (regparser has none) never ends; Walk visits every key once.
func TestWalkSubkeyPointsToAncestor(t *testing.T) {
	baseline := 0
	{
		bl, _, _ := attackHive()
		require.NoError(t, mustOpen(t, bl.bytes()).Walk(100, func(Key) error { baseline++; return nil }))
		require.Equal(t, 3, baseline)
	}
	bl, rootOff, aOff := attackHive()
	// "a" gets two children: the root (its parent) and itself
	list := bl.add(listCell("lf", rootOff, aOff))
	b := bl.bytes()
	h := mustOpen(t, b)
	patchKey(b, keyAt(t, h, "a"), nkSubkeyCount, 2)
	patchKey(b, keyAt(t, h, "a"), nkSubkeyList, list)

	got := 0
	within(t, 5*time.Second, func() {
		require.NoError(t, mustOpen(t, b).Walk(100, func(Key) error { got++; return nil }))
	})
	assert.Equal(t, baseline, got, "each key is visited once")
}

func TestWalkLimits(t *testing.T) {
	h := mustOpen(t, fixture(t))
	err := h.Walk(10, func(Key) error { return nil })
	assert.ErrorIs(t, err, ErrTooLarge)

	stop := errors.New("stop")
	n := 0
	err = h.Walk(1000, func(Key) error {
		if n++; n == 3 {
			return stop
		}
		return nil
	})
	assert.ErrorIs(t, err, stop)
	assert.Equal(t, 3, n)
}

// R2: regparser checks the declared size of a DWORD or QWORD, not the length of
// the data it read, and indexes out of range when the data cell is short or
// lies past the end of the file.
func TestValueDataCellTooShort(t *testing.T) {
	bl, _, _ := attackHive()
	tiny := bl.add([]byte{1, 2, 3, 4})
	vShort := bl.add(vkCell("Short", 4, 4000, tiny))
	vPast := bl.add(vkCell("Past", 4, 4, 0x7FFFFFF8))
	vNowhere := bl.add(vkCell("Nowhere", 4, 4, noOffset))
	vInline := bl.add(vkCell("InlineTooLong", 4, 0x80000008, 7))
	vals := bl.add(offsets(vShort, vPast, vNowhere, vInline))
	b := bl.bytes()
	h := mustOpen(t, b)
	a := keyAt(t, h, "a")
	patchKey(b, a, nkValueCount, 4)
	patchKey(b, a, nkValueList, vals)
	a = keyAt(t, mustOpen(t, b), "a")

	for _, name := range []string{"Short", "Past", "Nowhere", "InlineTooLong"} {
		_, err := valueNamed(t, a, name).Data()
		assert.ErrorIs(t, err, ErrCorrupt, name)
	}
}

// R7: regparser reads a value of up to 2 GiB one byte at a time, and a big data
// record that repeats one huge cell makes it read gigabytes per value.
func TestValueSizeLimits(t *testing.T) {
	t.Run("declared size over the limit", func(t *testing.T) {
		bl, _, _ := attackHive()
		d := bl.add(make([]byte, 64))
		v := bl.add(vkCell("Huge", 3, 0x7FFFFFFF, d))
		vals := bl.add(offsets(v))
		b := bl.bytes()
		a := keyAt(t, mustOpen(t, b), "a")
		patchKey(b, a, nkValueCount, 1)
		patchKey(b, a, nkValueList, vals)
		val := valueNamed(t, keyAt(t, mustOpen(t, b), "a"), "Huge")
		assert.Equal(t, 0x7FFFFFFF, val.Size())
		cost := allocated(func() {
			_, err := val.Data()
			assert.ErrorIs(t, err, ErrTooLarge)
		})
		assert.Less(t, cost, uint64(1<<20))
	})
	t.Run("data larger than its cell", func(t *testing.T) {
		bl, _, _ := attackHive()
		d := bl.add(make([]byte, 64))
		v := bl.add(vkCell("Big", 3, 5000, d))
		vals := bl.add(offsets(v))
		b := bl.bytes()
		a := keyAt(t, mustOpen(t, b), "a")
		patchKey(b, a, nkValueCount, 1)
		patchKey(b, a, nkValueList, vals)
		_, err := valueNamed(t, keyAt(t, mustOpen(t, b), "a"), "Big").Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
}

func TestBigData(t *testing.T) {
	// valueWith attaches a value of the given declared size, whose data cell
	// holds the given big data record, to "a" and returns it
	valueWith := func(t *testing.T, size uint32, build func(bl *builder) []byte) Value {
		t.Helper()
		bl, _, _ := attackHive()
		dbOff := bl.add(build(bl))
		v := bl.add(vkCell("Crafted", 3, size, dbOff))
		vals := bl.add(offsets(v))
		b := bl.bytes()
		a := keyAt(t, mustOpen(t, b), "a")
		patchKey(b, a, nkValueCount, 1)
		patchKey(b, a, nkValueList, vals)
		return valueNamed(t, keyAt(t, mustOpen(t, b), "a"), "Crafted")
	}
	db := func(count uint16, segs uint32) []byte {
		c := make([]byte, 8)
		copy(c, "db")
		put16(c, 2, count)
		put32(c, 4, segs)
		return c
	}

	t.Run("a segment list that repeats one cell yields exactly the declared size", func(t *testing.T) {
		v := valueWith(t, 3*bigDataSegmentMax-100, func(bl *builder) []byte {
			seg := bl.add(bytes.Repeat([]byte{7}, bigDataSegmentMax))
			return db(3, bl.add(offsets(seg, seg, seg)))
		})
		d, err := v.Data()
		require.NoError(t, err)
		assert.Len(t, d, 3*bigDataSegmentMax-100)
	})
	t.Run("segment count 65535 that does not fit the list cell", func(t *testing.T) {
		// regparser allocated and read per declared segment
		v := valueWith(t, MaxValueSize, func(bl *builder) []byte {
			seg := bl.add(make([]byte, bigDataSegmentMax))
			return db(0xFFFF, bl.add(offsets(seg)))
		})
		_, err := v.Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("segment count that does not match the size", func(t *testing.T) {
		v := valueWith(t, 20000, func(bl *builder) []byte {
			seg := bl.add(make([]byte, bigDataSegmentMax))
			return db(3, bl.add(offsets(seg, seg, seg)))
		})
		_, err := v.Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("segment cell too short for its share", func(t *testing.T) {
		v := valueWith(t, 20000, func(bl *builder) []byte {
			short := bl.add(make([]byte, 100))
			return db(2, bl.add(offsets(short, short)))
		})
		_, err := v.Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("segment offset outside the hive", func(t *testing.T) {
		v := valueWith(t, 20000, func(bl *builder) []byte {
			return db(2, bl.add(offsets(0x7FFFFFF8, noOffset)))
		})
		_, err := v.Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("not a big data record", func(t *testing.T) {
		v := valueWith(t, 20000, func(bl *builder) []byte {
			return append([]byte("xx"), make([]byte, 6)...)
		})
		_, err := v.Data()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("version 1.3 stores large data in one cell", func(t *testing.T) {
		// the fixture is version 1.3 and its 20000-byte values are no db
		v := valueNamed(t, keyAt(t, mustOpen(t, fixture(t)), "Values"), "BinaryBig")
		d, err := v.Data()
		require.NoError(t, err)
		assert.Len(t, d, 20000)
	})
}

// R8: regparser's value count is a uint32 that sizes loops and allocations.
func TestCountsAreLimited(t *testing.T) {
	bl, _, _ := attackHive()
	b := bl.bytes()
	a := keyAt(t, mustOpen(t, b), "a")

	t.Run("value count 0xFFFFFFFF", func(t *testing.T) {
		c := append([]byte(nil), b...)
		patchKey(c, a, nkValueCount, 0xFFFFFFFF)
		k := keyAt(t, mustOpen(t, c), "a")
		cost := allocated(func() {
			_, err := k.Values()
			assert.ErrorIs(t, err, ErrTooLarge)
		})
		assert.Less(t, cost, uint64(1<<20))
	})
	t.Run("value count that does not fit the value list", func(t *testing.T) {
		c := append([]byte(nil), b...)
		patchKey(c, a, nkValueCount, MaxValues)
		_, err := keyAt(t, mustOpen(t, c), "a").Values()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("value list points nowhere", func(t *testing.T) {
		c := append([]byte(nil), b...)
		patchKey(c, a, nkValueList, noOffset)
		_, err := keyAt(t, mustOpen(t, c), "a").Values()
		assert.ErrorIs(t, err, ErrCorrupt)
	})
	t.Run("a value listed twice is returned once", func(t *testing.T) {
		c := append([]byte(nil), b...)
		list := int(keyField(c, a, nkValueList))
		put32(c, baseBlockSize+list+4+4, le32(c, baseBlockSize+list+4)) // second entry = first
		vals, err := keyAt(t, mustOpen(t, c), "a").Values()
		require.NoError(t, err)
		assert.Len(t, vals, 2)
	})
	t.Run("an invalid value is skipped, the others stay", func(t *testing.T) {
		c := append([]byte(nil), b...)
		list := int(keyField(c, a, nkValueList))
		put32(c, baseBlockSize+list+4+4, 0x7FFFFFF8)
		vals, err := keyAt(t, mustOpen(t, c), "a").Values()
		require.NoError(t, err)
		assert.Len(t, vals, 2)
	})
	t.Run("value name longer than its cell", func(t *testing.T) {
		c := append([]byte(nil), b...)
		list := int(keyField(c, a, nkValueList))
		vk := int(le32(c, baseBlockSize+list+4))
		put16(c, baseBlockSize+vk+4+2, 0xFFFF)
		vals, err := keyAt(t, mustOpen(t, c), "a").Values()
		require.NoError(t, err)
		assert.Len(t, vals, 2)
	})
}

// failAfter is a reader that fails with a non-EOF error after n bytes.
type failAfter struct {
	r io.ReaderAt
	n int64
}

var errBoom = errors.New("boom")

func (f failAfter) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.n {
		return 0, errBoom
	}
	return f.r.ReadAt(p, off)
}

// R8: regparser retried reads that failed with an error other than EOF without
// advancing.
func TestReadErrorsEndTheCall(t *testing.T) {
	b := fixture(t)
	for _, limit := range []int64{100, 4096, 4096 + 200, int64(len(b)) / 2, int64(len(b)) - 1} {
		within(t, 10*time.Second, func() {
			h, err := Open(failAfter{bytes.NewReader(b), limit}, int64(len(b)))
			if err != nil {
				return
			}
			_ = h.Walk(1_000_000, func(k Key) error {
				vals, _ := k.Values()
				for _, v := range vals {
					_, _ = v.Data()
				}
				return nil
			})
		})
	}
}

func TestDecodeName(t *testing.T) {
	assert.Equal(t, "café", DecodeName([]byte("caf\xe9"), true))
	assert.Equal(t, "ab", DecodeName([]byte("a\x00b\x00"), false))
	assert.Equal(t, "日本", DecodeName(utf16le("日本"), false))
	assert.Equal(t, "a", DecodeName([]byte("a\x00b"), false), "a trailing odd byte is dropped")
	assert.Equal(t, "�", DecodeName([]byte{0x00, 0xD8}, false), "an unpaired surrogate does not panic")
	assert.Equal(t, "", DecodeName(nil, false))
}

func TestValueInlineData(t *testing.T) {
	bl, _, _ := attackHive()
	vals := make([]uint32, 0, 5)
	for i, size := range []uint32{0x80000000, 0x80000001, 0x80000002, 0x80000004, 0} {
		vals = append(vals, bl.add(vkCell(string(rune('a'+i)), 3, size, 0x04030201)))
	}
	list := bl.add(offsets(vals...))
	b := bl.bytes()
	a := keyAt(t, mustOpen(t, b), "a")
	patchKey(b, a, nkValueCount, 5)
	patchKey(b, a, nkValueList, list)
	a = keyAt(t, mustOpen(t, b), "a")
	want := map[string][]byte{"a": nil, "b": {1}, "c": {1, 2}, "d": {1, 2, 3, 4}, "e": nil}
	for name, w := range want {
		d, err := valueNamed(t, a, name).Data()
		require.NoError(t, err, name)
		assert.Equal(t, w, d, name)
	}
}

// guard is the safety net behind the public entry points; with noRecover set
// (as the fuzz targets do) it re-raises instead.
func TestGuardConvertsPanics(t *testing.T) {
	f := func() (err error) {
		defer guard(&err)
		panic("boom")
	}
	assert.ErrorIs(t, f(), ErrCorrupt)

	noRecover = true
	defer func() { noRecover = false }()
	assert.Panics(t, func() { _ = f() })
}

func FuzzOpenWalk(f *testing.F) {
	noRecover = true // the fuzzer must see a panic, not an error
	defer func() { noRecover = false }()
	bl, _, _ := attackHive()
	f.Add(bl.bytes())
	// the 300 KB fixture and the regression hives are run by their own tests;
	// as fuzz seeds they only make mutation slow
	seeds := func(mod func(b []byte, h *Hive)) {
		bl, _, _ := attackHive()
		b := bl.bytes()
		h, err := openBytes(b)
		if err != nil {
			f.Fatal(err)
		}
		mod(b, h)
		f.Add(b)
	}
	root := func(h *Hive) Key { k, _ := h.Root(); return k }
	seeds(func(b []byte, h *Hive) { patchKey(b, root(h), nkSubkeyCount, 0xFFFFFFFF) })
	seeds(func(b []byte, h *Hive) { patchKey(b, root(h), nkSubkeyList, root(h).Offset) })
	seeds(func(b []byte, h *Hive) {
		a, _ := root(h).Subkeys()
		patchKey(b, a[0], nkValueCount, 0xFFFFFFFF)
	})
	seeds(func(b []byte, h *Hive) {
		a, _ := root(h).Subkeys()
		patchKey(b, a[0], nkValueList, root(h).Offset)
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := openBytes(data)
		if err != nil {
			return
		}
		_ = h.Walk(2000, func(k Key) error {
			vals, _ := k.Values()
			for i, v := range vals {
				if i == 16 {
					break
				}
				if v.Size() <= 1<<20 {
					_, _ = v.Data()
				}
			}
			return nil
		})
	})
}

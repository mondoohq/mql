// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package regf reads Windows registry hive files (the "regf" format) from
// files that an attacker may have crafted, such as the registry of a disk
// image that is being scanned.
//
// The parser is written from the public format specification by Maxim
// Suhanov (https://github.com/msuhanov/regf, CC BY 4.0). The regparser module
// (www.velocidex.com/golang/regparser, Apache-2.0) was consulted as prior art
// for field offsets; no code was taken from it.
//
// Every structure that is read is validated first: offsets must point into the
// hive bins area, cells must be allocated and large enough for the fields that
// are read from them, counts must fit their cells and stay below fixed limits,
// and lists are walked iteratively with a visited set, so no input can cause a
// panic, unbounded recursion, an endless loop or an allocation larger than the
// limits below. A damaged element is an error (or is skipped and logged at
// debug level, where noted), never a crash.
//
// Dirty hives are recovered in memory from the new-format transaction logs
// (Windows 8.1 and later); see Open.
package regf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/rs/zerolog/log"
)

// Limits that bound the work and memory one hive can cause.
const (
	// MaxSubkeys is the largest subkey count of one key that is read.
	MaxSubkeys = 1 << 20
	// MaxValues is the largest value count of one key that is read.
	MaxValues = 65535
	// MaxValueSize is the largest value data that is read; a larger value
	// fails with ErrTooLarge.
	MaxValueSize = 16 << 20
	// MaxCellSize is the largest cell that is accepted.
	MaxCellSize = 16 << 20

	// nameBudget bounds the bytes of key names read by one Subkeys call.
	nameBudget = 64 << 20

	baseBlockSize     = 4096
	maxBinsSize       = 1 << 31 // hives are limited to 2 GiB
	bigDataSegmentMax = 16344
	noOffset          = 0xFFFFFFFF
)

var (
	// ErrCorrupt marks a structure that violates the format.
	ErrCorrupt = errors.New("corrupt registry hive")
	// ErrTooLarge marks a structure that exceeds one of the limits.
	ErrTooLarge = errors.New("registry hive structure exceeds the supported limits")
)

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// noRecover disables the panic safety net. Only the fuzz targets set it, so
// that a bug that would panic is found instead of being converted to an error.
var noRecover bool

// guard converts a panic into an error. It is defense in depth: every access
// is bounds-checked, so it is not expected to fire.
func guard(err *error) {
	if noRecover {
		return
	}
	if r := recover(); r != nil {
		log.Error().Interface("panic", r).Msg("registry hive parser panicked, treating the hive as corrupt")
		*err = corrupt("internal error while parsing: %v", r)
	}
}

// Hive is an opened registry hive. It is safe for concurrent use when the
// underlying readers are (os.File is).
type Hive struct {
	r        io.ReaderAt
	binsSize int64 // size of the hive bins data
	root     uint32
	major    uint32
	minor    uint32

	dirty    bool
	replayed int // log entries applied in memory
}

// Dirty reports whether the base block says the hive was not cleanly written
// (its sequence numbers differ).
func (h *Hive) Dirty() bool { return h.dirty }

// Replayed returns the number of transaction log entries applied in memory.
func (h *Hive) Replayed() int { return h.replayed }

// Open parses the hive in r, which holds size bytes. When the hive is dirty
// and logs are given, new-format transaction log entries are replayed in
// memory over r (r itself is never written). The logs must stay readable for
// as long as the Hive is used when Replayed is not 0.
//
// A log that cannot be applied is ignored (and logged at debug level), so the
// hive is then read as it is.
func Open(r io.ReaderAt, size int64, logs ...Log) (h *Hive, err error) {
	defer guard(&err)
	if size < baseBlockSize {
		return nil, corrupt("file is %d bytes, smaller than the %d byte base block", size, baseBlockSize)
	}
	bb := make([]byte, baseBlockSize)
	if err := readFull(r, bb, 0); err != nil {
		return nil, err
	}
	if string(bb[0:4]) != "regf" {
		return nil, corrupt("bad signature %q", bb[0:4])
	}
	h = &Hive{
		r:        r,
		binsSize: int64(binary.LittleEndian.Uint32(bb[40:44])),
		root:     binary.LittleEndian.Uint32(bb[36:40]),
		major:    binary.LittleEndian.Uint32(bb[20:24]),
		minor:    binary.LittleEndian.Uint32(bb[24:28]),
	}
	seq1 := binary.LittleEndian.Uint32(bb[4:8])
	seq2 := binary.LittleEndian.Uint32(bb[8:12])
	h.dirty = seq1 != seq2
	if h.major != 1 || h.minor < 3 || h.minor > 6 {
		log.Debug().Uint32("major", h.major).Uint32("minor", h.minor).Msg("registry hive has an unexpected version, trying anyway")
	}
	if h.binsSize > maxBinsSize {
		return nil, corrupt("hive bins data size %d exceeds the limit", h.binsSize)
	}
	if h.dirty && len(logs) > 0 {
		if o, err := planRecovery(r, size, seq2, logs); err != nil {
			log.Debug().Err(err).Msg("registry hive transaction logs not applied, reading the hive as is")
		} else if o != nil {
			h.r = o
			h.binsSize = o.binsSize
			h.replayed = o.entries
		}
	}
	if h.replayed == 0 && h.binsSize > size-baseBlockSize {
		return nil, corrupt("hive bins data size %d is larger than the file (%d bytes)", h.binsSize, size)
	}
	if _, err := h.Root(); err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	return h, nil
}

// readFull reads exactly len(p) bytes at off.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("read %d bytes at %d: %w", len(p), off, err)
}

// cell is a validated, allocated cell.
type cell struct {
	off  int64 // file offset of the cell data (after the size field)
	size int   // bytes of cell data
}

// cell validates the cell at the hive bins data offset off.
func (h *Hive) cell(off uint32) (cell, error) {
	if off == noOffset {
		return cell{}, corrupt("offset points nowhere")
	}
	if off&7 != 0 {
		return cell{}, corrupt("cell offset %#x is not 8-byte aligned", off)
	}
	o := int64(off)
	if o+8 > h.binsSize {
		return cell{}, corrupt("cell offset %#x is outside the hive bins", off)
	}
	var b [4]byte
	if err := readFull(h.r, b[:], baseBlockSize+o); err != nil {
		return cell{}, err
	}
	sz := int64(int32(binary.LittleEndian.Uint32(b[:])))
	if sz >= 0 {
		return cell{}, corrupt("cell %#x is not allocated", off)
	}
	n := -sz
	if n < 8 || n > MaxCellSize || o+n > h.binsSize {
		return cell{}, corrupt("cell %#x has invalid size %d", off, n)
	}
	return cell{off: baseBlockSize + o + 4, size: int(n - 4)}, nil
}

// read returns n bytes of the cell data starting at start. The range must lie
// within the cell.
func (h *Hive) read(c cell, start, n int) ([]byte, error) {
	if start < 0 || n < 0 || start > c.size || n > c.size-start {
		return nil, corrupt("read of %d bytes at %d exceeds the cell (%d bytes)", n, start, c.size)
	}
	buf := make([]byte, n)
	if err := readFull(h.r, buf, c.off+int64(start)); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeName decodes a key or value name: Latin-1 when compressed, otherwise
// UTF-16LE (a trailing odd byte is dropped).
func DecodeName(raw []byte, compressed bool) string {
	if compressed {
		var sb strings.Builder
		sb.Grow(len(raw))
		for _, b := range raw {
			sb.WriteRune(rune(b))
		}
		return sb.String()
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(units))
}

// Key is a registry key.
type Key struct {
	h *Hive
	// Offset identifies the key within its hive; use it as the key of a
	// visited set when walking the hive.
	Offset uint32
	Name   string

	subkeyCount uint32
	subkeyList  uint32
	valueCount  uint32
	valueList   uint32
}

const (
	nkHeaderSize = 76
	vkHeaderSize = 20
)

// key parses the key node cell at off.
func (h *Hive) key(off uint32) (Key, error) {
	c, err := h.cell(off)
	if err != nil {
		return Key{}, err
	}
	if c.size < nkHeaderSize {
		return Key{}, corrupt("key cell %#x is too small (%d bytes)", off, c.size)
	}
	// read the header and, in the same call, a typical name
	first := min(c.size, nkHeaderSize+96)
	b, err := h.read(c, 0, first)
	if err != nil {
		return Key{}, err
	}
	if b[0] != 'n' || b[1] != 'k' {
		return Key{}, corrupt("cell %#x is not a key node", off)
	}
	flags := binary.LittleEndian.Uint16(b[2:])
	nameLen := int(binary.LittleEndian.Uint16(b[72:]))
	if nkHeaderSize+nameLen > c.size {
		return Key{}, corrupt("key name of %d bytes does not fit its cell %#x", nameLen, off)
	}
	var raw []byte
	if nkHeaderSize+nameLen <= len(b) {
		raw = b[nkHeaderSize : nkHeaderSize+nameLen]
	} else if raw, err = h.read(c, nkHeaderSize, nameLen); err != nil {
		return Key{}, err
	}
	return Key{
		h:           h,
		Offset:      off,
		Name:        DecodeName(raw, flags&0x20 != 0),
		subkeyCount: binary.LittleEndian.Uint32(b[20:]),
		subkeyList:  binary.LittleEndian.Uint32(b[28:]),
		valueCount:  binary.LittleEndian.Uint32(b[36:]),
		valueList:   binary.LittleEndian.Uint32(b[40:]),
	}, nil
}

// Root returns the root key.
func (h *Hive) Root() (k Key, err error) {
	defer guard(&err)
	return h.key(h.root)
}

// SubkeyCount returns the subkey count the key declares.
func (k Key) SubkeyCount() uint32 { return k.subkeyCount }

// ValueCount returns the value count the key declares.
func (k Key) ValueCount() uint32 { return k.valueCount }

// Subkeys returns the subkeys in stored order. A child whose cell is invalid
// or that is listed twice is skipped. The result never has more entries than
// the key declares. A list that violates the format (a subkey list of a bad
// kind, an index root that points to an index root or to a list that was
// already read, a count that does not fit its cell) fails the call.
func (k Key) Subkeys() (keys []Key, err error) {
	defer guard(&err)
	if k.subkeyCount == 0 {
		return nil, nil
	}
	if k.subkeyCount > MaxSubkeys {
		return nil, fmt.Errorf("%w: key %q declares %d subkeys", ErrTooLarge, k.Name, k.subkeyCount)
	}
	h := k.h
	want := int(k.subkeyCount)
	visitedLists := map[uint32]struct{}{}
	seen := make(map[uint32]struct{}, min(want, 1024))
	budget := nameBudget

	addLeaf := func(offs []uint32) {
		for _, off := range offs {
			if len(keys) >= want || budget < 0 {
				return
			}
			if _, dup := seen[off]; dup {
				log.Debug().Uint32("offset", off).Str("key", k.Name).Msg("registry hive lists a subkey twice, skipping it")
				continue
			}
			seen[off] = struct{}{}
			child, err := h.key(off)
			if err != nil {
				log.Debug().Err(err).Uint32("offset", off).Str("key", k.Name).Msg("skipping invalid subkey")
				continue
			}
			budget -= len(child.Name) + nkHeaderSize
			if budget < 0 {
				return
			}
			keys = append(keys, child)
		}
	}

	kind, elems, err := h.subkeyList(k.subkeyList, visitedLists)
	if err != nil {
		return nil, err
	}
	if kind == 'r' {
		for _, lo := range elems {
			if len(keys) >= want {
				break
			}
			lk, le, err := h.subkeyList(lo, visitedLists)
			if err != nil {
				return nil, err
			}
			if lk == 'r' {
				return nil, corrupt("index root %#x points to another index root", lo)
			}
			addLeaf(le)
		}
	} else {
		addLeaf(elems)
	}
	if budget < 0 {
		return keys, fmt.Errorf("%w: names of the subkeys of %q", ErrTooLarge, k.Name)
	}
	if len(keys) != want {
		log.Debug().Str("key", k.Name).Int("declared", want).Int("found", len(keys)).Msg("registry key lists a different number of subkeys than it declares")
	}
	return keys, nil
}

// subkeyList reads the list cell at off. It returns 'r' with the offsets of
// the leaf lists for an index root, otherwise 'l' with the offsets of the
// subkeys. A list may be read once per Subkeys call.
func (h *Hive) subkeyList(off uint32, visited map[uint32]struct{}) (kind byte, elems []uint32, err error) {
	if _, dup := visited[off]; dup {
		return 0, nil, corrupt("subkey list %#x is referenced twice", off)
	}
	visited[off] = struct{}{}
	c, err := h.cell(off)
	if err != nil {
		return 0, nil, err
	}
	if c.size < 4 {
		return 0, nil, corrupt("subkey list %#x is too small", off)
	}
	hdr, err := h.read(c, 0, 4)
	if err != nil {
		return 0, nil, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[2:]))
	var stride int
	switch string(hdr[0:2]) {
	case "lf", "lh":
		stride, kind = 8, 'l'
	case "li":
		stride, kind = 4, 'l'
	case "ri":
		stride, kind = 4, 'r'
	default:
		return 0, nil, corrupt("cell %#x is not a subkey list (%q)", off, hdr[0:2])
	}
	if 4+n*stride > c.size {
		return 0, nil, corrupt("subkey list %#x declares %d elements, more than fit its cell", off, n)
	}
	body, err := h.read(c, 4, n*stride)
	if err != nil {
		return 0, nil, err
	}
	elems = make([]uint32, n)
	for i := range elems {
		elems[i] = binary.LittleEndian.Uint32(body[i*stride:])
	}
	return kind, elems, nil
}

// Value is a registry value. Its data is read on demand with Data.
type Value struct {
	h    *Hive
	Name string
	// Type is the registry value type (REG_SZ is 1, REG_DWORD is 4, ...).
	Type    uint32
	rawSize uint32
	dataOff uint32
}

// Size returns the data size the value declares.
func (v Value) Size() int { return int(v.rawSize & 0x7FFFFFFF) }

// Values returns the values in stored order. A value whose cell is invalid or
// that is listed twice is skipped.
func (k Key) Values() (values []Value, err error) {
	defer guard(&err)
	if k.valueCount == 0 {
		return nil, nil
	}
	if k.valueCount > MaxValues {
		return nil, fmt.Errorf("%w: key %q declares %d values", ErrTooLarge, k.Name, k.valueCount)
	}
	h := k.h
	n := int(k.valueCount)
	lc, err := h.cell(k.valueList)
	if err != nil {
		return nil, fmt.Errorf("value list of %q: %w", k.Name, err)
	}
	if 4*n > lc.size {
		return nil, corrupt("value list of %q declares %d values, more than fit its cell", k.Name, n)
	}
	list, err := h.read(lc, 0, 4*n)
	if err != nil {
		return nil, err
	}
	seen := make(map[uint32]struct{}, n)
	values = make([]Value, 0, n)
	for i := range n {
		off := binary.LittleEndian.Uint32(list[4*i:])
		if _, dup := seen[off]; dup {
			log.Debug().Uint32("offset", off).Str("key", k.Name).Msg("registry key lists a value twice, skipping it")
			continue
		}
		seen[off] = struct{}{}
		v, err := h.value(off)
		if err != nil {
			log.Debug().Err(err).Uint32("offset", off).Str("key", k.Name).Msg("skipping invalid value")
			continue
		}
		values = append(values, v)
	}
	return values, nil
}

func (h *Hive) value(off uint32) (Value, error) {
	c, err := h.cell(off)
	if err != nil {
		return Value{}, err
	}
	if c.size < vkHeaderSize {
		return Value{}, corrupt("value cell %#x is too small", off)
	}
	b, err := h.read(c, 0, min(c.size, vkHeaderSize+64))
	if err != nil {
		return Value{}, err
	}
	if b[0] != 'v' || b[1] != 'k' {
		return Value{}, corrupt("cell %#x is not a key value", off)
	}
	nameLen := int(binary.LittleEndian.Uint16(b[2:]))
	if vkHeaderSize+nameLen > c.size {
		return Value{}, corrupt("value name of %d bytes does not fit its cell %#x", nameLen, off)
	}
	var raw []byte
	if vkHeaderSize+nameLen <= len(b) {
		raw = b[vkHeaderSize : vkHeaderSize+nameLen]
	} else if raw, err = h.read(c, vkHeaderSize, nameLen); err != nil {
		return Value{}, err
	}
	flags := binary.LittleEndian.Uint16(b[16:])
	return Value{
		h:       h,
		Name:    DecodeName(raw, flags&1 != 0),
		Type:    binary.LittleEndian.Uint32(b[12:]),
		rawSize: binary.LittleEndian.Uint32(b[4:]),
		dataOff: binary.LittleEndian.Uint32(b[8:]),
	}, nil
}

// Data returns the value's data exactly as stored. It fails with ErrTooLarge
// above MaxValueSize and with ErrCorrupt when the data is not where the value
// says it is; other values are not affected.
func (v Value) Data() (data []byte, err error) {
	defer guard(&err)
	size := v.Size()
	if size == 0 {
		return nil, nil
	}
	if size > MaxValueSize {
		return nil, fmt.Errorf("%w: value %q declares %d bytes", ErrTooLarge, v.Name, size)
	}
	if v.rawSize&0x80000000 != 0 {
		if size > 4 {
			return nil, corrupt("inline value %q declares %d bytes", v.Name, size)
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v.dataOff)
		return b[:size:size], nil
	}
	h := v.h
	c, err := h.cell(v.dataOff)
	if err != nil {
		return nil, fmt.Errorf("data of value %q: %w", v.Name, err)
	}
	if h.minor >= 4 && size > bigDataSegmentMax {
		return h.bigData(v, c, size)
	}
	if size > c.size {
		return nil, corrupt("data of value %q (%d bytes) does not fit its cell (%d bytes)", v.Name, size, c.size)
	}
	return h.read(c, 0, size)
}

// bigData assembles the data of a "db" record: its segments must be exactly as
// many as the size requires, each of them full except the last.
func (h *Hive) bigData(v Value, c cell, size int) ([]byte, error) {
	if c.size < 8 {
		return nil, corrupt("big data record of %q is too small", v.Name)
	}
	hdr, err := h.read(c, 0, 8)
	if err != nil {
		return nil, err
	}
	if hdr[0] != 'd' || hdr[1] != 'b' {
		return nil, corrupt("data of value %q is not a big data record", v.Name)
	}
	count := int(binary.LittleEndian.Uint16(hdr[2:]))
	want := (size + bigDataSegmentMax - 1) / bigDataSegmentMax
	if count != want {
		return nil, corrupt("big data of %q has %d segments, %d bytes need %d", v.Name, count, size, want)
	}
	lc, err := h.cell(binary.LittleEndian.Uint32(hdr[4:]))
	if err != nil {
		return nil, fmt.Errorf("segment list of value %q: %w", v.Name, err)
	}
	if 4*count > lc.size {
		return nil, corrupt("segment list of %q does not fit its cell", v.Name)
	}
	list, err := h.read(lc, 0, 4*count)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, size)
	for i := range count {
		take := min(bigDataSegmentMax, size-len(data))
		sc, err := h.cell(binary.LittleEndian.Uint32(list[4*i:]))
		if err != nil {
			return nil, fmt.Errorf("segment %d of value %q: %w", i, v.Name, err)
		}
		seg, err := h.read(sc, 0, take)
		if err != nil {
			return nil, fmt.Errorf("segment %d of value %q: %w", i, v.Name, err)
		}
		data = append(data, seg...)
	}
	return data, nil
}

// Walk visits the root key and, depth first, every key below it exactly once,
// whatever the subkey lists say (a subkey that points to an ancestor is
// visited once). It stops with ErrTooLarge after maxKeys keys. A key whose
// subkeys cannot be read is visited, its subkeys are skipped. If fn returns an
// error the walk stops with it.
func (h *Hive) Walk(maxKeys int, fn func(Key) error) (err error) {
	defer guard(&err)
	root, err := h.Root()
	if err != nil {
		return err
	}
	visited := map[uint32]struct{}{root.Offset: {}}
	stack := []Key{root}
	count := 0
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if count++; count > maxKeys {
			return fmt.Errorf("%w: more than %d keys", ErrTooLarge, maxKeys)
		}
		if err := fn(k); err != nil {
			return err
		}
		subs, err := k.Subkeys()
		if err != nil {
			log.Debug().Err(err).Str("key", k.Name).Msg("skipping the subkeys of a key with an invalid subkey list")
		}
		for _, sub := range slices.Backward(subs) {
			if _, ok := visited[sub.Offset]; ok {
				continue
			}
			visited[sub.Offset] = struct{}{}
			stack = append(stack, sub)
		}
	}
	return nil
}

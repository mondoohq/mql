// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// A compiled dconf database is a GVDB file (glib's gvdb-format.h): a header,
// then hash tables of items. dconf update writes one item per key, named by
// its full path (/org/gnome/desktop/session/idle-delay) through a chain of
// parent items, with the value as a variant, plus a ".locks" table whose
// item names are the locked keys.

const (
	gvdbHeaderSize = 24
	gvdbItemSize   = 24
	noParent       = 0xffffffff
)

// ErrNotDatabase is returned for a file that is not a compiled database,
// including one whose header dconf update cleared when it replaced it. dconf
// ignores such a file.
var ErrNotDatabase = errors.New("not a dconf database")

var (
	gvdbSignature        = []byte("GVariant")
	gvdbSwappedSignature = []byte("raVGtnai")
)

// Database is the content of a compiled dconf database.
type Database struct {
	Values map[string]any
	Locks  []string
}

type gvdbFile struct {
	data  []byte
	order binary.ByteOrder
}

// ReadDatabase decodes a compiled dconf database. dconf writes it in little
// endian on every architecture (a database compiled on s390x is byte for byte
// the one compiled on x86_64); the byte-swapped signature is read for
// completeness. A file whose header was
// cleared, as dconf update does to the database it replaces, is an error.
func ReadDatabase(data []byte) (*Database, error) {
	if len(data) < gvdbHeaderSize {
		return nil, ErrNotDatabase
	}
	f := &gvdbFile{data: data}
	switch {
	case bytes.Equal(data[:8], gvdbSignature):
		f.order = binary.LittleEndian
	case bytes.Equal(data[:8], gvdbSwappedSignature):
		f.order = binary.BigEndian
	default:
		return nil, ErrNotDatabase
	}

	root, err := f.table(f.order.Uint32(data[16:]), f.order.Uint32(data[20:]))
	if err != nil {
		return nil, err
	}

	db := &Database{Values: map[string]any{}}
	for i := 0; i < root.count(); i++ {
		item := root.item(i)
		switch item.typ {
		case 'v':
			name, err := root.name(i)
			if err != nil {
				return nil, err
			}
			v, err := f.variant(item)
			if err != nil {
				return nil, fmt.Errorf("value of %s: %w", name, err)
			}
			db.Values[name] = v
		case 'H':
			name, err := root.name(i)
			if err != nil {
				return nil, err
			}
			if name != ".locks" {
				continue
			}
			locks, err := f.table(item.start, item.end)
			if err != nil {
				return nil, err
			}
			for j := 0; j < locks.count(); j++ {
				if locks.item(j).typ != 'v' && locks.item(j).typ != 's' {
					continue
				}
				lock, err := locks.name(j)
				if err != nil {
					return nil, err
				}
				db.Locks = append(db.Locks, lock)
			}
		}
	}
	return db, nil
}

type gvdbTable struct {
	f     *gvdbFile
	items []byte
}

type gvdbItem struct {
	parent   uint32
	keyStart uint32
	keySize  uint16
	typ      byte
	start    uint32
	end      uint32
}

func (f *gvdbFile) slice(start, end uint32) ([]byte, error) {
	if start > end || int(end) > len(f.data) {
		return nil, fmt.Errorf("invalid pointer %d-%d in a file of %d bytes", start, end, len(f.data))
	}
	return f.data[start:end], nil
}

func (f *gvdbFile) table(start, end uint32) (*gvdbTable, error) {
	b, err := f.slice(start, end)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, errors.New("hash table is too short")
	}
	nBloom := f.order.Uint32(b) & (1<<27 - 1)
	nBuckets := f.order.Uint32(b[4:])
	off := 8 + 4*uint64(nBloom) + 4*uint64(nBuckets)
	if off > uint64(len(b)) {
		return nil, errors.New("hash table header exceeds the table")
	}
	items := b[off:]
	return &gvdbTable{f: f, items: items[:len(items)/gvdbItemSize*gvdbItemSize]}, nil
}

func (t *gvdbTable) count() int { return len(t.items) / gvdbItemSize }

func (t *gvdbTable) item(i int) gvdbItem {
	b := t.items[i*gvdbItemSize:]
	o := t.f.order
	return gvdbItem{
		parent:   o.Uint32(b[4:]),
		keyStart: o.Uint32(b[8:]),
		keySize:  o.Uint16(b[12:]),
		typ:      b[14],
		start:    o.Uint32(b[16:]),
		end:      o.Uint32(b[20:]),
	}
}

// name builds an item's full name from its parents' names.
func (t *gvdbTable) name(i int) (string, error) {
	var parts [][]byte
	for depth := 0; ; depth++ {
		if depth > t.count() {
			return "", errors.New("item names form a cycle")
		}
		item := t.item(i)
		frag, err := t.f.slice(item.keyStart, item.keyStart+uint32(item.keySize))
		if err != nil {
			return "", err
		}
		parts = append(parts, frag)
		if item.parent == noParent {
			break
		}
		if int(item.parent) >= t.count() {
			return "", errors.New("item parent is out of range")
		}
		i = int(item.parent)
	}
	var b bytes.Buffer
	for j := len(parts) - 1; j >= 0; j-- {
		b.Write(parts[j])
	}
	return b.String(), nil
}

func (f *gvdbFile) variant(item gvdbItem) (any, error) {
	b, err := f.slice(item.start, item.end)
	if err != nil {
		return nil, err
	}
	return DecodeVariant(b, f.order)
}

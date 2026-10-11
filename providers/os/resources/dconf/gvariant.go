// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Values decoded from GVariants are plain Go values: bool, int64 for every
// integer type, float64 for doubles, string for strings, object paths and
// signatures, []any for arrays and tuples, map[string]any for dictionaries
// (keys formatted as strings), and nil for a maybe that holds nothing. A
// variant is replaced by the value it holds.

// gvType is a parsed GVariant type string.
type gvType struct {
	kind    byte // a basic type character, or 'a', 'm', '(', '{', 'v'
	elem    *gvType
	members []*gvType
}

func parseType(sig string) (*gvType, string, error) {
	if sig == "" {
		return nil, "", errors.New("empty type")
	}
	c := sig[0]
	switch c {
	case 'b', 'y', 'n', 'q', 'i', 'u', 'x', 't', 'h', 'd', 's', 'o', 'g', 'v':
		return &gvType{kind: c}, sig[1:], nil
	case 'a', 'm':
		elem, rest, err := parseType(sig[1:])
		if err != nil {
			return nil, "", err
		}
		return &gvType{kind: c, elem: elem}, rest, nil
	case '(', '{':
		end := byte(')')
		if c == '{' {
			end = '}'
		}
		t := &gvType{kind: c}
		rest := sig[1:]
		for {
			if rest == "" {
				return nil, "", fmt.Errorf("unterminated type %q", sig)
			}
			if rest[0] == end {
				rest = rest[1:]
				break
			}
			m, r, err := parseType(rest)
			if err != nil {
				return nil, "", err
			}
			t.members = append(t.members, m)
			rest = r
		}
		if c == '{' && len(t.members) != 2 {
			return nil, "", fmt.Errorf("dictionary entry %q needs two members", sig)
		}
		return t, rest, nil
	}
	return nil, "", fmt.Errorf("unsupported type %q", sig)
}

// ParseType parses a complete GVariant type string.
func ParseType(sig string) (*gvType, error) {
	t, rest, err := parseType(sig)
	if err != nil {
		return nil, err
	}
	if rest != "" {
		return nil, fmt.Errorf("trailing characters in type %q", sig)
	}
	return t, nil
}

func (t *gvType) alignment() int {
	switch t.kind {
	case 'n', 'q':
		return 2
	case 'i', 'u', 'h':
		return 4
	case 'x', 't', 'd', 'v':
		return 8
	case 'a', 'm':
		return t.elem.alignment()
	case '(', '{':
		a := 1
		for _, m := range t.members {
			if ma := m.alignment(); ma > a {
				a = ma
			}
		}
		return a
	}
	return 1
}

// fixedSize returns the size of a fixed-size type, or 0 for a variable-size one.
func (t *gvType) fixedSize() int {
	switch t.kind {
	case 'b', 'y':
		return 1
	case 'n', 'q':
		return 2
	case 'i', 'u', 'h':
		return 4
	case 'x', 't', 'd':
		return 8
	case '(', '{':
		size := 0
		for _, m := range t.members {
			ms := m.fixedSize()
			if ms == 0 {
				return 0
			}
			size = align(size, m.alignment()) + ms
		}
		if size == 0 {
			return 1 // the unit tuple
		}
		return align(size, t.alignment())
	}
	return 0
}

func align(n, a int) int {
	return (n + a - 1) &^ (a - 1)
}

// offsetSize is the size of a framing offset in a container of n bytes.
func offsetSize(n int) int {
	switch {
	case n == 0:
		return 0
	case n <= 0xff:
		return 1
	case n <= 0xffff:
		return 2
	case uint64(n) <= 0xffffffff:
		return 4
	}
	return 8
}

func readOffset(b []byte, order binary.ByteOrder) int {
	switch len(b) {
	case 1:
		return int(b[0])
	case 2:
		return int(order.Uint16(b))
	case 4:
		return int(order.Uint32(b))
	case 8:
		return int(order.Uint64(b))
	}
	return 0
}

// DecodeVariant decodes a serialized variant: the value, a zero byte and
// the value's type string.
func DecodeVariant(data []byte, order binary.ByteOrder) (any, error) {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			continue
		}
		t, err := ParseType(string(data[i+1:]))
		if err != nil {
			return nil, err
		}
		return decode(t, data[:i], order)
	}
	return nil, errors.New("variant without a type")
}

var errShort = errors.New("serialized value is too short")

func decode(t *gvType, data []byte, order binary.ByteOrder) (any, error) {
	if fs := t.fixedSize(); fs > 0 && len(data) != fs {
		// GVariant reads a fixed-size value of the wrong size as the default
		// value; a database dconf wrote never has one.
		return nil, errShort
	}
	switch t.kind {
	case 'b':
		return data[0] != 0, nil
	case 'y':
		return int64(data[0]), nil
	case 'n':
		return int64(int16(order.Uint16(data))), nil
	case 'q':
		return int64(order.Uint16(data)), nil
	case 'i', 'h':
		return int64(int32(order.Uint32(data))), nil
	case 'u':
		return int64(order.Uint32(data)), nil
	case 'x':
		return int64(order.Uint64(data)), nil
	case 't':
		return int64(order.Uint64(data)), nil
	case 'd':
		return math.Float64frombits(order.Uint64(data)), nil
	case 's', 'o', 'g':
		if len(data) == 0 || data[len(data)-1] != 0 {
			return nil, errors.New("string is not terminated")
		}
		return string(data[:len(data)-1]), nil
	case 'v':
		return DecodeVariant(data, order)
	case 'm':
		if len(data) == 0 {
			return nil, nil
		}
		if t.elem.fixedSize() > 0 {
			return decode(t.elem, data, order)
		}
		return decode(t.elem, data[:len(data)-1], order)
	case 'a':
		return decodeArray(t, data, order)
	case '(', '{':
		return decodeTuple(t, data, order)
	}
	return nil, fmt.Errorf("unsupported type %c", t.kind)
}

func decodeArray(t *gvType, data []byte, order binary.ByteOrder) (any, error) {
	var items [][]byte
	if size := t.elem.fixedSize(); size > 0 {
		if len(data)%size != 0 {
			return nil, errShort
		}
		for i := 0; i < len(data); i += size {
			items = append(items, data[i:i+size])
		}
	} else if len(data) > 0 {
		osz := offsetSize(len(data))
		last := readOffset(data[len(data)-osz:], order)
		if last > len(data) || (len(data)-last)%osz != 0 {
			return nil, errShort
		}
		n := (len(data) - last) / osz
		start := 0
		for i := 0; i < n; i++ {
			end := readOffset(data[last+i*osz:last+(i+1)*osz], order)
			start = align(start, t.elem.alignment())
			if start > end || end > last {
				return nil, errShort
			}
			items = append(items, data[start:end])
			start = end
		}
	}

	if t.elem.kind == '{' {
		res := make(map[string]any, len(items))
		for _, item := range items {
			entry, err := decodeTuple(t.elem, item, order)
			if err != nil {
				return nil, err
			}
			kv := entry.([]any)
			res[formatKey(kv[0])] = kv[1]
		}
		return res, nil
	}

	res := make([]any, 0, len(items))
	for _, item := range items {
		v, err := decode(t.elem, item, order)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return res, nil
}

func decodeTuple(t *gvType, data []byte, order binary.ByteOrder) (any, error) {
	res := make([]any, 0, len(t.members))
	osz := offsetSize(len(data))
	offsetsEnd := len(data)
	start := 0
	for i, m := range t.members {
		start = align(start, m.alignment())
		var end int
		if size := m.fixedSize(); size > 0 {
			end = start + size
		} else if i == len(t.members)-1 {
			end = offsetsEnd
		} else {
			offsetsEnd -= osz
			if offsetsEnd < 0 {
				return nil, errShort
			}
			end = readOffset(data[offsetsEnd:offsetsEnd+osz], order)
		}
		if start > end || end > offsetsEnd {
			return nil, errShort
		}
		v, err := decode(m, data[start:end], order)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
		start = end
	}
	return res, nil
}

func formatKey(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

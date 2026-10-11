// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseText parses a value in GVariant text format, as written in dconf
// keyfiles (`uint32 900`, `'text'`, `true`, `@as []`, `[('xkb', 'us')]`), into
// the same Go values DecodeVariant returns.
func ParseText(s string) (any, error) {
	p := &textParser{s: s}
	v, err := p.value(nil)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return nil, p.errorf("unexpected %q", p.s[p.pos:])
	}
	return v, nil
}

type textParser struct {
	s   string
	pos int
}

func (p *textParser) errorf(format string, args ...any) error {
	return fmt.Errorf("gvariant text at %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *textParser) skipSpace() {
	for p.pos < len(p.s) && strings.IndexByte(" \t\n\r\f\v", p.s[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *textParser) peek() byte {
	p.skipSpace()
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *textParser) expect(c byte) error {
	if p.peek() != c {
		return p.errorf("expected %q", c)
	}
	p.pos++
	return nil
}

func (p *textParser) word() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '+' || c == '-' {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos]
}

var typeKeywords = map[string]string{
	"boolean": "b", "byte": "y", "int16": "n", "uint16": "q", "int32": "i",
	"uint32": "u", "int64": "x", "uint64": "t", "handle": "h", "double": "d",
	"string": "s", "objectpath": "o", "signature": "g",
}

// value parses one value. t is the type the value must have, or nil.
func (p *textParser) value(t *gvType) (any, error) {
	switch c := p.peek(); {
	case c == '@':
		p.pos++
		sig := p.typeString()
		at, err := ParseType(sig)
		if err != nil {
			return nil, p.errorf("%v", err)
		}
		return p.value(at)
	case c == '[':
		return p.array(t)
	case c == '(':
		return p.tuple(t)
	case c == '{':
		return p.dict(t)
	case c == '<':
		p.pos++
		v, err := p.value(nil)
		if err != nil {
			return nil, err
		}
		return v, p.expect('>')
	case c == '\'' || c == '"':
		return p.str()
	case c == 'b' && p.pos+1 < len(p.s) && (p.s[p.pos+1] == '\'' || p.s[p.pos+1] == '"'):
		p.pos++
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		b := []byte(s.(string))
		res := make([]any, 0, len(b)+1)
		for _, x := range b {
			res = append(res, int64(x))
		}
		return append(res, int64(0)), nil
	case c == 0:
		return nil, p.errorf("missing value")
	}

	start := p.pos
	w := p.word()
	switch w {
	case "":
		return nil, p.errorf("unexpected %q", p.s[p.pos:])
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "nothing":
		return nil, nil
	case "just":
		var elem *gvType
		if t != nil && t.kind == 'm' {
			elem = t.elem
		}
		return p.value(elem)
	}
	if sig, ok := typeKeywords[w]; ok {
		kt, _ := ParseType(sig)
		return p.value(kt)
	}
	p.pos = start
	return p.number(t)
}

func (p *textParser) typeString() string {
	start := p.pos
	depth := 0
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch {
		case c == '(' || c == '{':
			depth++
		case c == ')' || c == '}':
			depth--
		case strings.IndexByte("bynqiuxthdsogvam", c) >= 0:
		default:
			return p.s[start:p.pos]
		}
		p.pos++
		if depth == 0 && c != 'a' && c != 'm' {
			return p.s[start:p.pos]
		}
	}
	return p.s[start:p.pos]
}

func (p *textParser) number(t *gvType) (any, error) {
	w := p.word()
	isFloat := t != nil && t.kind == 'd'
	lw := strings.ToLower(w)
	hex := strings.HasPrefix(strings.TrimLeft(lw, "+-"), "0x")
	if !hex && (strings.ContainsAny(lw, ".e") || lw == "inf" || lw == "-inf" || lw == "nan") {
		isFloat = true
	}
	if isFloat {
		f, err := strconv.ParseFloat(w, 64)
		if err != nil {
			if strings.EqualFold(w, "nan") {
				return math.NaN(), nil
			}
			return nil, p.errorf("invalid number %q", w)
		}
		return f, nil
	}
	i, err := strconv.ParseInt(w, 0, 64)
	if err != nil {
		u, uerr := strconv.ParseUint(w, 0, 64)
		if uerr != nil {
			return nil, p.errorf("invalid number %q", w)
		}
		i = int64(u)
	}
	if t != nil && t.kind == 'b' {
		return nil, p.errorf("a number is not a boolean")
	}
	return i, nil
}

func (p *textParser) str() (any, error) {
	quote := p.s[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		p.pos++
		switch c {
		case quote:
			return b.String(), nil
		case '\\':
			if p.pos >= len(p.s) {
				return nil, p.errorf("unterminated escape")
			}
			e := p.s[p.pos]
			p.pos++
			switch e {
			case 'a':
				b.WriteByte('\a')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'v':
				b.WriteByte('\v')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				if p.pos+n > len(p.s) {
					return nil, p.errorf("short unicode escape")
				}
				r, err := strconv.ParseUint(p.s[p.pos:p.pos+n], 16, 32)
				if err != nil {
					return nil, p.errorf("invalid unicode escape")
				}
				p.pos += n
				b.WriteRune(rune(r))
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for i := 0; i < 2 && p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '7'; i++ {
						v = v*8 + int(p.s[p.pos]-'0')
						p.pos++
					}
					b.WriteByte(byte(v))
				} else {
					b.WriteByte(e)
				}
			}
		default:
			if c < utf8.RuneSelf {
				b.WriteByte(c)
			} else {
				r, size := utf8.DecodeRuneInString(p.s[p.pos-1:])
				b.WriteRune(r)
				p.pos += size - 1
			}
		}
	}
	return nil, p.errorf("unterminated string")
}

func (p *textParser) array(t *gvType) (any, error) {
	p.pos++ // [
	var elem *gvType
	if t != nil && t.kind == 'a' {
		elem = t.elem
	}
	if elem != nil && elem.kind == '{' {
		return p.dictEntries(elem, ']')
	}
	res := []any{}
	if p.peek() == ']' {
		p.pos++
		return res, nil
	}
	for {
		v, err := p.value(elem)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return unifyNumbers(res), nil
		default:
			return nil, p.errorf("expected ',' or ']'")
		}
	}
}

// unifyNumbers makes an array of integers and doubles all doubles, as
// GVariant infers one element type for the array.
func unifyNumbers(items []any) []any {
	hasFloat := false
	for _, v := range items {
		if _, ok := v.(float64); ok {
			hasFloat = true
			break
		}
	}
	if !hasFloat {
		return items
	}
	for i, v := range items {
		if n, ok := v.(int64); ok {
			items[i] = float64(n)
		}
	}
	return items
}

func (p *textParser) tuple(t *gvType) (any, error) {
	p.pos++ // (
	res := []any{}
	if p.peek() == ')' {
		p.pos++
		return res, nil
	}
	for i := 0; ; i++ {
		var mt *gvType
		if t != nil && t.kind == '(' && i < len(t.members) {
			mt = t.members[i]
		}
		v, err := p.value(mt)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
		switch p.peek() {
		case ',':
			p.pos++
			if p.peek() == ')' { // a one-tuple: ('x',)
				p.pos++
				return res, nil
			}
		case ')':
			p.pos++
			return res, nil
		default:
			return nil, p.errorf("expected ',' or ')'")
		}
	}
}

// dict parses {k: v, ...} into a map and a dictionary entry {k, v} into a
// two-element slice.
func (p *textParser) dict(t *gvType) (any, error) {
	if t != nil && t.kind == 'a' && t.elem.kind == '{' {
		p.pos++
		return p.dictEntries(t.elem, '}')
	}
	start := p.pos
	p.pos++ // {
	if p.peek() == '}' {
		p.pos++
		return map[string]any{}, nil
	}
	var kt, vt *gvType
	if t != nil && t.kind == '{' {
		kt, vt = t.members[0], t.members[1]
	}
	k, err := p.value(kt)
	if err != nil {
		return nil, err
	}
	if p.peek() == ',' {
		p.pos++
		v, err := p.value(vt)
		if err != nil {
			return nil, err
		}
		return []any{k, v}, p.expect('}')
	}
	p.pos = start + 1
	return p.dictEntries(nil, '}')
}

func (p *textParser) dictEntries(entry *gvType, end byte) (any, error) {
	var kt, vt *gvType
	if entry != nil {
		kt, vt = entry.members[0], entry.members[1]
	}
	res := map[string]any{}
	if p.peek() == end {
		p.pos++
		return res, nil
	}
	for {
		k, err := p.value(kt)
		if err != nil {
			return nil, err
		}
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		v, err := p.value(vt)
		if err != nil {
			return nil, err
		}
		res[formatKey(k)] = v
		switch p.peek() {
		case ',':
			p.pos++
		case end:
			p.pos++
			return res, nil
		default:
			return nil, p.errorf("expected ',' or %q", end)
		}
	}
}

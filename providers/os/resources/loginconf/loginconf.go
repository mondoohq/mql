// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package loginconf parses the BSD login class capability database
// /etc/login.conf. The file uses the getcap(3) format:
//
//	name|alias|...:cap=value:cap#number:boolcap:cap@:\
//		:tc=otherclass:
//
// Records span lines with a trailing backslash, records starting with `#`
// are comments, `tc=name` splices in another record's capabilities, and
// `cap@` cancels a capability. As in getcap(3), the first occurrence of a
// capability in a record wins, after tc= references are expanded in place.
package loginconf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxTcDepth is the deepest tc= nesting getcap(3) follows before it gives up
// with a reference loop error (MAX_RECURSION in getcap.c).
const MaxTcDepth = 32

// ErrTcLoop is returned when tc= references form a cycle.
var ErrTcLoop = errors.New("tc= reference loop")

// Capability is one field of a record, in the order it was written.
type Capability struct {
	Name string
	// Kind is '=' for a string, '#' for a number, '@' for a cancellation and
	// 0 for a boolean.
	Kind byte
	// Value is the raw text after `=` or `#`, without any escape processing.
	Value string
}

// Record is one class from login.conf.
type Record struct {
	// Names lists the record's names from its header, `name|alias|...`.
	// The first is the class name.
	Names []string
	// Capabilities lists the record's fields in order, including tc=.
	Capabilities []Capability
}

// Name is the class name, the first name in the record header.
func (r *Record) Name() string {
	if len(r.Names) == 0 {
		return ""
	}
	return r.Names[0]
}

// Aliases are the record's other names.
func (r *Record) Aliases() []string {
	if len(r.Names) < 2 {
		return []string{}
	}
	return r.Names[1:]
}

// Own returns the capabilities as written in this record only, the way a
// lookup in this record would see them before tc= expansion: the first
// occurrence of each name wins and a cancelled capability is left out.
// tc= references are not included, Inherits lists them.
func (r *Record) Own() map[string]any {
	res := toMap(r.Capabilities)
	delete(res, "tc")
	return res
}

// Inherits lists the class names this record references with tc=, in order.
func (r *Record) Inherits() []string {
	res := []string{}
	for _, c := range r.Capabilities {
		if c.Name == "tc" && c.Kind == '=' {
			res = append(res, c.Value)
		}
	}
	return res
}

// Database is a parsed login.conf.
type Database struct {
	// Records in file order. A record whose name repeats an earlier record's
	// name is still listed here, but lookups never reach it, as in getcap(3).
	Records []*Record
}

// Parse reads login.conf content.
func Parse(r io.Reader) (*Database, error) {
	db := &Database{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var cur strings.Builder
	flush := func() {
		rec := cur.String()
		cur.Reset()
		// getcap tosses blank lines and records starting with '#'. A comment
		// ending in a backslash swallows the next line, which matches getcap.
		if rec == "" || rec[0] == '#' {
			return
		}
		if parsed := parseRecord(rec); parsed != nil {
			db.Records = append(db.Records, parsed)
		}
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(line[:len(line)-1])
			continue
		}
		cur.WriteString(line)
		flush()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	return db, nil
}

func parseRecord(rec string) *Record {
	fields := strings.Split(rec, ":")
	header := strings.TrimSpace(fields[0])
	if header == "" {
		return nil
	}
	r := &Record{Names: strings.Split(header, "|")}
	for _, f := range fields[1:] {
		// Continuation lines indent the next field, leaving whitespace-only
		// fields between `:\` and `\t:`. getcap never matches them.
		f = strings.TrimLeft(f, " \t")
		if strings.TrimSpace(f) == "" {
			continue
		}
		r.Capabilities = append(r.Capabilities, parseCapability(f))
	}
	return r
}

func parseCapability(f string) Capability {
	i := strings.IndexAny(f, "=#@")
	if i < 0 {
		return Capability{Name: strings.TrimRight(f, " \t")}
	}
	c := Capability{Name: f[:i], Kind: f[i]}
	if c.Kind != '@' {
		c.Value = f[i+1:]
	}
	return c
}

// Lookup returns the first record that has name among its names, as
// cgetent(3) does, or nil.
func (db *Database) Lookup(name string) *Record {
	if db == nil {
		return nil
	}
	for _, r := range db.Records {
		for _, n := range r.Names {
			if n == name {
				return r
			}
		}
	}
	return nil
}

// Effective returns the record's capabilities after expanding tc=
// references in place, the record login_getclass(3) hands to the
// login_getcap*(3) functions. The first occurrence of a capability wins and a
// cancelled one (cap@) is left out. tc= itself is not part of the result.
//
// An unresolvable tc= reference or a reference loop is an error, because
// login_getclass(3) fails for such a class and login refuses it.
func (db *Database) Effective(r *Record) (map[string]any, error) {
	caps, err := db.expand(r, []string{r.Name()})
	if err != nil {
		return nil, err
	}
	res := toMap(caps)
	delete(res, "tc")
	return res, nil
}

func (db *Database) expand(r *Record, stack []string) ([]Capability, error) {
	if len(stack) > MaxTcDepth {
		return nil, fmt.Errorf("%w: %s", ErrTcLoop, strings.Join(stack, " -> "))
	}
	var res []Capability
	for _, c := range r.Capabilities {
		if c.Name != "tc" || c.Kind != '=' {
			res = append(res, c)
			continue
		}
		target := db.Lookup(c.Value)
		if target == nil {
			return nil, fmt.Errorf("class %q: cannot resolve tc=%s", r.Name(), c.Value)
		}
		for _, s := range stack {
			if s == target.Name() {
				return nil, fmt.Errorf("%w: %s -> %s", ErrTcLoop, strings.Join(stack, " -> "), target.Name())
			}
		}
		sub, err := db.expand(target, append(stack[:len(stack):len(stack)], target.Name()))
		if err != nil {
			return nil, err
		}
		res = append(res, sub...)
	}
	return res, nil
}

// toMap applies getcap's first-occurrence rule. Strings and numbers keep
// their raw text, booleans are true, and a cancellation hides every later
// occurrence of the name.
func toMap(caps []Capability) map[string]any {
	res := map[string]any{}
	seen := map[string]bool{}
	for _, c := range caps {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		switch c.Kind {
		case '@':
			// cancelled: absent
		case 0:
			res[c.Name] = true
		default:
			res[c.Name] = c.Value
		}
	}
	return res
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"io"
	"strings"
)

// Stanza is one stanza of an AIX attribute file: a name followed by its
// attributes.
type Stanza struct {
	Name  string
	Attrs map[string]string
	// Keys lists the attributes in file order.
	Keys []string
}

// Get returns the value of an attribute and whether the stanza sets it.
func (s *Stanza) Get(key string) (string, bool) {
	v, ok := s.Attrs[key]
	return v, ok
}

// Stanzas is an AIX attribute file: /etc/security/user, login.cfg, limits,
// passwd, /etc/filesystems and the audit config all share the format.
type Stanzas struct {
	List   []*Stanza
	byName map[string]*Stanza
}

// Get returns the stanza with the given name, nil when the file has none.
func (s *Stanzas) Get(name string) *Stanza {
	if s == nil {
		return nil
	}
	return s.byName[name]
}

// Effective returns the value of an attribute for a stanza: its own value,
// else the value of the default stanza, the way lsuser and lssec resolve
// the security files. ok is false when neither sets it.
func (s *Stanzas) Effective(name, key string) (string, bool) {
	if st := s.Get(name); st != nil {
		if v, ok := st.Attrs[key]; ok {
			return v, true
		}
	}
	if st := s.Get("default"); st != nil {
		if v, ok := st.Attrs[key]; ok {
			return v, true
		}
	}
	return "", false
}

// EffectiveAttrs returns every attribute of a stanza merged over the default
// stanza.
func (s *Stanzas) EffectiveAttrs(name string) map[string]string {
	res := map[string]string{}
	if st := s.Get("default"); st != nil {
		for k, v := range st.Attrs {
			res[k] = v
		}
	}
	if st := s.Get(name); st != nil && name != "default" {
		for k, v := range st.Attrs {
			res[k] = v
		}
	}
	return res
}

// ParseStanzas reads an AIX attribute file:
//
//   - a comment starts with an asterisk
//     default:
//     maxage = 13
//     SYSTEM = "compat"
//
//     root:
//     minlen = 15
//
// A stanza starts with its name and a colon in the first column; its
// attributes follow on indented `key = value` lines. A value keeps its
// quotes stripped and its surrounding whitespace trimmed. A stanza that
// appears twice is merged, the later value winning, as the AIX commands
// read the file.
func ParseStanzas(r io.Reader) (*Stanzas, error) {
	res := &Stanzas{byName: map[string]*Stanza{}}
	var cur *Stanza

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '*' || line[0] == '#' {
			continue
		}

		indented := raw[0] == ' ' || raw[0] == '\t'
		if !indented && strings.HasSuffix(line, ":") && !strings.Contains(line, "=") {
			name := strings.TrimSuffix(line, ":")
			cur = res.byName[name]
			if cur == nil {
				cur = &Stanza{Name: name, Attrs: map[string]string{}}
				res.byName[name] = cur
				res.List = append(res.List, cur)
			}
			continue
		}

		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if _, seen := cur.Attrs[key]; !seen {
			cur.Keys = append(cur.Keys, key)
		}
		cur.Attrs[key] = value
	}
	return res, scanner.Err()
}

// SplitList splits a comma separated attribute value (sugroups, shells,
// ttys) and drops empty items.
func SplitList(v string) []string {
	res := []string{}
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			res = append(res, item)
		}
	}
	return res
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inetd

import (
	"slices"
	"strings"
)

// XinetdFile is one file of an xinetd configuration: its service blocks, the
// attributes of its defaults block, and the files it includes.
type XinetdFile struct {
	Services    []XinetdService
	Defaults    map[string][]string
	IncludeDirs []string
	Includes    []string
}

// XinetdService is one `service <name> { ... }` block.
type XinetdService struct {
	Name  string
	Attrs map[string][]string
	// Line is the 1-based line of the service keyword.
	Line int
}

// IsXinetd reports whether content is written in xinetd's block syntax rather
// than as classic inetd.conf lines. Classic entries have at least six
// columns, so a `defaults`, `service <name>`, `include` or `includedir` line
// never appears in one.
func IsXinetd(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "defaults":
			if len(fields) == 1 || (len(fields) == 2 && fields[1] == "{") {
				return true
			}
		case "service":
			if len(fields) == 2 || (len(fields) == 3 && fields[2] == "{") {
				return true
			}
		case "include", "includedir":
			if len(fields) == 2 {
				return true
			}
		}
	}
	return false
}

// ParseXinetd reads one xinetd configuration file. Attributes are applied
// with their operator: `=` sets the values, `+=` adds to them and `-=`
// removes from them. Lines whose first non-blank character is # are comments.
func ParseXinetd(content string) XinetdFile {
	res := XinetdFile{Defaults: map[string][]string{}}

	var attrs map[string][]string
	var current *XinetdService
	inBlock := false
	pendingOpen := false

	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !inBlock {
			fields := strings.Fields(line)
			opens := fields[len(fields)-1] == "{"
			if opens {
				fields = fields[:len(fields)-1]
			}
			if pendingOpen {
				if line == "{" {
					inBlock = true
					pendingOpen = false
					continue
				}
				// a block keyword without its brace: xinetd drops it
				pendingOpen = false
				current = nil
				attrs = nil
			}
			if len(fields) == 0 {
				continue
			}

			switch {
			case fields[0] == "defaults" && len(fields) == 1:
				attrs = res.Defaults
				current = nil
			case fields[0] == "service" && len(fields) == 2:
				current = &XinetdService{Name: fields[1], Attrs: map[string][]string{}, Line: i + 1}
				attrs = current.Attrs
			case fields[0] == "includedir" && len(fields) == 2 && !opens:
				res.IncludeDirs = append(res.IncludeDirs, fields[1])
				continue
			case fields[0] == "include" && len(fields) == 2 && !opens:
				res.Includes = append(res.Includes, fields[1])
				continue
			default:
				continue
			}
			if opens {
				inBlock = true
			} else {
				pendingOpen = true
			}
			continue
		}

		if line == "}" {
			if current != nil {
				res.Services = append(res.Services, *current)
			}
			current = nil
			attrs = nil
			inBlock = false
			continue
		}

		applyXinetdAttr(attrs, line)
	}

	return res
}

func applyXinetdAttr(attrs map[string][]string, line string) {
	if attrs == nil {
		return
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return
	}
	key := line[:idx]
	op := "="
	if strings.HasSuffix(key, "+") || strings.HasSuffix(key, "-") {
		op = key[len(key)-1:] + "="
		key = key[:len(key)-1]
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	values := strings.Fields(line[idx+1:])

	switch op {
	case "+=":
		attrs[key] = append(attrs[key], values...)
	case "-=":
		attrs[key] = slices.DeleteFunc(attrs[key], func(v string) bool {
			return slices.Contains(values, v)
		})
	default:
		attrs[key] = values
	}
}

// MergeXinetdDefaults collects the defaults attributes of all files of an
// xinetd configuration.
func MergeXinetdDefaults(files []XinetdFile) map[string][]string {
	defaults := map[string][]string{}
	for _, f := range files {
		for k, v := range f.Defaults {
			defaults[k] = append(defaults[k], v...)
		}
	}
	return defaults
}

// Entries returns the services of this file that xinetd runs, as inetd
// entries. A service is left out when it sets `disable = yes`, when its id is
// listed in the defaults' `disabled` attribute, or when the defaults have an
// `enabled` list that does not name it. A service's id is its `id` attribute,
// or its name.
func (f XinetdFile) Entries(defaults map[string][]string) []Entry {
	enabled, hasEnabled := defaults["enabled"]
	disabled := defaults["disabled"]

	entries := []Entry{}
	for _, s := range f.Services {
		id := s.Name
		if v := s.Attrs["id"]; len(v) > 0 {
			id = v[0]
		}
		if v := s.Attrs["disable"]; len(v) > 0 && strings.EqualFold(v[0], "yes") {
			continue
		}
		if slices.Contains(disabled, id) {
			continue
		}
		if hasEnabled && !slices.Contains(enabled, id) {
			continue
		}

		e := Entry{
			Name:       s.Name,
			SocketType: first(s.Attrs["socket_type"]),
			Protocol:   first(s.Attrs["protocol"]),
			User:       first(s.Attrs["user"]),
			Server:     first(s.Attrs["server"]),
			Arguments:  strings.Join(s.Attrs["server_args"], " "),
			Line:       s.Line,
		}
		if slices.Contains(s.Attrs["type"], "INTERNAL") {
			e.Server = "internal"
		}
		switch strings.ToLower(first(s.Attrs["wait"])) {
		case "yes":
			e.Wait = "wait"
		case "no":
			e.Wait = "nowait"
		}
		e.Address = first(s.Attrs["bind"])
		if e.Address == "" {
			e.Address = first(s.Attrs["interface"])
		}
		if e.Address == "" {
			e.Address = first(defaults["bind"])
		}
		if e.Address == "" {
			e.Address = first(defaults["interface"])
		}
		entries = append(entries, e)
	}
	return entries
}

// XinetdIncludesFile reports whether xinetd reads a file of an includedir:
// it skips names that contain a dot or end with a tilde.
func XinetdIncludesFile(name string) bool {
	return name != "" && !strings.Contains(name, ".") && !strings.HasSuffix(name, "~")
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

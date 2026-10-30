// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"bufio"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	// SystemDbDir holds the system databases and their keyfile directories.
	SystemDbDir = "/etc/dconf/db"
	// UserProfile is the profile dconf uses when DCONF_PROFILE is not set.
	UserProfile = "user"
)

// ProfileDirs are the directories a profile name is looked up in, in order:
// /etc/dconf/profile, then the default XDG_DATA_DIRS.
var ProfileDirs = []string{
	"/etc/dconf/profile",
	"/usr/local/share/dconf/profile",
	"/usr/share/dconf/profile",
}

// Source types of a profile line.
const (
	SourceUser    = "user"
	SourceSystem  = "system"
	SourceService = "service"
	SourceFile    = "file"
)

// Source is one database of a profile, in priority order.
type Source struct {
	Type string
	Name string
}

// Path returns the compiled database a source reads, or "" for a user or
// service database, which belong to each user.
func (s Source) Path() string {
	switch s.Type {
	case SourceSystem:
		return path.Join(SystemDbDir, s.Name)
	case SourceFile:
		return s.Name
	}
	return ""
}

// DefaultSources is the profile dconf uses when no user profile exists.
var DefaultSources = []Source{{Type: SourceUser, Name: "user"}}

// ParseProfile reads a profile as dconf does: text after # is a comment, and
// each remaining line names a source, `user-db:NAME`, `system-db:NAME`,
// `service-db:NAME` or `file-db:PATH`. Other lines are ignored.
func ParseProfile(r io.Reader) ([]Source, error) {
	var res []Source
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		typ, name, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			continue
		}
		switch typ {
		case "user-db":
			res = append(res, Source{Type: SourceUser, Name: name})
		case "system-db":
			res = append(res, Source{Type: SourceSystem, Name: name})
		case "service-db":
			res = append(res, Source{Type: SourceService, Name: name})
		case "file-db":
			res = append(res, Source{Type: SourceFile, Name: name})
		}
	}
	return res, scanner.Err()
}

// Resolve computes what a profile's system and file databases provide. dbs
// holds the database read for each source, nil when it is a user or service
// database or could not be read. A key's value comes from the first source
// that has it, except that a lock moves the search to the lowest-priority
// source holding a lock for the key (a lock in the first source is ignored),
// as dconf_engine_read does. Values from user and service databases cannot be
// known, so a key unlocked below a writable first source is the value users
// get until they change it. locked lists the keys a source after the first one
// locks.
func Resolve(dbs []*Database) (values map[string]any, locked []string) {
	values = map[string]any{}
	lockLevel := map[string]int{}
	for i := len(dbs) - 1; i > 0; i-- {
		if dbs[i] == nil {
			continue
		}
		for _, l := range dbs[i].Locks {
			if _, ok := lockLevel[l]; !ok {
				lockLevel[l] = i
			}
		}
	}

	keys := map[string]bool{}
	for _, db := range dbs {
		if db == nil {
			continue
		}
		for k := range db.Values {
			keys[k] = true
		}
	}
	for k := range keys {
		for i := lockLevel[k]; i < len(dbs); i++ {
			if dbs[i] == nil {
				continue
			}
			if v, ok := dbs[i].Values[k]; ok {
				values[k] = v
				break
			}
		}
	}

	for k := range lockLevel {
		locked = append(locked, k)
	}
	sort.Strings(locked)
	return values, locked
}

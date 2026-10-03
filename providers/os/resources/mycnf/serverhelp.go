// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"encoding/json"
	"slices"
	"strings"
)

// ServerDefaults is what a server binary says about the option files it reads
// when it starts without option file arguments, from the header of
// `mysqld --verbose --help`.
type ServerDefaults struct {
	// Files are the default option files in the order the server reads them,
	// as printed: "~/" stands for the home directory of the account the
	// server runs as.
	Files []string
	// Groups are the option groups the server reads.
	Groups []string
}

// ParseServerHelp reads the default option files and option groups from the
// output of `mysqld --verbose --help` (or mariadbd's), which both products
// print as
//
//	Default options are read from the following files in the given order:
//	/etc/my.cnf /etc/mysql/my.cnf ~/.my.cnf
//	The following groups are read: mysql_cluster mysqld server mysqld-8.4
//
// The binary is the authority on both lists: they differ by build and by
// release in ways no static table keeps up with. Oracle and Percona 8.0 builds
// add /usr/etc/my.cnf and [mysql_cluster], the distribution 8.0 builds on RHEL
// do neither, and MariaDB 11.8.8 on Fedora reads [mariadb-11] and
// [mariadbd-11] where the 11.8.6 Ubuntu build does not. It reports false when
// the output carries neither line.
func ParseServerHelp(output string) (ServerDefaults, bool) {
	var d ServerDefaults
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "Default options are read from the following files") && i+1 < len(lines) {
			d.Files = strings.Fields(lines[i+1])
			continue
		}
		if rest, ok := strings.CutPrefix(line, "The following groups are read:"); ok {
			for _, g := range strings.Fields(rest) {
				d.Groups = append(d.Groups, strings.ToLower(g))
			}
		}
	}
	return d, len(d.Files) > 0 && len(d.Groups) > 0
}

// ParsePersisted reads the server options a MySQL 8.0+ server persisted with
// SET PERSIST and SET PERSIST_ONLY, from <datadir>/mysqld-auto.cnf. The server
// applies them at startup after every option file, unless
// persisted_globals_load is off.
//
// Two layouts exist. Version 1 (8.0.x before 8.0.29) keeps the variables
// under "mysql_server", with the read-only ones nested in
// "mysql_server_static_options". Version 2 sorts them into
// "mysql_static_variables", "mysql_dynamic_variables" and
// "mysql_dynamic_parse_early_variables". Each variable is an object whose
// "Value" is the setting. "mysql_sensitive_variables" holds encrypted values
// and is skipped.
func ParsePersisted(content string) ([]Option, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return nil, err
	}
	var out []Option
	var walk func(section map[string]json.RawMessage)
	walk = func(section map[string]json.RawMessage) {
		for name, raw := range section {
			var v struct {
				Value *string `json:"Value"`
			}
			if err := json.Unmarshal(raw, &v); err != nil || v.Value == nil {
				// A nested group (mysql_server_static_options) rather
				// than a variable.
				var nested map[string]json.RawMessage
				if err := json.Unmarshal(raw, &nested); err == nil && name == "mysql_server_static_options" {
					walk(nested)
				}
				continue
			}
			normalized, _ := NormalizeName(name)
			if normalized == "" {
				continue
			}
			out = append(out, Option{Name: normalized, Value: *v.Value})
		}
	}
	for _, key := range []string{"mysql_server", "mysql_static_variables", "mysql_dynamic_parse_early_variables", "mysql_dynamic_variables"} {
		raw, ok := root[key]
		if !ok {
			continue
		}
		var section map[string]json.RawMessage
		if err := json.Unmarshal(raw, &section); err != nil {
			return nil, err
		}
		walk(section)
	}
	// Map iteration order is random; the variables are distinct, so sort for
	// a reproducible result.
	slices.SortFunc(out, func(a, b Option) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/clickhousedb/connection"
)

func (r *mqlClickhousedbInstance) users() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		`SELECT name, auth_type, storage,
		        host_ip, host_names, host_names_regexp, host_names_like,
		        default_roles_all, default_roles_list, default_roles_except, default_database,
		        grantees_any, grantees_list, grantees_except
		 FROM system.users ORDER BY name`)
	if err != nil {
		if connection.IsPermissionError(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name, storage, defaultDatabase string
		var hostIps, hostNames, hostNamesRegexp, hostNamesLike []string
		var defaultRoles, defaultRolesExcept, granteesList, granteesExcept []string
		// default_roles_all and grantees_any are UInt8 flags, not Bool columns.
		var defaultRolesAll, granteesAny uint8
		// auth_type is taken as-is because its arity changed between releases;
		// see stringList.
		var authType any
		if err := rows.Scan(&name, &authType, &storage,
			&hostIps, &hostNames, &hostNamesRegexp, &hostNamesLike,
			&defaultRolesAll, &defaultRoles, &defaultRolesExcept, &defaultDatabase,
			&granteesAny, &granteesList, &granteesExcept); err != nil {
			return nil, err
		}
		authTypes, err := stringList("auth_type", authType)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.user", map[string]*llx.RawData{
			"__id":               llx.StringData(serverID + "/user/" + name),
			"name":               llx.StringData(name),
			"authTypes":          llx.ArrayData(toAnySlice(authTypes), "string"),
			"hasPassword":        llx.BoolData(requiresCredential(authTypes)),
			"anyHost":            llx.BoolData(allowsAnyHost(hostIps, hostNamesRegexp, hostNamesLike)),
			"storage":            llx.StringData(storage),
			"hostIps":            llx.ArrayData(toAnySlice(hostIps), "string"),
			"hostNames":          llx.ArrayData(toAnySlice(hostNames), "string"),
			"hostNamesRegexp":    llx.ArrayData(toAnySlice(hostNamesRegexp), "string"),
			"hostNamesLike":      llx.ArrayData(toAnySlice(hostNamesLike), "string"),
			"defaultRolesAll":    llx.BoolData(defaultRolesAll != 0),
			"defaultRoles":       llx.ArrayData(toAnySlice(defaultRoles), "string"),
			"defaultRolesExcept": llx.ArrayData(toAnySlice(defaultRolesExcept), "string"),
			"defaultDatabase":    llx.StringData(defaultDatabase),
			"granteesAny":        llx.BoolData(granteesAny != 0),
			"granteesList":       llx.ArrayData(toAnySlice(granteesList), "string"),
			"granteesExcept":     llx.ArrayData(toAnySlice(granteesExcept), "string"),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// grants renders the privileges granted directly to the user.
func (r *mqlClickhousedbUser) grants() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	return grantsFor(conn.Context(), db, "user_name", r.Name.Data)
}

// grants renders the privileges granted to the role.
func (r *mqlClickhousedbRole) grants() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	return grantsFor(conn.Context(), db, "role_name", r.Name.Data)
}

// requiresCredential reports whether a user needs a credential to authenticate.
// ClickHouse admits a login if any authentication method matches, so a single
// "no_password" method makes the account reachable without a credential even
// when it also has a real one; that is treated as password-less on purpose.
func requiresCredential(authTypes []string) bool {
	// An empty method list is anomalous — ClickHouse always defines at least one
	// method. Treat it defensively as requiring a credential rather than emitting
	// a password-less finding on incomplete data.
	if len(authTypes) == 0 {
		return true
	}
	return !slices.Contains(authTypes, "no_password")
}

// allowsAnyHost reports whether the user's host restrictions permit any origin.
//
// ClickHouse gates the origin of a connection on three independent lists and
// admits the connection when any one of them matches: host_ip holds IP ranges,
// host_names_regexp holds regular expressions matched against the resolved
// host name, and host_names_like holds LIKE patterns matched against the same
// name. Reading only host_ip therefore misses an account that is pinned to a
// single IP range and also carries a name pattern matching everything, which
// is reachable from anywhere while looking restricted.
//
// Only patterns that admit every name count. A merely broad one (for example
// the LIKE pattern "%.%", or a regular expression covering one domain) is a
// real restriction and is left alone, so this stays a statement about being
// open to the world rather than about being weakly restricted.
func allowsAnyHost(hostIps, hostNamesRegexp, hostNamesLike []string) bool {
	for _, ip := range hostIps {
		if ip == "::/0" || ip == "0.0.0.0/0" {
			return true
		}
	}
	for _, re := range hostNamesRegexp {
		if matchesAnyHostName(re) {
			return true
		}
	}
	for _, like := range hostNamesLike {
		if likeMatchesAnyHostName(like) {
			return true
		}
	}
	return false
}

// anyHostNameRegexps are the regular expressions that match every host name,
// once the anchors have been stripped. ClickHouse matches host_names_regexp
// against the whole name, so an unanchored ".*" and an anchored "^.*$" are the
// same pattern. ".+" is listed with them because a resolved host name is never
// empty, so requiring one character excludes nothing.
//
// The set is deliberately literal rather than an attempt to decide emptiness of
// an arbitrary regular expression. A pattern outside it is reported as a real
// restriction, which is the safe direction for a check that is read as "open to
// the world": a novel way of spelling ".*" is a missed finding, whereas
// over-matching would call a restricted account open.
var anyHostNameRegexps = map[string]struct{}{
	".*":        {},
	".+":        {},
	".*?":       {},
	".+?":       {},
	"(.*)":      {},
	"(.+)":      {},
	"[\\s\\S]*": {},
	"[\\s\\S]+": {},
}

// matchesAnyHostName reports whether a host_names_regexp entry matches every
// host name.
func matchesAnyHostName(expr string) bool {
	expr = strings.TrimSuffix(strings.TrimPrefix(expr, "^"), "$")
	_, ok := anyHostNameRegexps[expr]
	return ok
}

// likeMatchesAnyHostName reports whether a host_names_like entry matches every
// host name. In a LIKE pattern "%" stands for any run of characters, including
// an empty one, so a pattern built only from "%" matches anything. "_" stands
// for exactly one character, so a pattern containing one is a restriction.
func likeMatchesAnyHostName(pattern string) bool {
	if pattern == "" {
		return false
	}
	return strings.Trim(pattern, "%") == ""
}

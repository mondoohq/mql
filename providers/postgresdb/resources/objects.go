// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// --- tablespaces ------------------------------------------------------------

func (r *mqlPostgresdbInstance) tablespaces() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT t.spcname, t.oid::bigint, COALESCE(o.rolname, ''), COALESCE(pg_tablespace_location(t.oid), '')
		 FROM pg_tablespace t LEFT JOIN pg_roles o ON t.spcowner = o.oid ORDER BY t.spcname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, ownerName, location string
		var oid int64
		if err := rows.Scan(&name, &oid, &ownerName, &location); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.tablespace", map[string]*llx.RawData{
			"__id":     llx.StringData(r.SystemIdentifier.Data + "/tablespace/" + name),
			"name":     llx.StringData(name),
			"oid":      llx.IntData(oid),
			"location": llx.StringData(location),
		})
		if err != nil {
			return nil, err
		}
		ts := res.(*mqlPostgresdbTablespace)
		ts.cacheOwner = ownerName
		list = append(list, ts)
	}
	return list, rows.Err()
}

func (r *mqlPostgresdbTablespace) owner() (*mqlPostgresdbRole, error) {
	return resolveRoleRef(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlPostgresdbTablespace) privileges() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	return aclPrivileges(r.MqlRuntime, pool, r.__id,
		`SELECT COALESCE(gr.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable
		 FROM pg_tablespace t, aclexplode(COALESCE(t.spcacl, acldefault('t', t.spcowner))) a
		 LEFT JOIN pg_roles gr ON gr.oid = a.grantee
		 WHERE t.spcname = $1`, r.Name.Data)
}

// --- foreign servers --------------------------------------------------------

// redactOptions drops any option whose key carries a secret. Options are
// "key=value" pairs; the key is compared exactly so benign keys such as
// "password_required" are kept.
func redactOptions(in []string) []any {
	out := []any{}
	for _, opt := range in {
		key, _, _ := strings.Cut(opt, "=")
		if isSecretConnKeyword(strings.TrimSpace(key)) {
			continue
		}
		out = append(out, opt)
	}
	return out
}

func (r *mqlPostgresdbDatabase) foreignServers() ([]any, error) {
	if !r.AllowConnections.Data {
		return []any{}, nil
	}
	pool, err := pgPool(r.MqlRuntime, r.Name.Data)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT s.srvname, COALESCE(s.srvtype, ''), COALESCE(s.srvversion, ''),
			w.fdwname, COALESCE(o.rolname, ''), COALESCE(s.srvoptions, '{}')
		 FROM pg_foreign_server s
		 JOIN pg_foreign_data_wrapper w ON s.srvfdw = w.oid
		 LEFT JOIN pg_roles o ON s.srvowner = o.oid ORDER BY s.srvname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, srvType, version, fdwName, ownerName string
		var options []string
		if err := rows.Scan(&name, &srvType, &version, &fdwName, &ownerName, &options); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.foreignServer", map[string]*llx.RawData{
			"__id":    llx.StringData(r.__id + "/foreignserver/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(srvType),
			"version": llx.StringData(version),
			"fdwName": llx.StringData(fdwName),
			"options": llx.ArrayData(redactOptions(options), types.String),
		})
		if err != nil {
			return nil, err
		}
		fs := res.(*mqlPostgresdbForeignServer)
		fs.cacheOwner = ownerName
		fs.cacheDatabase = r.Name.Data
		list = append(list, fs)
	}
	return list, rows.Err()
}

func (r *mqlPostgresdbForeignServer) owner() (*mqlPostgresdbRole, error) {
	return resolveRoleRef(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlPostgresdbForeignServer) userMappings() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, r.cacheDatabase)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT COALESCE(um.usename, 'PUBLIC'), um.srvname, COALESCE(um.umoptions, '{}')
		 FROM pg_user_mappings um WHERE um.srvname = $1`, r.Name.Data)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var role, server string
		var options []string
		if err := rows.Scan(&role, &server, &options); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.userMapping", map[string]*llx.RawData{
			"__id":    llx.StringData(r.__id + "/mapping/" + role),
			"role":    llx.StringData(role),
			"server":  llx.StringData(server),
			"options": llx.ArrayData(redactOptions(options), types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// --- replication ------------------------------------------------------------

func (r *mqlPostgresdbInstance) replicationSlots() ([]any, error) {
	// Replication slots arrived in 9.4; an older server has none.
	if !pgAtLeast(r.MqlRuntime, pgVersion94) {
		return []any{}, nil
	}
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT slot_name, slot_type, active, COALESCE(database, ''), `+pgColumn(r.MqlRuntime, pgVersion10, "temporary", "false")+`
		 FROM pg_replication_slots ORDER BY slot_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, slotType, database string
		var active, temporary bool
		if err := rows.Scan(&name, &slotType, &active, &database, &temporary); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.replicationSlot", map[string]*llx.RawData{
			"__id":      llx.StringData(r.SystemIdentifier.Data + "/slot/" + name),
			"name":      llx.StringData(name),
			"slotType":  llx.StringData(slotType),
			"active":    llx.BoolData(active),
			"database":  llx.StringData(database),
			"temporary": llx.BoolData(temporary),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlPostgresdbDatabase) publications() ([]any, error) {
	if !r.AllowConnections.Data {
		return []any{}, nil
	}
	// Logical replication arrived in 10; an older server has no publications.
	if !pgAtLeast(r.MqlRuntime, pgVersion10) {
		return []any{}, nil
	}
	pool, err := pgPool(r.MqlRuntime, r.Name.Data)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT p.pubname, COALESCE(o.rolname, ''), p.puballtables,
			p.pubinsert, p.pubupdate, p.pubdelete, `+pgColumn(r.MqlRuntime, pgVersion11, "p.pubtruncate", "false")+`
		 FROM pg_publication p LEFT JOIN pg_roles o ON p.pubowner = o.oid ORDER BY p.pubname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, ownerName string
		var allTables, insert, update, del, truncate bool
		if err := rows.Scan(&name, &ownerName, &allTables, &insert, &update, &del, &truncate); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.publication", map[string]*llx.RawData{
			"__id":      llx.StringData(r.__id + "/publication/" + name),
			"name":      llx.StringData(name),
			"allTables": llx.BoolData(allTables),
			"insert":    llx.BoolData(insert),
			"update":    llx.BoolData(update),
			"delete":    llx.BoolData(del),
			"truncate":  llx.BoolData(truncate),
		})
		if err != nil {
			return nil, err
		}
		pub := res.(*mqlPostgresdbPublication)
		pub.cacheOwner = ownerName
		list = append(list, pub)
	}
	return list, rows.Err()
}

// redactedValue replaces every secret in a sanitized connection string.
const redactedValue = "REDACTED"

// isSecretConnKeyword reports whether a libpq connection keyword carries a
// secret: the password itself, or sslpassword (PG13+), which decrypts the
// client key. libpq keywords are case-sensitive, but any case is matched so
// a near-miss spelling can never leak.
func isSecretConnKeyword(key string) bool {
	switch strings.ToLower(key) {
	case "password", "sslpassword":
		return true
	}
	return false
}

// sanitizeConnInfo removes every secret from a subscription connection
// string. It covers both libpq formats, following libpq's own parser
// (conninfo_parse and conninfo_uri_parse_options in fe-connect.c):
//
//   - keyword/value: whitespace is allowed around '=', values may be
//     single-quoted, and a backslash escapes the next character both inside
//     and outside quotes
//   - URI: the password in the userinfo, and password/sslpassword query
//     parameters (whose keys may be percent-encoded)
//
// A string that does not parse is cut off at the point parsing failed, so a
// malformed value can never pass through unredacted.
func sanitizeConnInfo(conninfo string) string {
	s := strings.TrimSpace(conninfo)
	if strings.HasPrefix(s, "postgresql://") || strings.HasPrefix(s, "postgres://") {
		return sanitizeConnURI(s)
	}
	return sanitizeConnKeywords(s)
}

func isConnSpace(c byte) bool {
	// libpq uses isspace(): space, \t, \n, \v, \f, \r
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// sanitizeConnKeywords redacts secrets in a keyword/value connection string.
// Non-secret pairs and the whitespace between pairs are kept verbatim; a
// secret pair is rewritten as "<keyword>=REDACTED".
func sanitizeConnKeywords(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		// whitespace between pairs is copied as is
		start := i
		for i < len(s) && isConnSpace(s[i]) {
			i++
		}
		out.WriteString(s[start:i])
		if i >= len(s) {
			break
		}
		pairStart := i

		// keyword: up to '=' or whitespace
		for i < len(s) && s[i] != '=' && !isConnSpace(s[i]) {
			i++
		}
		key := s[pairStart:i]
		for i < len(s) && isConnSpace(s[i]) {
			i++
		}
		if i >= len(s) || s[i] != '=' || key == "" {
			// libpq rejects this ("missing = after keyword"); stop here
			out.WriteString(redactedValue)
			return out.String()
		}
		i++ // '='
		for i < len(s) && isConnSpace(s[i]) {
			i++
		}

		// value: single-quoted or up to whitespace, with backslash escapes
		terminated := true
		if i < len(s) && s[i] == '\'' {
			i++
			terminated = false
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '\'' {
					i++
					terminated = true
					break
				}
				i++
			}
		} else {
			for i < len(s) && !isConnSpace(s[i]) {
				if s[i] == '\\' {
					i++
				}
				i++
			}
		}
		if i > len(s) {
			i = len(s)
		}
		if !terminated {
			// unterminated quoted string: libpq rejects it
			out.WriteString(redactedValue)
			return out.String()
		}

		if isSecretConnKeyword(key) {
			out.WriteString(key + "=" + redactedValue)
		} else {
			out.WriteString(s[pairStart:i])
		}
	}
	return out.String()
}

// sanitizeConnURI redacts the userinfo password and secret query parameters
// of a postgresql:// or postgres:// connection URI.
func sanitizeConnURI(s string) string {
	schemeEnd := strings.Index(s, "://") + len("://")
	rest := s[schemeEnd:]

	query := ""
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		rest, query = rest[:q], rest[q+1:]
	}

	// The userinfo ends at an '@' before the first '/'. libpq takes the first
	// '@'; the last one is used here so an unencoded '@' inside a password
	// cannot leave part of it behind.
	authority := rest
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		authority = rest[:slash]
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		if colon := strings.IndexByte(authority[:at], ':'); colon >= 0 {
			rest = authority[:colon+1] + redactedValue + rest[at:]
		}
	}

	out := s[:schemeEnd] + rest
	if query == "" && !strings.Contains(s, "?") {
		return out
	}
	params := strings.Split(query, "&")
	for i, param := range params {
		rawKey, _, hasValue := strings.Cut(param, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		if isSecretConnKeyword(key) || (err != nil && hasValue) {
			params[i] = rawKey + "=" + redactedValue
		}
	}
	return out + "?" + strings.Join(params, "&")
}

func (r *mqlPostgresdbInstance) subscriptions() ([]any, error) {
	// Logical replication arrived in 10; an older server has no subscriptions.
	if !pgAtLeast(r.MqlRuntime, pgVersion10) {
		return []any{}, nil
	}
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	// pg_subscription is superuser-only; treat only a permission error as none,
	// and propagate real failures (network, timeout, syntax).
	rows, err := pool.Query(pgContext(),
		`SELECT s.subname, COALESCE(o.rolname, ''), s.subenabled, COALESCE(s.subconninfo, '')
		 FROM pg_subscription s LEFT JOIN pg_roles o ON s.subowner = o.oid ORDER BY s.subname`)
	if err != nil {
		if isPermissionDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, ownerName, conninfo string
		var enabled bool
		if err := rows.Scan(&name, &ownerName, &enabled, &conninfo); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.subscription", map[string]*llx.RawData{
			"__id":                llx.StringData(r.SystemIdentifier.Data + "/subscription/" + name),
			"name":                llx.StringData(name),
			"enabled":             llx.BoolData(enabled),
			"connectionSanitized": llx.StringData(sanitizeConnInfo(conninfo)),
		})
		if err != nil {
			return nil, err
		}
		sub := res.(*mqlPostgresdbSubscription)
		sub.cacheOwner = ownerName
		list = append(list, sub)
	}
	return list, rows.Err()
}

func (r *mqlPostgresdbPublication) owner() (*mqlPostgresdbRole, error) {
	return resolveRoleRef(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlPostgresdbSubscription) owner() (*mqlPostgresdbRole, error) {
	return resolveRoleRef(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

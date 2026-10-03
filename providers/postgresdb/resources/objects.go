// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
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
		 FROM pg_tablespace t, aclexplode(t.spcacl) a
		 LEFT JOIN pg_roles gr ON gr.oid = a.grantee
		 WHERE t.spcname = $1`, r.Name.Data)
}

// --- foreign servers --------------------------------------------------------

// redactOptions drops any option whose key carries a secret. Options are
// "key=value" pairs; the key is compared exactly so benign keys such as
// "password_timeout" are kept.
func redactOptions(in []string) []any {
	out := []any{}
	for _, opt := range in {
		key, _, _ := strings.Cut(opt, "=")
		if strings.EqualFold(strings.TrimSpace(key), "password") {
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

// connInfoPasswordRe matches a libpq keyword password, including single-quoted
// values that may contain spaces (password='s3cret value').
var connInfoPasswordRe = regexp.MustCompile(`(?i)password=('[^']*'|[^ ]*)`)

// connInfoURIRe matches the password in a URI-style connection string
// (postgresql://user:password@host/db).
var connInfoURIRe = regexp.MustCompile(`(://[^:/@]+:)([^@]+)(@)`)

// sanitizeConnInfo removes a password from a subscription connection string,
// covering both keyword-value and URI formats.
func sanitizeConnInfo(conninfo string) string {
	s := connInfoPasswordRe.ReplaceAllString(conninfo, "password=REDACTED")
	s = connInfoURIRe.ReplaceAllString(s, "${1}REDACTED${3}")
	return strings.TrimSpace(s)
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

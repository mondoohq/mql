// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"database/sql"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousedb/connection"
)

func initClickhousedbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := clickhousedbConnection(runtime)
	db, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}

	var version string
	if err := db.QueryRowContext(conn.Context(), `SELECT version()`).Scan(&version); err != nil {
		return nil, nil, fmt.Errorf("clickhousedb: cannot read version: %w", err)
	}

	args["__id"] = llx.StringData(connection.NewClickhousedbInstanceIdentifier(conn.ServerID()))
	args["version"] = llx.StringData(version)
	return args, nil, nil
}

// serverPort resolves one listener port through the getServerPort() function.
//
// ClickHouse does not expose its listeners in system.server_settings: that
// table covers the settings declared in the server's settings struct, and ports
// are read straight from the config XML. getServerPort() is the only route to
// the resolved value, and it throws rather than returning zero when the port is
// not configured -- "There is no port named tcp_port_secure" -- which is the
// normal state for a server with TLS switched off. That is reported as 0 here,
// since "not configured" is exactly what a caller asking for the port wants to
// be told. A refusal is an error, not a 0 (ADR 046).
func serverPort(ctx context.Context, db *sql.DB, name string) (int64, error) {
	var port uint16
	err := db.QueryRowContext(ctx, `SELECT getServerPort(?)`, name).Scan(&port)
	if err != nil {
		if connection.IsUnknownPortError(err) {
			return 0, nil
		}
		// A refused call is not an unconfigured port: reading it as 0 would
		// make a server with a plaintext listener look TLS-only.
		if connection.IsPermissionError(err) {
			if !plugin.StructuredErrors() {
				return 0, nil
			}
			return 0, refusal(err, "getServerPort")
		}
		return 0, fmt.Errorf("clickhousedb: cannot read port %s: %w", name, err)
	}
	return int64(port), nil
}

func (r *mqlClickhousedbInstance) instancePort(name string) (int64, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return 0, err
	}
	return serverPort(conn.Context(), db, name)
}

func (r *mqlClickhousedbInstance) tcpPort() (int64, error) {
	return r.instancePort("tcp_port")
}

func (r *mqlClickhousedbInstance) tcpPortSecure() (int64, error) {
	return r.instancePort("tcp_port_secure")
}

func (r *mqlClickhousedbInstance) httpPort() (int64, error) {
	return r.instancePort("http_port")
}

func (r *mqlClickhousedbInstance) httpsPort() (int64, error) {
	return r.instancePort("https_port")
}

// tlsEnabled reports whether either interface has a secure listener bound.
// Both are checked because a deployment may expose only one of them, and a
// server reachable in the clear on the interface its clients actually use is
// not made safe by the other one being encrypted.
//
// It reads the two port fields rather than querying for them again, so a policy
// that looks at tlsEnabled and at tcpPortSecure costs one round trip per port
// rather than one per read.
func (r *mqlClickhousedbInstance) tlsEnabled() (bool, error) {
	native := r.GetTcpPortSecure()
	if native.Error != nil {
		return false, native.Error
	}
	https := r.GetHttpsPort()
	if https.Error != nil {
		return false, https.Error
	}
	return native.Data != 0 || https.Data != 0, nil
}

func (r *mqlClickhousedbInstance) roles() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		`SELECT name, storage FROM system.roles ORDER BY name`)
	if err != nil {
		return refusedList(err, "SELECT ON system.roles")
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name, storage string
		if err := rows.Scan(&name, &storage); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.role", map[string]*llx.RawData{
			"__id":    llx.StringData(serverID + "/role/" + name),
			"name":    llx.StringData(name),
			"storage": llx.StringData(storage),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlClickhousedbInstance) settingsProfiles() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		`SELECT name, storage, num_elements, apply_to_all, apply_to_list
		 FROM system.settings_profiles ORDER BY name`)
	if err != nil {
		return refusedList(err, "SELECT ON system.settings_profiles")
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name, storage string
		var numElements uint64
		var applyToAll bool
		var applyToList []string
		if err := rows.Scan(&name, &storage, &numElements, &applyToAll, &applyToList); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.settingsProfile", map[string]*llx.RawData{
			"__id":         llx.StringData(serverID + "/settingsProfile/" + name),
			"name":         llx.StringData(name),
			"storage":      llx.StringData(storage),
			"numElements":  llx.IntData(int64(numElements)),
			"appliesToAll": llx.BoolData(applyToAll),
			"appliesTo":    llx.ArrayData(toAnySlice(applyToList), "string"),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlClickhousedbInstance) quotas() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		`SELECT name, storage, keys, apply_to_all, apply_to_list
		 FROM system.quotas ORDER BY name`)
	if err != nil {
		return refusedList(err, "SELECT ON system.quotas")
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name, storage string
		var keys, applyToList []string
		var applyToAll bool
		if err := rows.Scan(&name, &storage, &keys, &applyToAll, &applyToList); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.quota", map[string]*llx.RawData{
			"__id":         llx.StringData(serverID + "/quota/" + name),
			"name":         llx.StringData(name),
			"storage":      llx.StringData(storage),
			"keys":         llx.ArrayData(toAnySlice(keys), "string"),
			"appliesToAll": llx.BoolData(applyToAll),
			"appliesTo":    llx.ArrayData(toAnySlice(applyToList), "string"),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlClickhousedbInstance) clusters() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		`SELECT cluster, countDistinct(shard_num) AS shards, max(replica_num) AS replicas
		 FROM system.clusters GROUP BY cluster ORDER BY cluster`)
	if err != nil {
		return refusedList(err, "SELECT ON system.clusters")
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name string
		var shards, replicas uint64
		if err := rows.Scan(&name, &shards, &replicas); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.cluster", map[string]*llx.RawData{
			"__id":            llx.StringData(serverID + "/cluster/" + name),
			"name":            llx.StringData(name),
			"shardCount":      llx.IntData(int64(shards)),
			"maxReplicaCount": llx.IntData(int64(replicas)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlClickhousedbInstance) serverSettings() ([]any, error) {
	conn := clickhousedbConnection(r.MqlRuntime)
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(conn.Context(),
		// `default` is a SQL reserved word; backtick-quote it so the query stays
		// valid across ClickHouse versions.
		"SELECT name, value, `default`, changed, description"+
			" FROM system.server_settings ORDER BY name")
	if err != nil {
		return refusedList(err, "SELECT ON system.server_settings")
	}
	defer rows.Close()

	serverID := conn.ServerID()
	list := []any{}
	for rows.Next() {
		var name, value, def, description string
		var changed bool
		if err := rows.Scan(&name, &value, &def, &changed, &description); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "clickhousedb.serverSetting", map[string]*llx.RawData{
			"__id":        llx.StringData(serverID + "/serverSetting/" + name),
			"name":        llx.StringData(name),
			"value":       llx.StringData(value),
			"default":     llx.StringData(def),
			"changed":     llx.BoolData(changed),
			"description": llx.StringData(description),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// grantsFor renders the privileges granted to a user or role from system.grants
// into readable "<privilege> ON <scope>" strings. The grantee `name` is bound as
// a query parameter; `column` is concatenated into the SQL, so it must be a
// trusted literal column name ("user_name" or "role_name") and never user input.
func grantsFor(ctx context.Context, db *sql.DB, column, name string) ([]any, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT access_type, database, table, column, is_partial_revoke, grant_option
		 FROM system.grants WHERE `+column+` = ? ORDER BY access_type`, name)
	if err != nil {
		return refusedList(err, "SELECT ON system.grants")
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var accessType string
		var database, table, col sql.NullString
		var partialRevoke, grantOption bool
		if err := rows.Scan(&accessType, &database, &table, &col, &partialRevoke, &grantOption); err != nil {
			return nil, err
		}
		scope := grantScope(database, table, col)
		line := accessType + " ON " + scope
		if grantOption {
			line += " WITH GRANT OPTION"
		}
		if partialRevoke {
			line = "REVOKE " + line
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return toAnySlice(out), nil
}

// grantScope formats the database/table/column of a grant, using "*" for the
// wildcard (NULL) parts.
func grantScope(database, table, column sql.NullString) string {
	db := "*"
	if database.Valid && database.String != "" {
		db = database.String
	}
	tbl := "*"
	if table.Valid && table.String != "" {
		tbl = table.String
	}
	scope := db + "." + tbl
	if column.Valid && column.String != "" {
		scope += "(" + column.String + ")"
	}
	return scope
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// initMysqldbInstance fetches the server's core metadata once and populates the
// instance resource. Collections resolve lazily through their accessors.
func initMysqldbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := mysqldbConnection(runtime)
	serverID, err := conn.ServerID()
	if err != nil {
		return nil, nil, err
	}
	flavor, err := conn.Flavor()
	if err != nil {
		return nil, nil, err
	}
	db, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}

	var version, versionComment string
	if err := db.QueryRowContext(mysqldbContext(), "SELECT @@version, @@version_comment").Scan(&version, &versionComment); err != nil {
		return nil, nil, err
	}
	var serverUUID string
	// @@server_uuid may not exist on older MariaDB; ignore the error.
	_ = db.QueryRowContext(mysqldbContext(), "SELECT @@server_uuid").Scan(&serverUUID)

	vars := map[string]string{}
	rows, err := db.QueryContext(mysqldbContext(),
		`SHOW GLOBAL VARIABLES WHERE Variable_name IN
		 ('have_ssl','require_secure_transport','tls_version','sql_mode',
		  'secure_file_priv','local_infile','bind_address')`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			rows.Close()
			return nil, nil, err
		}
		vars[strings.ToLower(name)] = value
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(serverID)
	args["version"] = llx.StringData(version)
	args["versionComment"] = llx.StringData(versionComment)
	args["flavor"] = llx.StringData(flavor)
	args["serverUuid"] = llx.StringData(serverUUID)
	args["ssl"] = llx.BoolData(isYes(vars["have_ssl"]))
	args["requireSecureTransport"] = llx.BoolData(isYes(vars["require_secure_transport"]))
	args["tlsVersion"] = llx.StringData(vars["tls_version"])
	args["sqlMode"] = llx.StringData(vars["sql_mode"])
	args["secureFilePriv"] = llx.StringData(vars["secure_file_priv"])
	args["localInfile"] = llx.BoolData(isYes(vars["local_infile"]))
	args["bindAddress"] = llx.StringData(vars["bind_address"])
	return args, nil, nil
}

func (r *mqlMysqldbInstance) variables() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(), "SHOW GLOBAL VARIABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.variable", map[string]*llx.RawData{
			"__id":  llx.StringData(r.__id + "/var/" + name),
			"name":  llx.StringData(name),
			"value": llx.StringData(value),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbInstance) plugins() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT PLUGIN_NAME, PLUGIN_STATUS, PLUGIN_TYPE,
			COALESCE(PLUGIN_LIBRARY, ''), COALESCE(PLUGIN_LICENSE, '')
		 FROM information_schema.PLUGINS ORDER BY PLUGIN_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, status, typ, library, license string
		if err := rows.Scan(&name, &status, &typ, &library, &license); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.plugin", map[string]*llx.RawData{
			"__id":    llx.StringData(pluginResourceID(r.__id, name, typ)),
			"name":    llx.StringData(name),
			"status":  llx.StringData(status),
			"type":    llx.StringData(typ),
			"library": llx.StringData(library),
			"license": llx.StringData(license),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbInstance) components() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// mysql.component is MySQL 8+ only; MariaDB has no such table. Treat a
	// missing table or access-denied as no components, but surface real errors.
	rows, err := db.QueryContext(mysqldbContext(), "SELECT component_urn FROM mysql.component")
	if err != nil {
		if isMissingTable(err) || isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var urn string
		if err := rows.Scan(&urn); err != nil {
			return nil, err
		}
		name := urn
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		name = strings.TrimPrefix(name, "component_")
		res, err := CreateResource(r.MqlRuntime, "mysqldb.component", map[string]*llx.RawData{
			"__id": llx.StringData(r.__id + "/component/" + urn),
			"name": llx.StringData(name),
			"urn":  llx.StringData(urn),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbInstance) replicationChannels() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// performance_schema.replication_connection_configuration is MySQL/Percona;
	// MariaDB exposes replication state differently. Treat a missing table or
	// access-denied as no channels, but surface real errors.
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT CHANNEL_NAME, HOST, SSL_ALLOWED, SSL_VERIFY_SERVER_CERTIFICATE
		 FROM performance_schema.replication_connection_configuration`)
	if err != nil {
		if isMissingTable(err) || isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var channel, host, sslAllowed, sslVerify string
		if err := rows.Scan(&channel, &host, &sslAllowed, &sslVerify); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.replicationChannel", map[string]*llx.RawData{
			"__id":                llx.StringData(r.__id + "/replchannel/" + channel),
			"channel":             llx.StringData(channel),
			"sourceHost":          llx.StringData(host),
			"sslAllowed":          llx.BoolData(isYes(sslAllowed)),
			"sslVerifyServerCert": llx.BoolData(isYes(sslVerify)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

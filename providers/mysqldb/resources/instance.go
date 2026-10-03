// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"errors"
	"slices"
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
	haveSSL, haveSSLSet := vars["have_ssl"]
	var channelEnabled, sessionTLS string
	if !haveSSLSet {
		// MySQL 8.4 removed have_ssl. tls_channel_status reports whether the
		// main channel has TLS (it needs SELECT on the table); otherwise this
		// session's own TLS version shows that the server offers TLS.
		err := db.QueryRowContext(mysqldbContext(),
			`SELECT VALUE FROM performance_schema.tls_channel_status
			 WHERE CHANNEL = 'mysql_main' AND PROPERTY = 'Enabled'`).Scan(&channelEnabled)
		if err != nil && !errors.Is(err, sql.ErrNoRows) && !isMissingTable(err) && !isAccessDenied(err) {
			return nil, nil, err
		}
		if channelEnabled == "" {
			var name string
			err := db.QueryRowContext(mysqldbContext(), "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &sessionTLS)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, nil, err
			}
		}
	}
	args["ssl"] = llx.BoolData(sslAvailable(haveSSL, haveSSLSet, channelEnabled, sessionTLS))
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
			"__id":    llx.StringData(r.__id + "/plugin/" + name),
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

	var urns []string
	for rows.Next() {
		var urn string
		if err := rows.Scan(&urn); err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	keyring, ok, err := activeKeyringComponent(db)
	if err != nil {
		return nil, err
	}
	if ok && !slices.Contains(urns, keyring) {
		urns = append(urns, keyring)
	}

	list := []any{}
	for _, urn := range urns {
		res, err := CreateResource(r.MqlRuntime, "mysqldb.component", map[string]*llx.RawData{
			"__id": llx.StringData(r.__id + "/component/" + urn),
			"name": llx.StringData(componentName(urn)),
			"urn":  llx.StringData(urn),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlMysqldbInstance) replicationChannels() ([]any, error) {
	if r.Flavor.Data == "mariadb" {
		return r.mariadbReplicationChannels()
	}
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

// sslAvailable reports whether the server accepts TLS connections. have_ssl
// answers it where the variable exists (it was removed in MySQL 8.4). Without
// it, performance_schema.tls_channel_status says whether the mysql_main
// channel has TLS enabled. Current_tls_cert is not used: it keeps the
// configured file name while TLS is disabled. When the channel status is
// unreadable, a TLS version on this session proves TLS is on.
func sslAvailable(haveSSL string, haveSSLSet bool, channelEnabled, sessionTLSVersion string) bool {
	if haveSSLSet {
		return isYes(haveSSL)
	}
	if channelEnabled != "" {
		return isYes(strings.ToUpper(channelEnabled))
	}
	return sessionTLSVersion != ""
}

// keyringComponent reads the rows of performance_schema.keyring_component_status
// (STATUS_KEY to STATUS_VALUE). A keyring component is loaded through the
// server's manifest file rather than INSTALL COMPONENT, so mysql.component does
// not list it. It returns the component's URN when one is active.
func keyringComponent(status map[string]string) (string, bool) {
	name := status["Component_name"]
	if name == "" || !strings.EqualFold(status["Component_status"], "Active") {
		return "", false
	}
	return "file://" + name, true
}

// componentName derives the short name from a component URN, for example
// validate_password from file://component_validate_password.
func componentName(urn string) string {
	name := urn
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimPrefix(name, "component_")
}

// activeKeyringComponent returns the URN of the keyring component loaded
// through the manifest, if any. The status table exists from MySQL 8.0.24.
func activeKeyringComponent(db *sql.DB) (string, bool, error) {
	rows, err := db.QueryContext(mysqldbContext(),
		"SELECT STATUS_KEY, STATUS_VALUE FROM performance_schema.keyring_component_status")
	if err != nil {
		if isMissingTable(err) {
			return "", false, nil
		}
		if isAccessDenied(err) {
			if plugin.StructuredErrors() {
				return "", false, llx.Forbidden(err, llx.WithPermissions("SELECT ON performance_schema.keyring_component_status"))
			}
			return "", false, nil
		}
		return "", false, err
	}
	defer rows.Close()
	status := map[string]string{}
	for rows.Next() {
		var k, v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return "", false, err
		}
		status[k.String] = v.String
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	urn, ok := keyringComponent(status)
	return urn, ok, nil
}

// replicationChannelRow is one replication source connection.
type replicationChannelRow struct {
	channel, host                   string
	sslAllowed, sslVerifyServerCert bool
}

// mariadbChannelFromStatus maps one row of SHOW ALL SLAVES STATUS, keyed by
// column name, to a channel. The column set grows between MariaDB releases,
// so columns are read by name. The default (unnamed) connection has an empty
// Connection_name.
func mariadbChannelFromStatus(row map[string]string) replicationChannelRow {
	return replicationChannelRow{
		channel:             row["Connection_name"],
		host:                row["Master_Host"],
		sslAllowed:          isYes(strings.ToUpper(row["Master_SSL_Allowed"])),
		sslVerifyServerCert: isYes(strings.ToUpper(row["Master_SSL_Verify_Server_Cert"])),
	}
}

// mariadbReplicationChannels reads MariaDB's replication connections. MariaDB
// does not populate performance_schema.replication_connection_configuration;
// SHOW ALL SLAVES STATUS lists every named connection.
func (r *mqlMysqldbInstance) mariadbReplicationChannels() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// SHOW ALL REPLICAS STATUS is the 10.5.1+ name; earlier servers reject it
	// with a syntax error and know only SHOW ALL SLAVES STATUS. The columns
	// keep their Master_* names under both.
	rows, err := db.QueryContext(mysqldbContext(), "SHOW ALL REPLICAS STATUS")
	if isSyntaxError(err) {
		rows, err = db.QueryContext(mysqldbContext(), "SHOW ALL SLAVES STATUS")
	}
	if err != nil {
		if isAccessDenied(err) {
			// v13 read the empty performance_schema table and returned no
			// channels for every caller
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("SLAVE MONITOR ON *.*"))
		}
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	list := []any{}
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]string, len(cols))
		for i, c := range cols {
			row[c] = vals[i].String
		}
		ch := mariadbChannelFromStatus(row)
		res, err := CreateResource(r.MqlRuntime, "mysqldb.replicationChannel", map[string]*llx.RawData{
			"__id":                llx.StringData(r.__id + "/replchannel/" + ch.channel),
			"channel":             llx.StringData(ch.channel),
			"sourceHost":          llx.StringData(ch.host),
			"sslAllowed":          llx.BoolData(ch.sslAllowed),
			"sslVerifyServerCert": llx.BoolData(ch.sslVerifyServerCert),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

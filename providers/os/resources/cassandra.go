// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"path"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/cassandraconf"
	"go.mondoo.com/mql/providers/os/resources/yamlconf"
)

// cassandraConfDirs lists the directories a Cassandra installation keeps its
// configuration in, in the order they are probed. The three files this
// package reads live side by side, so one list serves all of them.
var cassandraConfDirs = []string{
	"/etc/cassandra",              // Debian, Ubuntu, and RPM packages
	"/etc/cassandra/conf",         // RPM layouts that keep a conf subdirectory
	"/opt/cassandra/conf",         // tarball installs
	"/usr/local/cassandra/conf",   // tarball installs
	"/opt/homebrew/etc/cassandra", // Homebrew on Apple silicon
	"/usr/local/etc/cassandra",    // Homebrew on Intel
}

// cassandraConfPaths expands the probe directories into candidate paths for
// one configuration file.
func cassandraConfPaths(name string) []string {
	paths := make([]string, 0, len(cassandraConfDirs))
	for _, dir := range cassandraConfDirs {
		paths = append(paths, path.Join(dir, name))
	}
	return paths
}

// resolveCassandraPathArg resolves the optional `path` argument shared by the three
// file-backed cassandra resources into the file resource they read.
func resolveCassandraPathArg(runtime *plugin.Runtime, args map[string]*llx.RawData, resource string) (map[string]*llx.RawData, plugin.Resource, error) {
	x, ok := args["path"]
	if !ok {
		return args, nil, nil
	}

	p, ok := x.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'path' in " + resource + " initialization, it must be a string")
	}
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(p),
	})
	if err != nil {
		return nil, nil, err
	}
	args["file"] = llx.ResourceData(f, "file")
	delete(args, "path")
	return args, nil, nil
}

// probeCassandraFile locates the first candidate path that exists.
//
// It is only reached when the resource was not initialized with an explicit
// path. A miss is not an error: Cassandra is most likely not installed, so
// the field is marked set and null and the dependent fields report empty
// rather than cascading a missing-file error.
func probeCassandraFile(runtime *plugin.Runtime, state *plugin.TValue[*mqlFile], name string) (*mqlFile, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		state.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, p := range cassandraConfPaths(name) {
		if ok, _ := afs.Exists(p); ok {
			f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
				"path": llx.StringData(p),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	state.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// readCassandraFile reports the content of a located configuration file, and
// the empty string when there is none. Every parser treats empty content as a
// server running on its defaults, so the callers do not need to distinguish
// the two.
func readCassandraFile(file *mqlFile) (string, error) {
	if file == nil {
		return "", nil
	}
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		return "", nil
	}
	content := file.GetContent()
	if content.Error != nil {
		return "", content.Error
	}
	return content.Data, nil
}

// ---------------------------------------------------------------------------
// cassandra
// ---------------------------------------------------------------------------

func (c *mqlCassandra) id() (string, error) {
	return "cassandra", nil
}

// cassandraPackageBinaries lists where the Debian, Ubuntu and RPM packages
// install the launch script. Debian and RPM put it in /usr/sbin, which is not
// on a non-root user's PATH, so `cassandra -v` alone finds nothing there.
var cassandraPackageBinaries = []string{
	"/usr/sbin/cassandra",
	"/usr/bin/cassandra",
}

// cassandraBinaries returns the launch scripts to try after the one on PATH:
// the package locations, then the script of each tarball install among
// confDirs. A tarball unpacks into one directory that holds conf/ and bin/
// side by side and puts nothing on PATH. Package installs keep their
// configuration under /etc, which has no sibling bin directory.
func cassandraBinaries(confDirs []string) []string {
	out := append([]string{}, cassandraPackageBinaries...)
	for _, dir := range confDirs {
		if path.Base(dir) != "conf" || strings.HasPrefix(dir, "/etc/") {
			continue
		}
		out = append(out, path.Join(path.Dir(dir), "bin", "cassandra"))
	}
	return out
}

// version reads the server version from the installed binary.
//
// The launch script prints the version at runtime rather than storing it in
// the binary, so this needs command execution and reports nothing over a
// transport that cannot run commands. The configuration files the other
// cassandra resources read are unaffected, since they come off the
// filesystem. The script on PATH is tried first, then the package
// locations and the bin directory of each tarball install that exist.
func (c *mqlCassandra) version() (string, error) {
	conn, ok := c.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		c.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	if version := cassandraVersionFrom(conn, "cassandra"); version != "" {
		return version, nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, bin := range cassandraBinaries(cassandraConfDirs) {
		if ok, _ := afs.Exists(bin); !ok {
			continue
		}
		if version := cassandraVersionFrom(conn, bin); version != "" {
			return version, nil
		}
	}

	c.Version.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

// cassandraVersionFrom runs `<bin> -v` and returns the version it prints, or
// the empty string when the command fails or prints none.
func cassandraVersionFrom(conn shared.Connection, bin string) string {
	res, err := conn.RunCommand(bin + " -v")
	if err != nil || res.ExitStatus != 0 {
		return ""
	}
	data, err := io.ReadAll(res.Stdout)
	if err != nil {
		return ""
	}
	return cassandraconf.ParseVersion(string(data))
}

// ---------------------------------------------------------------------------
// cassandra.conf
// ---------------------------------------------------------------------------

func initCassandraConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return resolveCassandraPathArg(runtime, args, "cassandra.conf")
}

func (c *mqlCassandraConf) id() (string, error) {
	file := c.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "cassandra.yaml", nil
	}
	return file.Data.Path.Data, nil
}

func (c *mqlCassandraConf) file() (*mqlFile, error) {
	return probeCassandraFile(c.MqlRuntime, &c.File, "cassandra.yaml")
}

func (c *mqlCassandraConf) params(file *mqlFile) (any, error) {
	content, err := readCassandraFile(file)
	if err != nil {
		return nil, err
	}
	if content == "" {
		return map[string]any{}, nil
	}

	cfg, err := cassandraconf.ParseConf(content)
	if err != nil {
		return nil, err
	}
	return cfg.Params, nil
}

// cassandraParams narrows the dict the accessors depend on back to a tree.
//
// The comma-ok form is what keeps a malformed file from taking down the
// scan: the executor runs blocks in goroutines, so a failed bare type
// assertion here would be an unrecoverable panic rather than one bad field.
func cassandraParams(params any) map[string]any {
	m, ok := params.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return m
}

// cluster identity

func (c *mqlCassandraConf) clusterName(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "cluster_name"), nil
}

func (c *mqlCassandraConf) endpointSnitch(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "endpoint_snitch"), nil
}

func (c *mqlCassandraConf) seedProviderClass(params any) (string, error) {
	return cassandraconf.SeedProviderClass(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) seeds(params any) ([]any, error) {
	return toAnySlice(cassandraconf.Seeds(cassandraParams(params))), nil
}

// network binding

func (c *mqlCassandraConf) listenAddress(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "listen_address"), nil
}

func (c *mqlCassandraConf) broadcastAddress(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "broadcast_address"), nil
}

func (c *mqlCassandraConf) rpcAddress(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "rpc_address"), nil
}

func (c *mqlCassandraConf) broadcastRpcAddress(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "broadcast_rpc_address"), nil
}

func (c *mqlCassandraConf) startNativeTransport(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), true, "start_native_transport"), nil
}

func (c *mqlCassandraConf) nativeTransportPort(params any) (int64, error) {
	return yamlconf.Int(cassandraParams(params), 9042, "native_transport_port"), nil
}

func (c *mqlCassandraConf) nativeTransportPortSsl(params any) (int64, error) {
	return yamlconf.Int(cassandraParams(params), 0, "native_transport_port_ssl"), nil
}

func (c *mqlCassandraConf) storagePort(params any) (int64, error) {
	return yamlconf.Int(cassandraParams(params), 7000, "storage_port"), nil
}

func (c *mqlCassandraConf) sslStoragePort(params any) (int64, error) {
	return yamlconf.Int(cassandraParams(params), 7001, "ssl_storage_port"), nil
}

// authentication and authorization

func (c *mqlCassandraConf) authenticator(params any) (string, error) {
	return cassandraconf.Authenticator(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) authorizer(params any) (string, error) {
	return cassandraconf.Authorizer(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) roleManager(params any) (string, error) {
	return cassandraconf.RoleManager(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) networkAuthorizer(params any) (string, error) {
	return cassandraconf.NetworkAuthorizer(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) internodeAuthenticator(params any) (string, error) {
	return cassandraconf.ClassName(cassandraParams(params), "", "internode_authenticator"), nil
}

func (c *mqlCassandraConf) authenticationEnabled(params any) (bool, error) {
	return cassandraconf.AuthenticationEnabled(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) authorizationEnabled(params any) (bool, error) {
	return cassandraconf.AuthorizationEnabled(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) networkAuthorizationEnabled(params any) (bool, error) {
	return cassandraconf.NetworkAuthorizationEnabled(cassandraParams(params)), nil
}

// client encryption

func (c *mqlCassandraConf) clientEncryptionEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "client_encryption_options", "enabled"), nil
}

func (c *mqlCassandraConf) clientEncryptionOptional(params any) (bool, error) {
	return cassandraconf.ClientEncryptionOptional(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) clientEncryptionKeystore(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "client_encryption_options", "keystore"), nil
}

func (c *mqlCassandraConf) clientEncryptionTruststore(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "client_encryption_options", "truststore"), nil
}

func (c *mqlCassandraConf) clientEncryptionRequireClientAuth(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "client_encryption_options", "require_client_auth"), nil
}

func (c *mqlCassandraConf) clientEncryptionRequireEndpointVerification(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "client_encryption_options", "require_endpoint_verification"), nil
}

func (c *mqlCassandraConf) clientEncryptionProtocol(params any) (string, error) {
	v := yamlconf.String(cassandraParams(params), "client_encryption_options", "protocol")
	if v == "" {
		return "TLS", nil
	}
	return v, nil
}

func (c *mqlCassandraConf) clientEncryptionCipherSuites(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "client_encryption_options", "cipher_suites")), nil
}

// internode encryption

func (c *mqlCassandraConf) internodeEncryption(params any) (string, error) {
	return cassandraconf.InternodeEncryption(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) serverEncryptionOptional(params any) (bool, error) {
	return cassandraconf.ServerEncryptionOptional(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) serverEncryptionKeystore(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "server_encryption_options", "keystore"), nil
}

func (c *mqlCassandraConf) serverEncryptionOutboundKeystore(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "server_encryption_options", "outbound_keystore"), nil
}

func (c *mqlCassandraConf) serverEncryptionTruststore(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "server_encryption_options", "truststore"), nil
}

func (c *mqlCassandraConf) serverEncryptionRequireClientAuth(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "server_encryption_options", "require_client_auth"), nil
}

func (c *mqlCassandraConf) serverEncryptionRequireEndpointVerification(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "server_encryption_options", "require_endpoint_verification"), nil
}

func (c *mqlCassandraConf) serverEncryptionProtocol(params any) (string, error) {
	v := yamlconf.String(cassandraParams(params), "server_encryption_options", "protocol")
	if v == "" {
		return "TLS", nil
	}
	return v, nil
}

func (c *mqlCassandraConf) serverEncryptionCipherSuites(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "server_encryption_options", "cipher_suites")), nil
}

func (c *mqlCassandraConf) legacySslStoragePortEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "server_encryption_options", "legacy_ssl_storage_port_enabled"), nil
}

// encryption at rest

func (c *mqlCassandraConf) transparentDataEncryptionEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "transparent_data_encryption_options", "enabled"), nil
}

func (c *mqlCassandraConf) transparentDataEncryptionCipher(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "transparent_data_encryption_options", "cipher"), nil
}

func (c *mqlCassandraConf) transparentDataEncryptionKeyAlias(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "transparent_data_encryption_options", "key_alias"), nil
}

func (c *mqlCassandraConf) transparentDataEncryptionKeyProvider(params any) (string, error) {
	return cassandraconf.TDEKeyProviderClass(cassandraParams(params)), nil
}

// audit and full query logging

func (c *mqlCassandraConf) auditLoggingEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "audit_logging_options", "enabled"), nil
}

func (c *mqlCassandraConf) auditLogger(params any) (string, error) {
	return cassandraconf.AuditLoggerClass(cassandraParams(params)), nil
}

func (c *mqlCassandraConf) auditLogsDir(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "audit_logging_options", "audit_logs_dir"), nil
}

func (c *mqlCassandraConf) auditIncludedKeyspaces(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "included_keyspaces")), nil
}

func (c *mqlCassandraConf) auditExcludedKeyspaces(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "excluded_keyspaces")), nil
}

func (c *mqlCassandraConf) auditIncludedCategories(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "included_categories")), nil
}

func (c *mqlCassandraConf) auditExcludedCategories(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "excluded_categories")), nil
}

func (c *mqlCassandraConf) auditIncludedUsers(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "included_users")), nil
}

func (c *mqlCassandraConf) auditExcludedUsers(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "audit_logging_options", "excluded_users")), nil
}

func (c *mqlCassandraConf) fullQueryLogDir(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "full_query_logging_options", "log_dir"), nil
}

func (c *mqlCassandraConf) fullQueryLogAllowNodetoolArchiveCommand(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "full_query_logging_options", "allow_nodetool_archive_command"), nil
}

// feature toggles

func (c *mqlCassandraConf) userDefinedFunctionsEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "user_defined_functions_enabled"), nil
}

func (c *mqlCassandraConf) materializedViewsEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "materialized_views_enabled"), nil
}

func (c *mqlCassandraConf) sasiIndexesEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "sasi_indexes_enabled"), nil
}

func (c *mqlCassandraConf) dropCompactStorageEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "drop_compact_storage_enabled"), nil
}

func (c *mqlCassandraConf) transientReplicationEnabled(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "transient_replication_enabled"), nil
}

// storage and durability

func (c *mqlCassandraConf) commitlogSync(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "commitlog_sync"), nil
}

func (c *mqlCassandraConf) commitlogDirectory(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "commitlog_directory"), nil
}

func (c *mqlCassandraConf) dataFileDirectories(params any) ([]any, error) {
	return toAnySlice(yamlconf.List(cassandraParams(params), "data_file_directories")), nil
}

func (c *mqlCassandraConf) hintsDirectory(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "hints_directory"), nil
}

func (c *mqlCassandraConf) savedCachesDirectory(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "saved_caches_directory"), nil
}

func (c *mqlCassandraConf) diskFailurePolicy(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "disk_failure_policy"), nil
}

func (c *mqlCassandraConf) commitFailurePolicy(params any) (string, error) {
	return yamlconf.String(cassandraParams(params), "commit_failure_policy"), nil
}

func (c *mqlCassandraConf) incrementalBackups(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), false, "incremental_backups"), nil
}

func (c *mqlCassandraConf) autoSnapshot(params any) (bool, error) {
	return yamlconf.Bool(cassandraParams(params), true, "auto_snapshot"), nil
}

// ---------------------------------------------------------------------------
// cassandra.env
// ---------------------------------------------------------------------------

func initCassandraEnv(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return resolveCassandraPathArg(runtime, args, "cassandra.env")
}

func (c *mqlCassandraEnv) id() (string, error) {
	file := c.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "cassandra-env.sh", nil
	}
	return file.Data.Path.Data, nil
}

func (c *mqlCassandraEnv) file() (*mqlFile, error) {
	return probeCassandraFile(c.MqlRuntime, &c.File, "cassandra-env.sh")
}

// parseEnv reads the script backing this resource.
//
// Both variables and properties come from the same parse, and the parse is
// cheap enough that running it for each is not worth an extra cache: the file
// content itself is already memoized by the file resource.
func (c *mqlCassandraEnv) parseEnv(file *mqlFile) (*cassandraconf.Env, error) {
	content, err := readCassandraFile(file)
	if err != nil {
		return nil, err
	}
	return cassandraconf.ParseEnv(content), nil
}

func (c *mqlCassandraEnv) variables(file *mqlFile) (map[string]any, error) {
	env, err := c.parseEnv(file)
	if err != nil {
		return nil, err
	}
	return toAnyMap(env.Variables), nil
}

func (c *mqlCassandraEnv) properties(file *mqlFile) (map[string]any, error) {
	env, err := c.parseEnv(file)
	if err != nil {
		return nil, err
	}
	return toAnyMap(env.Properties), nil
}

// envFrom rebuilds the reader over an already-computed field, so the JMX
// accessors read the same resolved values the map fields report.
func envFrom(variables, properties map[string]any) *cassandraconf.Env {
	return &cassandraconf.Env{
		Variables:  fromAnyMap(variables),
		Properties: fromAnyMap(properties),
	}
}

func (c *mqlCassandraEnv) localJmx(variables map[string]any) (bool, error) {
	return envFrom(variables, nil).LocalJMX(), nil
}

// jmxPort reads the port out of the resolved properties, falling back to the
// JMX_PORT variable for a script that sets it without threading it into a
// system property.
func (c *mqlCassandraEnv) jmxPort(properties map[string]any) (int64, error) {
	variables := c.GetVariables()
	if variables.Error != nil {
		return 0, variables.Error
	}
	return envFrom(variables.Data, properties).JMXPort(), nil
}

// jmxAuthenticate reports whether JMX requires credentials.
//
// The default is false because that is what the shipped script sets for the
// localhost-only case, which is the case a host that never touched this file
// is in.
func (c *mqlCassandraEnv) jmxAuthenticate(properties map[string]any) (bool, error) {
	return envFrom(nil, properties).Bool(cassandraconf.PropJMXAuthenticate, false), nil
}

func (c *mqlCassandraEnv) jmxSsl(properties map[string]any) (bool, error) {
	return envFrom(nil, properties).Bool(cassandraconf.PropJMXSSL, false), nil
}

func (c *mqlCassandraEnv) jmxSslRequireClientAuth(properties map[string]any) (bool, error) {
	return envFrom(nil, properties).Bool(cassandraconf.PropJMXSSLClientAuth, false), nil
}

func (c *mqlCassandraEnv) jmxPasswordFile(properties map[string]any) (string, error) {
	return envFrom(nil, properties).String(cassandraconf.PropJMXPasswordFile), nil
}

func (c *mqlCassandraEnv) jmxAccessFile(properties map[string]any) (string, error) {
	return envFrom(nil, properties).String(cassandraconf.PropJMXAccessFile), nil
}

func (c *mqlCassandraEnv) jmxAuthorizer(properties map[string]any) (string, error) {
	return envFrom(nil, properties).String(cassandraconf.PropJMXAuthorizer), nil
}

func (c *mqlCassandraEnv) jmxLoginConfig(properties map[string]any) (string, error) {
	return envFrom(nil, properties).String(cassandraconf.PropJMXLoginConfig), nil
}

// ---------------------------------------------------------------------------
// cassandra.rackdc
// ---------------------------------------------------------------------------

func initCassandraRackdc(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return resolveCassandraPathArg(runtime, args, "cassandra.rackdc")
}

func (c *mqlCassandraRackdc) id() (string, error) {
	file := c.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "cassandra-rackdc.properties", nil
	}
	return file.Data.Path.Data, nil
}

func (c *mqlCassandraRackdc) file() (*mqlFile, error) {
	return probeCassandraFile(c.MqlRuntime, &c.File, "cassandra-rackdc.properties")
}

func (c *mqlCassandraRackdc) params(file *mqlFile) (map[string]any, error) {
	content, err := readCassandraFile(file)
	if err != nil {
		return nil, err
	}
	return toAnyMap(cassandraconf.ParseProperties(content)), nil
}

func (c *mqlCassandraRackdc) dc(params map[string]any) (string, error) {
	return propString(params, "dc"), nil
}

func (c *mqlCassandraRackdc) rack(params map[string]any) (string, error) {
	return propString(params, "rack"), nil
}

func (c *mqlCassandraRackdc) preferLocal(params map[string]any) (bool, error) {
	return propString(params, "prefer_local") == "true", nil
}

func (c *mqlCassandraRackdc) dcSuffix(params map[string]any) (string, error) {
	return propString(params, "dc_suffix"), nil
}

// propString reads a properties entry, guarding the type assertion so a
// surprising value cannot panic the executor goroutine.
func propString(params map[string]any, key string) string {
	v, ok := params[key].(string)
	if !ok {
		return ""
	}
	return v
}

// toAnyMap widens a string map to the type llx uses for map[string]string.
func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// fromAnyMap narrows an llx string map back, dropping anything that is not a
// string rather than asserting on it.
func fromAnyMap(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

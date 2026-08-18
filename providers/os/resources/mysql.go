// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/resources/mycnf"
)

// ---------------------------------------------------------------------------
// mysql
// ---------------------------------------------------------------------------

type mqlMysqlInternal struct {
	lock     sync.Mutex
	detected bool
	// Named apart from the version and flavor fields the generator produces,
	// which carry the accessor methods of the same name.
	cachedVersion string
	cachedFlavor  string
}

func (m *mqlMysql) id() (string, error) {
	return "mysql", nil
}

// detect reads the server version once and keeps it, so version and flavor
// share a single binary read.
//
// A MariaDB server is deliberately not reported here even though it installs a
// binary named mysqld: this resource covers MySQL and Percona Server, and
// reporting MariaDB's version under it would make a version assertion pass
// against a product the audit never meant to cover.
func (m *mqlMysql) detect() {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.detected {
		return
	}
	m.detected = true

	version, flavor := detectServerVersion(m.MqlRuntime)
	if flavor == mycnf.FlavorMariaDB {
		return
	}
	m.cachedVersion = version
	m.cachedFlavor = flavor
}

func (m *mqlMysql) version() (string, error) {
	m.detect()
	if m.cachedVersion == "" {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return m.cachedVersion, nil
}

func (m *mqlMysql) flavor() (string, error) {
	m.detect()
	if m.cachedFlavor == "" {
		m.Flavor.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return m.cachedFlavor, nil
}

// ---------------------------------------------------------------------------
// mysql.conf
// ---------------------------------------------------------------------------

type mqlMysqlConfInternal struct {
	mycnfState
}

func initMysqlConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in mysql.conf initialization, it must be a string")
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
		delete(args, "path")
	}
	return args, nil, nil
}

func (s *mqlMysqlConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "mysql.conf", nil
	}
	return file.Data.Path.Data, nil
}

// file locates the root option file. It is only reached when the resource was
// not initialized with an explicit path, so this is always the probe path.
func (s *mqlMysqlConf) file() (*mqlFile, error) {
	if err := s.resolve(s.MqlRuntime, mycnf.FlavorMySQL, mysqlConfPaths, ""); err != nil {
		return nil, err
	}
	f := s.rootFile()
	if f == nil {
		// No MySQL option file on this host, either because MySQL is not
		// installed or because the option files found belong to MariaDB.
		// Mark the field set and null so dependent fields report empty
		// instead of cascading a missing-file error.
		s.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f, nil
}

func (s *mqlMysqlConf) ensure(file *mqlFile) error {
	return s.ensureFrom(s.MqlRuntime, mycnf.FlavorMySQL, mysqlConfPaths, file)
}

func (s *mqlMysqlConf) files(file *mqlFile) ([]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.fileList(), nil
}

func (s *mqlMysqlConf) sections(file *mqlFile) ([]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.sectionResources(s.MqlRuntime, "mysql.conf.section")
}

func (s *mqlMysqlConf) serverOptions(file *mqlFile) (map[string]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.optionMap(mycnf.ServerGroups(mycnf.FlavorMySQL)...), nil
}

func (s *mqlMysqlConf) clientOptions(file *mqlFile) (map[string]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.optionMap(mycnf.ClientGroups(mycnf.FlavorMySQL)...), nil
}

func (s *mqlMysqlConf) userFiles() ([]any, error) {
	return userOptionFiles(s.MqlRuntime, "mysql.conf.userOptionFile")
}

// networking

func (s *mqlMysqlConf) port(serverOptions map[string]any) (int64, error) {
	return optionInt(serverOptions, "port", 3306), nil
}

func (s *mqlMysqlConf) bindAddress(serverOptions map[string]any) ([]any, error) {
	return bindAddressList(serverOptions), nil
}

func (s *mqlMysqlConf) socket(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "socket"), nil
}

func (s *mqlMysqlConf) skipNetworking(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_networking"), nil
}

func (s *mqlMysqlConf) skipNameResolve(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_name_resolve"), nil
}

func (s *mqlMysqlConf) maxConnections(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "max_connections")
	if !ok {
		s.MaxConnections.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

// TLS

func (s *mqlMysqlConf) requireSecureTransport(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "require_secure_transport"), nil
}

func (s *mqlMysqlConf) sslCaFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_ca"), nil
}

func (s *mqlMysqlConf) sslCaPath(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_capath"), nil
}

func (s *mqlMysqlConf) sslCertFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_cert"), nil
}

func (s *mqlMysqlConf) sslKeyFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_key"), nil
}

func (s *mqlMysqlConf) sslCrlFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_crl"), nil
}

func (s *mqlMysqlConf) sslCipher(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_cipher"), nil
}

func (s *mqlMysqlConf) sslFipsMode(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_fips_mode"), nil
}

func (s *mqlMysqlConf) tlsVersion(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "tls_version"), nil
}

func (s *mqlMysqlConf) tlsCiphersuites(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "tls_ciphersuites"), nil
}

func (s *mqlMysqlConf) certificate() ([]any, error) {
	path := s.GetSslCertFile()
	if path.Error != nil || path.Data == "" {
		return []any{}, nil
	}
	return readCertificatesFromPath(s.MqlRuntime, path.Data)
}

// authentication and password policy

func (s *mqlMysqlConf) defaultAuthenticationPlugin(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "default_authentication_plugin"), nil
}

func (s *mqlMysqlConf) authenticationPolicy(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "authentication_policy"), nil
}

func (s *mqlMysqlConf) skipGrantTables(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_grant_tables"), nil
}

func (s *mqlMysqlConf) pluginDir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "plugin_dir"), nil
}

func (s *mqlMysqlConf) pluginLoad(serverOptions map[string]any) ([]any, error) {
	return pluginLoadList(serverOptions), nil
}

func (s *mqlMysqlConf) earlyPluginLoad(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "early_plugin_load"), nil
}

func (s *mqlMysqlConf) validatePasswordPolicy(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "validate_password.policy"), nil
}

func (s *mqlMysqlConf) validatePasswordLength(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "validate_password.length")
	if !ok {
		s.ValidatePasswordLength.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) validatePasswordCheckUserName(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "validate_password.check_user_name"), nil
}

func (s *mqlMysqlConf) defaultPasswordLifetime(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "default_password_lifetime")
	if !ok {
		s.DefaultPasswordLifetime.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) passwordHistory(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "password_history")
	if !ok {
		s.PasswordHistory.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) passwordReuseInterval(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "password_reuse_interval")
	if !ok {
		s.PasswordReuseInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) passwordRequireCurrent(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "password_require_current"), nil
}

// filesystem and privileges

func (s *mqlMysqlConf) runAsUser() (*mqlUser, error) {
	options := s.GetServerOptions()
	if options.Error != nil {
		s.RunAsUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, ok := resolveRunAsUser(s.MqlRuntime, options.Data)
	if !ok {
		s.RunAsUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

func (s *mqlMysqlConf) datadir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "datadir"), nil
}

func (s *mqlMysqlConf) basedir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "basedir"), nil
}

func (s *mqlMysqlConf) tmpdir(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "tmpdir"), nil
}

func (s *mqlMysqlConf) secureFilePriv(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "secure_file_priv"), nil
}

func (s *mqlMysqlConf) localInfile(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "local_infile"), nil
}

func (s *mqlMysqlConf) symbolicLinks(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "symbolic_links"), nil
}

func (s *mqlMysqlConf) allowSuspiciousUdfs(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "allow_suspicious_udfs"), nil
}

func (s *mqlMysqlConf) chroot(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "chroot"), nil
}

func (s *mqlMysqlConf) pidFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "pid_file"), nil
}

func (s *mqlMysqlConf) skipShowDatabase(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_show_database"), nil
}

func (s *mqlMysqlConf) automaticSpPrivileges(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "automatic_sp_privileges"), nil
}

func (s *mqlMysqlConf) logBinTrustFunctionCreators(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "log_bin_trust_function_creators"), nil
}

func (s *mqlMysqlConf) sqlMode(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "sql_mode"), nil
}

// logging

func (s *mqlMysqlConf) logError(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "log_error"), nil
}

func (s *mqlMysqlConf) logErrorVerbosity(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "log_error_verbosity")
	if !ok {
		s.LogErrorVerbosity.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) logOutput(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "log_output"), nil
}

func (s *mqlMysqlConf) generalLog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "general_log"), nil
}

func (s *mqlMysqlConf) generalLogFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "general_log_file"), nil
}

func (s *mqlMysqlConf) slowQueryLog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "slow_query_log"), nil
}

func (s *mqlMysqlConf) slowQueryLogFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "slow_query_log_file"), nil
}

func (s *mqlMysqlConf) auditLogPolicy(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "audit_log_policy"), nil
}

func (s *mqlMysqlConf) auditLogFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "audit_log_file"), nil
}

func (s *mqlMysqlConf) auditLogFormat(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "audit_log_format"), nil
}

// binary logging and replication

func (s *mqlMysqlConf) logBin(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "log_bin"), nil
}

func (s *mqlMysqlConf) binlogFormat(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "binlog_format"), nil
}

func (s *mqlMysqlConf) binlogExpireLogsSeconds(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "binlog_expire_logs_seconds")
	if !ok {
		s.BinlogExpireLogsSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) binlogEncryption(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "binlog_encryption"), nil
}

func (s *mqlMysqlConf) serverId(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "server_id")
	if !ok {
		s.ServerId.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMysqlConf) gtidMode(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "gtid_mode"), nil
}

func (s *mqlMysqlConf) enforceGtidConsistency(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "enforce_gtid_consistency"), nil
}

func (s *mqlMysqlConf) readOnly(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "read_only"), nil
}

func (s *mqlMysqlConf) superReadOnly(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "super_read_only"), nil
}

// encryption at rest

func (s *mqlMysqlConf) defaultTableEncryption(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "default_table_encryption"), nil
}

func (s *mqlMysqlConf) tableEncryptionPrivilegeCheck(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "table_encryption_privilege_check"), nil
}

func (s *mqlMysqlConf) innodbRedoLogEncrypt(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "innodb_redo_log_encrypt"), nil
}

func (s *mqlMysqlConf) innodbUndoLogEncrypt(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "innodb_undo_log_encrypt"), nil
}

func (s *mqlMysqlConf) keyringFileData(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "keyring_file_data"), nil
}

// ---------------------------------------------------------------------------
// mysql.conf.section
// ---------------------------------------------------------------------------

func (s *mqlMysqlConfSection) id() (string, error) {
	return s.__id, nil
}

// ---------------------------------------------------------------------------
// mysql.conf.userOptionFile
// ---------------------------------------------------------------------------

func (s *mqlMysqlConfUserOptionFile) id() (string, error) {
	return s.__id, nil
}

func (s *mqlMysqlConfUserOptionFile) sections() ([]any, error) {
	file := s.GetFile()
	if file.Error != nil {
		return []any{}, nil
	}
	return userOptionFileSections(s.MqlRuntime, "mysql.conf.section", s.Format.Data, file.Data)
}

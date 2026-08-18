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
// mariadb
// ---------------------------------------------------------------------------

type mqlMariadbInternal struct {
	lock     sync.Mutex
	detected bool
	// Named apart from the version field the generator produces, which
	// carries the accessor method of the same name.
	cachedVersion string
}

func (m *mqlMariadb) id() (string, error) {
	return "mariadb", nil
}

// detect reads the server version once and keeps it.
//
// MariaDB installs a binary named mysqld alongside mariadbd, and both print the
// same banner, so the version is accepted only when the banner itself names
// MariaDB.
func (m *mqlMariadb) detect() {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.detected {
		return
	}
	m.detected = true

	version, flavor := detectServerVersion(m.MqlRuntime)
	if flavor != mycnf.FlavorMariaDB {
		return
	}
	m.cachedVersion = version
}

func (m *mqlMariadb) version() (string, error) {
	m.detect()
	if m.cachedVersion == "" {
		m.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return m.cachedVersion, nil
}

// ---------------------------------------------------------------------------
// mariadb.conf
// ---------------------------------------------------------------------------

type mqlMariadbConfInternal struct {
	mycnfState
}

func initMariadbConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in mariadb.conf initialization, it must be a string")
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

func (s *mqlMariadbConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "mariadb.conf", nil
	}
	return file.Data.Path.Data, nil
}

func (s *mqlMariadbConf) file() (*mqlFile, error) {
	if err := s.resolve(s.MqlRuntime, mycnf.FlavorMariaDB, mariadbConfPaths, ""); err != nil {
		return nil, err
	}
	f := s.rootFile()
	if f == nil {
		// No MariaDB option file on this host, either because MariaDB is not
		// installed or because the option files found belong to MySQL.
		s.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f, nil
}

func (s *mqlMariadbConf) ensure(file *mqlFile) error {
	return s.ensureFrom(s.MqlRuntime, mycnf.FlavorMariaDB, mariadbConfPaths, file)
}

func (s *mqlMariadbConf) files(file *mqlFile) ([]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.fileList(), nil
}

func (s *mqlMariadbConf) sections(file *mqlFile) ([]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.sectionResources(s.MqlRuntime, "mariadb.conf.section")
}

func (s *mqlMariadbConf) serverOptions(file *mqlFile) (map[string]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.optionMap(mycnf.ServerGroups(mycnf.FlavorMariaDB)...), nil
}

func (s *mqlMariadbConf) clientOptions(file *mqlFile) (map[string]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.optionMap(mycnf.ClientGroups(mycnf.FlavorMariaDB)...), nil
}

func (s *mqlMariadbConf) galeraOptions(file *mqlFile) (map[string]any, error) {
	if err := s.ensure(file); err != nil {
		return nil, err
	}
	return s.optionMap("galera"), nil
}

func (s *mqlMariadbConf) userFiles() ([]any, error) {
	return userOptionFiles(s.MqlRuntime, "mariadb.conf.userOptionFile")
}

// networking

func (s *mqlMariadbConf) port(serverOptions map[string]any) (int64, error) {
	return optionInt(serverOptions, "port", 3306), nil
}

func (s *mqlMariadbConf) bindAddress(serverOptions map[string]any) ([]any, error) {
	return bindAddressList(serverOptions), nil
}

func (s *mqlMariadbConf) socket(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "socket"), nil
}

func (s *mqlMariadbConf) skipNetworking(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_networking"), nil
}

func (s *mqlMariadbConf) skipNameResolve(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_name_resolve"), nil
}

func (s *mqlMariadbConf) maxConnections(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "max_connections")
	if !ok {
		s.MaxConnections.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

// TLS

func (s *mqlMariadbConf) requireSecureTransport(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "require_secure_transport"), nil
}

func (s *mqlMariadbConf) sslCaFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_ca"), nil
}

func (s *mqlMariadbConf) sslCaPath(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_capath"), nil
}

func (s *mqlMariadbConf) sslCertFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_cert"), nil
}

func (s *mqlMariadbConf) sslKeyFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_key"), nil
}

func (s *mqlMariadbConf) sslCrlFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_crl"), nil
}

func (s *mqlMariadbConf) sslCipher(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "ssl_cipher"), nil
}

func (s *mqlMariadbConf) tlsVersion(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "tls_version"), nil
}

func (s *mqlMariadbConf) certificate() ([]any, error) {
	path := s.GetSslCertFile()
	if path.Error != nil || path.Data == "" {
		return []any{}, nil
	}
	return readCertificatesFromPath(s.MqlRuntime, path.Data)
}

// authentication and password policy

func (s *mqlMariadbConf) skipGrantTables(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_grant_tables"), nil
}

func (s *mqlMariadbConf) pluginDir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "plugin_dir"), nil
}

func (s *mqlMariadbConf) pluginLoad(serverOptions map[string]any) ([]any, error) {
	return pluginLoadList(serverOptions), nil
}

func (s *mqlMariadbConf) simplePasswordCheckMinimalLength(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "simple_password_check_minimal_length")
	if !ok {
		s.SimplePasswordCheckMinimalLength.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) simplePasswordCheckDigits(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "simple_password_check_digits")
	if !ok {
		s.SimplePasswordCheckDigits.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) simplePasswordCheckLetters(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "simple_password_check_letters_same_case")
	if !ok {
		s.SimplePasswordCheckLetters.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) simplePasswordCheckOtherCharacters(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "simple_password_check_other_characters")
	if !ok {
		s.SimplePasswordCheckOtherCharacters.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) passwordReuseCheckInterval(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "password_reuse_check_interval")
	if !ok {
		s.PasswordReuseCheckInterval.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

// filesystem and privileges

func (s *mqlMariadbConf) runAsUser() (*mqlUser, error) {
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

func (s *mqlMariadbConf) datadir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "datadir"), nil
}

func (s *mqlMariadbConf) basedir(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "basedir"), nil
}

func (s *mqlMariadbConf) tmpdir(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "tmpdir"), nil
}

func (s *mqlMariadbConf) secureFilePriv(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "secure_file_priv"), nil
}

func (s *mqlMariadbConf) localInfile(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "local_infile"), nil
}

func (s *mqlMariadbConf) symbolicLinks(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "symbolic_links"), nil
}

func (s *mqlMariadbConf) allowSuspiciousUdfs(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "allow_suspicious_udfs"), nil
}

func (s *mqlMariadbConf) chroot(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "chroot"), nil
}

func (s *mqlMariadbConf) pidFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "pid_file"), nil
}

func (s *mqlMariadbConf) skipShowDatabase(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "skip_show_database"), nil
}

func (s *mqlMariadbConf) automaticSpPrivileges(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "automatic_sp_privileges"), nil
}

func (s *mqlMariadbConf) logBinTrustFunctionCreators(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "log_bin_trust_function_creators"), nil
}

func (s *mqlMariadbConf) sqlMode(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "sql_mode"), nil
}

// logging

func (s *mqlMariadbConf) logError(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "log_error"), nil
}

func (s *mqlMariadbConf) logWarnings(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "log_warnings")
	if !ok {
		s.LogWarnings.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) logOutput(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "log_output"), nil
}

func (s *mqlMariadbConf) generalLog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "general_log"), nil
}

func (s *mqlMariadbConf) generalLogFile(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "general_log_file"), nil
}

func (s *mqlMariadbConf) slowQueryLog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "slow_query_log"), nil
}

// slowQueryLogFile reads the two spellings MariaDB accepts for one setting.
// log_slow_query_file is the name its own packages write into 50-server.cnf on
// Debian and Ubuntu; slow_query_log_file is the MySQL-compatible synonym, and
// the server reports the value under that name whichever one set it. Reading
// only the MySQL name reports nothing on a packaged server whose administrator
// uncommented the line the package shipped, which is the configuration this
// field exists to locate.
//
// When a file sets both, MariaDB takes the last one it reads; the merged option
// map cannot express that order, so the native spelling is preferred here.
func (s *mqlMariadbConf) slowQueryLogFile(serverOptions map[string]any) (string, error) {
	if v := optionString(serverOptions, "log_slow_query_file"); v != "" {
		return v, nil
	}
	return optionString(serverOptions, "slow_query_log_file"), nil
}

func (s *mqlMariadbConf) serverAuditLogging(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "server_audit_logging"), nil
}

func (s *mqlMariadbConf) serverAuditEvents(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "server_audit_events"), nil
}

func (s *mqlMariadbConf) serverAuditFilePath(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "server_audit_file_path"), nil
}

func (s *mqlMariadbConf) serverAuditExclUsers(serverOptions map[string]any) ([]any, error) {
	return optionList(serverOptions, "server_audit_excl_users"), nil
}

// binary logging and replication

func (s *mqlMariadbConf) logBin(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "log_bin"), nil
}

func (s *mqlMariadbConf) binlogFormat(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "binlog_format"), nil
}

func (s *mqlMariadbConf) expireLogsDays(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "expire_logs_days")
	if !ok {
		s.ExpireLogsDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) serverId(serverOptions map[string]any) (int64, error) {
	v, ok := optionCount(serverOptions, "server_id")
	if !ok {
		s.ServerId.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (s *mqlMariadbConf) gtidStrictMode(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "gtid_strict_mode"), nil
}

func (s *mqlMariadbConf) readOnly(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "read_only"), nil
}

// encryption at rest

func (s *mqlMariadbConf) innodbEncryptTables(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "innodb_encrypt_tables"), nil
}

func (s *mqlMariadbConf) innodbEncryptLog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "innodb_encrypt_log"), nil
}

func (s *mqlMariadbConf) encryptTmpDiskTables(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "encrypt_tmp_disk_tables"), nil
}

func (s *mqlMariadbConf) encryptBinlog(serverOptions map[string]any) (bool, error) {
	return optionBool(serverOptions, "encrypt_binlog"), nil
}

func (s *mqlMariadbConf) fileKeyManagementFilename(serverOptions map[string]any) (string, error) {
	return optionString(serverOptions, "file_key_management_filename"), nil
}

// Galera cluster

func (s *mqlMariadbConf) wsrepOn(galeraOptions map[string]any) (bool, error) {
	return optionBool(galeraOptions, "wsrep_on"), nil
}

func (s *mqlMariadbConf) wsrepClusterAddress(galeraOptions map[string]any) (string, error) {
	return optionString(galeraOptions, "wsrep_cluster_address"), nil
}

func (s *mqlMariadbConf) wsrepClusterName(galeraOptions map[string]any) (string, error) {
	return optionString(galeraOptions, "wsrep_cluster_name"), nil
}

func (s *mqlMariadbConf) wsrepSstMethod(galeraOptions map[string]any) (string, error) {
	return optionString(galeraOptions, "wsrep_sst_method"), nil
}

func (s *mqlMariadbConf) wsrepProviderOptions(galeraOptions map[string]any) (string, error) {
	return optionString(galeraOptions, "wsrep_provider_options"), nil
}

// ---------------------------------------------------------------------------
// mariadb.conf.section
// ---------------------------------------------------------------------------

func (s *mqlMariadbConfSection) id() (string, error) {
	return s.__id, nil
}

// ---------------------------------------------------------------------------
// mariadb.conf.userOptionFile
// ---------------------------------------------------------------------------

func (s *mqlMariadbConfUserOptionFile) id() (string, error) {
	return s.__id, nil
}

func (s *mqlMariadbConfUserOptionFile) sections() ([]any, error) {
	file := s.GetFile()
	if file.Error != nil {
		return []any{}, nil
	}
	return userOptionFileSections(s.MqlRuntime, "mariadb.conf.section", s.Format.Data, file.Data)
}

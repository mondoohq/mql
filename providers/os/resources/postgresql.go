// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/postgresql"
	"go.mondoo.com/mql/v13/types"
)

// ---------------------------------------------------------------------------
// postgresql.conf
// ---------------------------------------------------------------------------

// postgresqlConfPaths lists well-known paths the parser will probe when no
// explicit `path` argument is given. Postgres installations are highly
// version- and distro-specific, so we walk this list in order and stop at
// the first existing file. Debian/Ubuntu uses version-stamped subdirectories
// (/etc/postgresql/<MAJOR>/main); for those we list the conventional `main`
// cluster across the supported major versions.
var postgresqlConfPaths = []string{
	"/etc/postgresql/17/main/postgresql.conf",
	"/etc/postgresql/16/main/postgresql.conf",
	"/etc/postgresql/15/main/postgresql.conf",
	"/etc/postgresql/14/main/postgresql.conf",
	"/etc/postgresql/13/main/postgresql.conf",
	"/etc/postgresql/12/main/postgresql.conf",
	"/var/lib/postgresql/data/postgresql.conf",
	"/var/lib/pgsql/data/postgresql.conf",
	"/var/lib/pgsql/17/data/postgresql.conf",
	"/var/lib/pgsql/16/data/postgresql.conf",
	"/var/lib/pgsql/15/data/postgresql.conf",
	"/var/lib/pgsql/14/data/postgresql.conf",
	"/var/lib/pgsql/13/data/postgresql.conf",
	"/usr/local/var/postgres/postgresql.conf",
	"/usr/local/pgsql/data/postgresql.conf",
}

type mqlPostgresqlConfInternal struct {
	lock sync.Mutex
	// parsed flips to true once parse() has run to completion (whether the
	// outcome was data, empty, or an error). It's a dedicated flag rather
	// than overloading `s.Params.State` because the empty- and error-paths
	// set extra state bits (StateIsNull) that the previous equality guard
	// failed to recognise as "already parsed", causing infinite re-parses.
	parsed bool
}

func initPostgresqlConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in postgresql.conf initialization, it must be a string")
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

func (s *mqlPostgresqlConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "postgresql.conf", nil
	}
	return file.Data.Path.Data, nil
}

func (s *mqlPostgresqlConf) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, path := range postgresqlConfPaths {
		if ok, _ := afs.Exists(path); ok {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	// No config file found anywhere — PostgreSQL likely isn't installed.
	// Mark every dependent field set+null so downstream accessors return
	// empty data instead of cascading "file does not exist" errors.
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlPostgresqlConf) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.parsed {
		return nil
	}
	// Flip the guard before any early-return path so transient empty/error
	// outcomes don't trigger an infinite re-parse loop on subsequent field
	// accesses.
	s.parsed = true

	if file == nil {
		s.setConfEmpty()
		return nil
	}
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		s.setConfEmpty()
		return nil
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	filesIdx := map[string]*mqlFile{file.Path.Data: file}

	fileReader := func(path string) (string, error) {
		f, ok := filesIdx[path]
		if !ok {
			raw, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return "", err
			}
			f = raw.(*mqlFile)
			filesIdx[path] = f
		}
		content := f.GetContent()
		if content.Error != nil {
			return "", content.Error
		}
		return content.Data, nil
	}

	dirLister := func(dir string) ([]string, error) {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
		return paths, nil
	}

	cfg, err := postgresql.ParseConf(file.Path.Data, fileReader, dirLister)
	if err != nil {
		// Surface the parse error to every dependent field. The error is
		// the same across all of them — we don't try to dissect which field
		// is to blame.
		s.setConfError(err)
		return err
	}

	params := make(map[string]any, len(cfg.Params))
	for k, v := range cfg.Params {
		params[k] = v
	}
	s.Params = plugin.TValue[map[string]any]{Data: params, State: plugin.StateIsSet}

	files := make([]any, 0, len(filesIdx))
	for _, f := range filesIdx {
		files = append(files, f)
	}
	s.Files = plugin.TValue[[]any]{Data: files, State: plugin.StateIsSet}

	return nil
}

func (s *mqlPostgresqlConf) setConfEmpty() {
	s.Params = plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}
	s.Files = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
}

func (s *mqlPostgresqlConf) setConfError(err error) {
	errState := plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.Params = errState
	s.Files = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
}

func (s *mqlPostgresqlConf) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlPostgresqlConf) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

// Convenience views into specific directives. They all derive from `params`
// so they share the same parse cycle (single file read, single tokenisation).

// confAbsent reports that no postgresql.conf was found anywhere on the host.
//
// The convenience accessors below fall back to PostgreSQL's documented
// defaults when a directive is missing from the file, which is correct when
// the file exists and simply omits it. With no file at all there is nothing to
// default from: reporting port 5432, listenAddresses ["localhost"] or
// sslEnabled false describes a posture nobody ever configured. Worse, it reads
// as a real finding, and a check asserting "does not listen on *" passes
// against a host where PostgreSQL was never set up.
func (s *mqlPostgresqlConf) confAbsent() bool {
	return s.File.State&plugin.StateIsNull != 0
}

func (s *mqlPostgresqlConf) listenAddresses(params map[string]any) ([]any, error) {
	if s.confAbsent() {
		s.ListenAddresses.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	v := paramString(params, "listen_addresses")
	if v == "" {
		// Default per PostgreSQL: 'localhost' if unset.
		v = "localhost"
	}
	parts := postgresql.SplitListParam(v)
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out, nil
}

func (s *mqlPostgresqlConf) port(params map[string]any) (int64, error) {
	if s.confAbsent() {
		s.Port.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}

	v := paramString(params, "port")
	if v == "" {
		return 5432, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 5432, nil
	}
	return n, nil
}

func (s *mqlPostgresqlConf) sslEnabled(params map[string]any) (bool, error) {
	if s.confAbsent() {
		s.SslEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return postgresql.IsTruthy(paramString(params, "ssl")), nil
}

func (s *mqlPostgresqlConf) sslCertFile(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.SslCertFile.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ssl_cert_file"), nil
}

func (s *mqlPostgresqlConf) sslKeyFile(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.SslKeyFile.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ssl_key_file"), nil
}

func (s *mqlPostgresqlConf) sslCaFile(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.SslCaFile.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ssl_ca_file"), nil
}

func (s *mqlPostgresqlConf) sslMinProtocolVersion(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.SslMinProtocolVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ssl_min_protocol_version"), nil
}

func (s *mqlPostgresqlConf) sslCiphers(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.SslCiphers.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ssl_ciphers"), nil
}

func (s *mqlPostgresqlConf) passwordEncryption(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.PasswordEncryption.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "password_encryption"), nil
}

func (s *mqlPostgresqlConf) dataDirectory(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.DataDirectory.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "data_directory"), nil
}

func (s *mqlPostgresqlConf) hbaFile(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.HbaFile.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "hba_file"), nil
}

func (s *mqlPostgresqlConf) identFile(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.IdentFile.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "ident_file"), nil
}

func (s *mqlPostgresqlConf) logDestination(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.LogDestination.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "log_destination"), nil
}

func (s *mqlPostgresqlConf) loggingCollector(params map[string]any) (bool, error) {
	if s.confAbsent() {
		s.LoggingCollector.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return postgresql.IsTruthy(paramString(params, "logging_collector")), nil
}

func (s *mqlPostgresqlConf) logConnections(params map[string]any) (bool, error) {
	if s.confAbsent() {
		s.LogConnections.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return postgresql.IsTruthy(paramString(params, "log_connections")), nil
}

func (s *mqlPostgresqlConf) logDisconnections(params map[string]any) (bool, error) {
	if s.confAbsent() {
		s.LogDisconnections.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	return postgresql.IsTruthy(paramString(params, "log_disconnections")), nil
}

func (s *mqlPostgresqlConf) logStatement(params map[string]any) (string, error) {
	if s.confAbsent() {
		s.LogStatement.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	return paramString(params, "log_statement"), nil
}

func (s *mqlPostgresqlConf) sharedPreloadLibraries(params map[string]any) ([]any, error) {
	if s.confAbsent() {
		s.SharedPreloadLibraries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parts := postgresql.SplitListParam(paramString(params, "shared_preload_libraries"))
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// postgresql.hba
// ---------------------------------------------------------------------------

var postgresqlHbaPaths = []string{
	"/etc/postgresql/17/main/pg_hba.conf",
	"/etc/postgresql/16/main/pg_hba.conf",
	"/etc/postgresql/15/main/pg_hba.conf",
	"/etc/postgresql/14/main/pg_hba.conf",
	"/etc/postgresql/13/main/pg_hba.conf",
	"/etc/postgresql/12/main/pg_hba.conf",
	"/var/lib/postgresql/data/pg_hba.conf",
	"/var/lib/pgsql/data/pg_hba.conf",
	"/var/lib/pgsql/17/data/pg_hba.conf",
	"/var/lib/pgsql/16/data/pg_hba.conf",
	"/var/lib/pgsql/15/data/pg_hba.conf",
	"/var/lib/pgsql/14/data/pg_hba.conf",
	"/var/lib/pgsql/13/data/pg_hba.conf",
	"/usr/local/var/postgres/pg_hba.conf",
	"/usr/local/pgsql/data/pg_hba.conf",
}

func initPostgresqlHba(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in postgresql.hba initialization, it must be a string")
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

func (s *mqlPostgresqlHba) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "postgresql.hba", nil
	}
	return file.Data.Path.Data, nil
}

func (s *mqlPostgresqlHba) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, path := range postgresqlHbaPaths {
		if ok, _ := afs.Exists(path); ok {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlPostgresqlHba) rules(file *mqlFile) ([]any, error) {
	if file == nil {
		return []any{}, nil
	}
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	rules := postgresql.ParseHba(content.Data)

	out := make([]any, 0, len(rules))
	for _, rule := range rules {
		opts := make(map[string]any, len(rule.Options))
		for k, v := range rule.Options {
			opts[k] = v
		}
		res, err := CreateResource(s.MqlRuntime, "postgresql.hba.rule", map[string]*llx.RawData{
			"__id":       llx.StringData(file.Path.Data + ":" + strconv.Itoa(rule.LineNumber)),
			"lineNumber": llx.IntData(int64(rule.LineNumber)),
			"type":       llx.StringData(rule.Type),
			"database":   llx.StringData(rule.Database),
			"user":       llx.StringData(rule.User),
			"address":    llx.StringData(rule.Address),
			"authMethod": llx.StringData(rule.AuthMethod),
			"options":    llx.MapData(opts, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *mqlPostgresqlHbaRule) id() (string, error) {
	return s.__id, nil
}

// ---------------------------------------------------------------------------
// postgresql.ident
// ---------------------------------------------------------------------------

var postgresqlIdentPaths = []string{
	"/etc/postgresql/17/main/pg_ident.conf",
	"/etc/postgresql/16/main/pg_ident.conf",
	"/etc/postgresql/15/main/pg_ident.conf",
	"/etc/postgresql/14/main/pg_ident.conf",
	"/etc/postgresql/13/main/pg_ident.conf",
	"/etc/postgresql/12/main/pg_ident.conf",
	"/var/lib/postgresql/data/pg_ident.conf",
	"/var/lib/pgsql/data/pg_ident.conf",
	"/var/lib/pgsql/17/data/pg_ident.conf",
	"/var/lib/pgsql/16/data/pg_ident.conf",
	"/var/lib/pgsql/15/data/pg_ident.conf",
	"/var/lib/pgsql/14/data/pg_ident.conf",
	"/var/lib/pgsql/13/data/pg_ident.conf",
	"/usr/local/var/postgres/pg_ident.conf",
	"/usr/local/pgsql/data/pg_ident.conf",
}

func initPostgresqlIdent(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in postgresql.ident initialization, it must be a string")
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

func (s *mqlPostgresqlIdent) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "postgresql.ident", nil
	}
	return file.Data.Path.Data, nil
}

func (s *mqlPostgresqlIdent) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, path := range postgresqlIdentPaths {
		if ok, _ := afs.Exists(path); ok {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlPostgresqlIdent) mappings(file *mqlFile) ([]any, error) {
	if file == nil {
		return []any{}, nil
	}
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	mappings := postgresql.ParseIdent(content.Data)

	out := make([]any, 0, len(mappings))
	for _, m := range mappings {
		res, err := CreateResource(s.MqlRuntime, "postgresql.ident.mapping", map[string]*llx.RawData{
			"__id":           llx.StringData(file.Path.Data + ":" + strconv.Itoa(m.LineNumber)),
			"lineNumber":     llx.IntData(int64(m.LineNumber)),
			"mapName":        llx.StringData(m.MapName),
			"systemUsername": llx.StringData(m.SystemUsername),
			"pgUsername":     llx.StringData(m.PgUsername),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *mqlPostgresqlIdentMapping) id() (string, error) {
	return s.__id, nil
}

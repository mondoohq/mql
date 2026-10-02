// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/postgresql"
	"go.mondoo.com/mql/types"
)

// ---------------------------------------------------------------------------
// postgresql.conf
// ---------------------------------------------------------------------------

// postgresqlConfigSearchPaths returns the ordered list of well-known locations
// probed for one of PostgreSQL's config files (postgresql.conf, pg_hba.conf,
// pg_ident.conf) when no explicit `path` argument is given. The caller walks
// the list in order and stops at the first existing file.
//
// Distro packages stamp the major version into the directory name
// (/etc/postgresql/<MAJOR>/main on Debian/Ubuntu, /var/lib/pgsql/<MAJOR>/data
// on RHEL, /var/db/postgres/data<MAJOR> on FreeBSD), so those groups are
// resolved by glob. Enumerating the majors
// by hand goes stale the day a new one ships: the list previously stopped at
// 17 and therefore found nothing at all on a PostgreSQL 18 install. The
// remaining paths (container images, initdb defaults, homebrew) carry no
// version and stay listed literally.
func postgresqlConfigSearchPaths(fs afero.Fs, name string) []string {
	paths := versionedPostgresqlPaths(fs, "/etc/postgresql", "main", name)
	paths = append(paths,
		"/var/lib/postgresql/data/"+name,
		"/var/lib/pgsql/data/"+name,
	)
	paths = append(paths, versionedPostgresqlPaths(fs, "/var/lib/pgsql", "data", name)...)
	paths = append(paths, freebsdPostgresqlPaths(fs, name)...)
	return append(paths,
		"/usr/local/var/postgres/"+name,
		"/usr/local/pgsql/data/"+name,
	)
}

// versionedPostgresqlPaths expands <root>/*/<cluster>/<name> and returns the
// matches ordered by version, highest first, so a host running several
// clusters side by side resolves to the newest the way the old descending
// enumeration did. The sort is numeric: lexically "9" sorts above "17", and
// /etc/postgresql/9/main still exists on long-lived hosts.
//
// Before PostgreSQL 10 the major version had two parts, and packages named the
// directory after both (/etc/postgresql/9.5/main on Ubuntu 16.04,
// /var/lib/pgsql/9.6/data from the PGDG RPMs). A directory whose name is not a
// version (someone's /etc/postgresql/backup) is skipped rather than treated as
// major 0. A filesystem that cannot be globbed contributes no candidates,
// which is what the hardcoded list did when a path simply was not there.
func versionedPostgresqlPaths(fs afero.Fs, root, cluster, name string) []string {
	// <root>/<version>/<cluster>/<name>
	return postgresqlPathsByMajor(fs, root+"/*/"+cluster+"/"+name, func(match string) (int, bool) {
		return postgresqlVersionRank(path.Base(path.Dir(path.Dir(match))))
	})
}

// postgresqlVersionRank turns a version directory name ("18", "9.6") into a
// sortable rank, major*100+minor, so 9.6 ranks above 9.5 and below 10. It
// reports false for anything else.
func postgresqlVersionRank(dir string) (int, bool) {
	majorStr, minorStr, dotted := strings.Cut(dir, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil || major <= 0 {
		return 0, false
	}
	minor := 0
	if dotted {
		minor, err = strconv.Atoi(minorStr)
		if err != nil || minor < 0 || minor > 99 {
			return 0, false
		}
	}
	return major*100 + minor, true
}

// freebsdPostgresqlPaths expands the data directories the FreeBSD
// postgresql<MAJOR>-server packages create: the rc.d script initializes
// ~postgres/data<MAJOR> (/var/db/postgres/data17 for postgresql17-server on
// FreeBSD 14.5). Before PostgreSQL 10 the suffix carried major and minor
// (data96 for 9.6), which is ranked as 9.6.
func freebsdPostgresqlPaths(fs afero.Fs, name string) []string {
	return postgresqlPathsByMajor(fs, "/var/db/postgres/data*/"+name, func(match string) (int, bool) {
		suffix := strings.TrimPrefix(path.Base(path.Dir(match)), "data")
		major, err := strconv.Atoi(suffix)
		if err != nil || major <= 0 {
			return 0, false
		}
		if major >= 90 && major <= 99 {
			return (major/10)*100 + major%10, true
		}
		return major * 100, true
	})
}

// postgresqlPathsByMajor expands pattern and returns the matches ordered by the
// version rank majorOf reads from each, highest first. Matches majorOf
// rejects are dropped.
func postgresqlPathsByMajor(fs afero.Fs, pattern string, majorOf func(match string) (int, bool)) []string {
	if fs == nil {
		return nil
	}
	matches, err := afero.Glob(fs, pattern)
	if err != nil {
		return nil
	}

	type candidate struct {
		major int
		path  string
	}
	candidates := make([]candidate, 0, len(matches))
	for _, match := range matches {
		major, ok := majorOf(match)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate{major: major, path: match})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].major > candidates[j].major
	})

	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.path)
	}
	return out
}

// findPostgresqlConfigFile returns the first search path that exists, or "" if
// PostgreSQL keeps its config somewhere we do not know about (or is not
// installed at all).
func findPostgresqlConfigFile(fs afero.Fs, name string) string {
	afs := &afero.Afero{Fs: fs}
	for _, p := range postgresqlConfigSearchPaths(fs, name) {
		if ok, _ := afs.Exists(p); ok {
			return p
		}
	}
	return ""
}

// postgresqlFileReaders returns the reader and directory lister the parsers
// use to follow include directives. Every file is read through a file
// resource, recorded in files by path so callers can hand back the resources
// that contributed. A missing file or directory is reported as
// fs.ErrNotExist so include_if_exists and include_dir can skip it, while a
// refusal (a fragment only the postgres user may read) stays an error.
func postgresqlFileReaders(runtime *plugin.Runtime, files map[string]*mqlFile) (postgresql.FileReader, postgresql.DirLister) {
	conn := runtime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	reader := func(p string) (string, error) {
		f, ok := files[p]
		if !ok {
			raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
				"path": llx.StringData(p),
			})
			if err != nil {
				return "", err
			}
			f = raw.(*mqlFile)
		}
		exists := f.GetExists()
		if exists.Error != nil {
			return "", exists.Error
		}
		if !exists.Data {
			return "", fmt.Errorf("%s: %w", p, fs.ErrNotExist)
		}
		content := f.GetContent()
		if content.Error != nil {
			return "", content.Error
		}
		files[p] = f
		return content.Data, nil
	}

	lister := func(dir string) ([]string, error) {
		ok, err := afs.DirExists(dir)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s: %w", dir, fs.ErrNotExist)
		}
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

	return reader, lister
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

	if p := findPostgresqlConfigFile(conn.FileSystem(), "postgresql.conf"); p != "" {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		return f.(*mqlFile), nil
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

	filesIdx := map[string]*mqlFile{file.Path.Data: file}
	fileReader, dirLister := postgresqlFileReaders(s.MqlRuntime, filesIdx)

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

	// cfg.Files lists only the files that were read, in load order, so a
	// missing include_if_exists target is not reported as a config file.
	files := make([]any, 0, len(cfg.Files))
	for _, p := range cfg.Files {
		if f, ok := filesIdx[p]; ok {
			files = append(files, f)
		}
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

	return postgresql.LogConnectionsEnabled(paramString(params, "log_connections")), nil
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

	if p := findPostgresqlConfigFile(conn.FileSystem(), "pg_hba.conf"); p != "" {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		return f.(*mqlFile), nil
	}
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlPostgresqlHba) rules(file *mqlFile) ([]any, error) {
	if file == nil {
		// No pg_hba.conf anywhere: there are no rules to report, which is not
		// the same as a file that holds none. An empty list would let
		// `rules.none(authMethod == "trust")` pass on a host nothing was read
		// from.
		s.Rules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	files := map[string]*mqlFile{file.Path.Data: file}
	fileReader, dirLister := postgresqlFileReaders(s.MqlRuntime, files)
	rules, err := postgresql.ParseHbaFile(file.Path.Data, fileReader, dirLister)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(rules))
	for _, rule := range rules {
		opts := make(map[string]any, len(rule.Options))
		for k, v := range rule.Options {
			opts[k] = v
		}
		res, err := CreateResource(s.MqlRuntime, "postgresql.hba.rule", map[string]*llx.RawData{
			"__id":       llx.StringData(rule.File + ":" + strconv.Itoa(rule.LineNumber)),
			"file":       llx.ResourceData(files[rule.File], "file"),
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

	if p := findPostgresqlConfigFile(conn.FileSystem(), "pg_ident.conf"); p != "" {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		return f.(*mqlFile), nil
	}
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlPostgresqlIdent) mappings(file *mqlFile) ([]any, error) {
	if file == nil {
		s.Mappings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	files := map[string]*mqlFile{file.Path.Data: file}
	fileReader, dirLister := postgresqlFileReaders(s.MqlRuntime, files)
	mappings, err := postgresql.ParseIdentFile(file.Path.Data, fileReader, dirLister)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(mappings))
	for _, m := range mappings {
		res, err := CreateResource(s.MqlRuntime, "postgresql.ident.mapping", map[string]*llx.RawData{
			"__id":           llx.StringData(m.File + ":" + strconv.Itoa(m.LineNumber)),
			"file":           llx.ResourceData(files[m.File], "file"),
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

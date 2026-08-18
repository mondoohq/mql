// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/mycnf"
	"go.mondoo.com/mql/v13/types"
)

// mysqlConfPaths lists the paths a MySQL or Percona server reads its root
// option file from, in probe order. /etc/my.cnf and /etc/mysql/my.cnf are
// shared with MariaDB, which is why a match here is not enough on its own and
// every candidate goes through the flavor gate.
var mysqlConfPaths = []string{
	"/etc/my.cnf",
	"/etc/mysql/my.cnf",
	"/etc/mysql/mysql.cnf",
	"/usr/local/mysql/etc/my.cnf",
	"/usr/local/etc/my.cnf",
	"/opt/homebrew/etc/my.cnf",
}

// mariadbConfPaths lists the paths a MariaDB server reads its root option file
// from, in probe order.
var mariadbConfPaths = []string{
	"/etc/my.cnf",
	"/etc/mysql/my.cnf",
	"/etc/mysql/mariadb.cnf",
	"/usr/local/etc/my.cnf",
	"/opt/homebrew/etc/my.cnf",
}

// mycnfState is the shared parse state behind the mysql.conf and mariadb.conf
// resources. It is embedded into each resource's generated Internal struct so
// both share one code path for candidate selection, include expansion, and the
// flavor gate.
type mycnfState struct {
	lock sync.Mutex
	// resolved flips to true once resolve() has run to completion, whatever
	// the outcome. It is a dedicated flag rather than a check on one of the
	// resource's fields because the empty and error paths set extra state
	// bits that such a check fails to recognize as "already done", which
	// sends the resource into an endless re-parse.
	resolved bool
	// rootPath is the option file that was parsed, empty when the product
	// this resource covers is not installed on the target.
	rootPath string
	conf     *mycnf.Conf
	// filesIdx holds a file resource per path that contributed, so files()
	// and the section resources can hand out the same instances.
	filesIdx map[string]*mqlFile
	parseErr error
}

// resolve selects the option file for wantFlavor, parses it together with
// everything it includes, and caches the result.
//
// explicitPath short-circuits both the candidate probe and the flavor gate:
// when a caller names a file, they get that file parsed whichever product it
// belongs to. Otherwise each candidate that exists is parsed and offered to
// the flavor gate, and the first one belonging to wantFlavor wins.
func (st *mycnfState) resolve(runtime *plugin.Runtime, wantFlavor string, candidates []string, explicitPath string) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	if st.resolved {
		return st.parseErr
	}
	// Flip the guard before any early return so a transient empty or error
	// outcome cannot trigger an endless re-parse on the next field access.
	st.resolved = true
	st.conf = &mycnf.Conf{}
	st.filesIdx = map[string]*mqlFile{}

	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		st.parseErr = errors.New("mysql option files require a filesystem connection")
		return st.parseErr
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	reader := func(path string) (string, error) {
		f, ok := st.filesIdx[path]
		if !ok {
			raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return "", err
			}
			f = raw.(*mqlFile)
			st.filesIdx[path] = f
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
			// Directories are skipped: the server reads files out of a
			// fragment directory, and MariaDB parks a directory named
			// "99-enable-encryption.cnf.preset" inside one of them.
			if e.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
		return paths, nil
	}

	probe := func(path string) (bool, bool) {
		fi, err := afs.Stat(path)
		if err != nil {
			return false, false
		}
		return true, fi.IsDir()
	}

	if explicitPath != "" {
		conf, err := mycnf.Parse(explicitPath, reader, dirLister)
		if err != nil {
			st.parseErr = err
			return err
		}
		st.rootPath = explicitPath
		st.conf = conf
		return nil
	}

	for _, candidate := range candidates {
		if exists, isDir := probe(candidate); !exists || isDir {
			continue
		}
		// Every candidate is parsed before it can be judged. On RHEL-family
		// hosts the two products ship an indistinguishable root file holding
		// only a [client-server] header and an !includedir, so nothing short
		// of the expanded configuration identifies the product.
		conf, err := mycnf.Parse(candidate, reader, dirLister)
		if err != nil {
			continue
		}
		if mycnf.DetectFlavor(conf, probe) != wantFlavor {
			continue
		}
		st.rootPath = candidate
		st.conf = conf
		return nil
	}

	// Nothing on this host belongs to wantFlavor. Leave rootPath empty so
	// every dependent field reports empty rather than an error.
	return nil
}

// ensureFrom resolves using the path of an already-set file resource, which is
// how a resource initialized with an explicit path reaches the parser. When
// file is nil the auto-detect path has already run and found nothing.
func (st *mycnfState) ensureFrom(runtime *plugin.Runtime, wantFlavor string, candidates []string, file *mqlFile) error {
	explicit := ""
	if file != nil {
		explicit = file.Path.Data
	}
	return st.resolve(runtime, wantFlavor, candidates, explicit)
}

// rootFile returns the file resource for the parsed root option file, or nil
// when the product is not installed. Callers must mark their File field
// set-and-null on a nil return.
func (st *mycnfState) rootFile() *mqlFile {
	if st.rootPath == "" {
		return nil
	}
	return st.filesIdx[st.rootPath]
}

func (st *mycnfState) fileList() []any {
	out := make([]any, 0, len(st.conf.Files))
	for _, path := range st.conf.Files {
		if f, ok := st.filesIdx[path]; ok {
			out = append(out, f)
		}
	}
	return out
}

// optionMap merges the named groups into the shape the resource layer hands to
// MQL.
func (st *mycnfState) optionMap(groups ...string) map[string]any {
	merged := mycnf.Merge(st.conf, groups...)
	out := make(map[string]any, len(merged))
	for k, v := range merged {
		out[k] = v
	}
	return out
}

// sectionResources builds one resource per option group. resourceName selects
// between mysql.conf.section and mariadb.conf.section, which are field
// identical but kept apart so each product's docs stand alone.
func (st *mycnfState) sectionResources(runtime *plugin.Runtime, resourceName string) ([]any, error) {
	out := []any{}
	for _, section := range st.conf.Sections() {
		options := make(map[string]any)
		for k, v := range mycnf.Merge(st.conf, section.Name) {
			options[k] = v
		}

		files := make([]any, 0, len(section.Files))
		for _, path := range section.Files {
			if f, ok := st.filesIdx[path]; ok {
				files = append(files, f)
			}
		}

		res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
			"__id":         llx.StringData(st.rootPath + "/" + section.Name),
			"name":         llx.StringData(section.Name),
			"options":      llx.MapData(options, types.String),
			"flags":        llx.ArrayData(toAnySlice(mycnf.Flags(st.conf, section.Name)), types.String),
			"looseOptions": llx.ArrayData(toAnySlice(mycnf.LooseOptions(st.conf, section.Name)), types.String),
			"files":        llx.ArrayData(files, types.Resource("file")),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// per-user option files
// ---------------------------------------------------------------------------

// userOptionFileNames are the option files a client program reads out of a
// user's home directory. .mylogin.cnf is an obfuscated credential store rather
// than text, so it is reported but never decoded.
var userOptionFileNames = []string{".my.cnf", ".mylogin.cnf"}

// userOptionFiles enumerates the per-user option files across every account's
// home directory. resourceName selects the product's sub-resource.
func userOptionFiles(runtime *plugin.Runtime, resourceName string) ([]any, error) {
	raw, err := CreateResource(runtime, "users", nil)
	if err != nil {
		return nil, err
	}
	users := raw.(*mqlUsers)
	list := users.GetList()
	if list.Error != nil {
		return nil, list.Error
	}

	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return []any{}, nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	out := []any{}
	seen := map[string]bool{}
	for _, entry := range list.Data {
		user, ok := entry.(*mqlUser)
		if !ok {
			continue
		}
		home := user.GetHome()
		if home.Error != nil || home.Data == "" {
			continue
		}
		for _, name := range userOptionFileNames {
			path := filepath.Join(home.Data, name)
			// Several accounts commonly share one home directory (root and
			// a system account pointing at /), so dedupe on the path.
			if seen[path] {
				continue
			}
			if exists, err := afs.Exists(path); err != nil || !exists {
				continue
			}
			seen[path] = true

			format := "ini"
			if name == ".mylogin.cnf" {
				format = "mylogin"
			}
			f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
				"__id":   llx.StringData(path),
				"file":   llx.ResourceData(f, "file"),
				"owner":  llx.ResourceData(user, "user"),
				"format": llx.StringData(format),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// userOptionFileSections parses a per-user option file. An obfuscated
// .mylogin.cnf yields no sections: its contents are an encrypted credential
// store, and decoding it would copy the credentials it holds into scan results.
func userOptionFileSections(runtime *plugin.Runtime, resourceName, format string, file *mqlFile) ([]any, error) {
	if format != "ini" || file == nil {
		return []any{}, nil
	}
	content := file.GetContent()
	if content.Error != nil {
		return []any{}, nil
	}

	path := file.Path.Data
	conf, err := mycnf.Parse(path, func(p string) (string, error) {
		if p == path {
			return content.Data, nil
		}
		return "", errors.New("per-user option files are not followed beyond themselves")
	}, nil)
	if err != nil {
		return []any{}, nil
	}

	out := []any{}
	for _, section := range conf.Sections() {
		options := make(map[string]any)
		for k, v := range mycnf.Merge(conf, section.Name) {
			options[k] = v
		}
		res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
			"__id":         llx.StringData(path + "/" + section.Name),
			"name":         llx.StringData(section.Name),
			"options":      llx.MapData(options, types.String),
			"flags":        llx.ArrayData(toAnySlice(mycnf.Flags(conf, section.Name)), types.String),
			"looseOptions": llx.ArrayData(toAnySlice(mycnf.LooseOptions(conf, section.Name)), types.String),
			"files":        llx.ArrayData([]any{file}, types.Resource("file")),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// server version detection
// ---------------------------------------------------------------------------

// detectServerVersion reads the server version and product from the target by
// running the server binary with --version. Returns empty strings when no
// server binary could be run.
//
// Unlike Apache and nginx, neither product can be identified by scanning the
// server binary for an embedded banner. They render the banner at runtime from
// a printf format string ("Ver %s for %s on %s (%s)"), holding the version in a
// separate string constant, so the binary never contains the assembled text.
// Verified against Oracle MySQL 8.0, MariaDB 11.8, and Percona Server 8.0: the
// only "Ver " occurrences in each are format strings. Version detection
// therefore needs command execution, and reports nothing over a transport that
// cannot run commands. The option files this file's other resources read are
// unaffected, since those come off the filesystem.
func detectServerVersion(runtime *plugin.Runtime) (version string, flavor string) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return "", ""
	}

	for _, cmd := range []string{"mariadbd --version", "mysqld --version"} {
		res, err := conn.RunCommand(cmd)
		if err != nil || res.ExitStatus != 0 {
			continue
		}
		data, err := io.ReadAll(res.Stdout)
		if err != nil {
			continue
		}
		if v, f := mycnf.ParseVersion(string(data)); v != "" {
			return v, f
		}
	}

	return "", ""
}

// ---------------------------------------------------------------------------
// option accessors
// ---------------------------------------------------------------------------

func optionString(options map[string]any, key string) string {
	v, ok := options[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// optionBool resolves an option to a boolean. Bare options already carry "ON"
// through Merge, so the merged map is the only source needed here.
func optionBool(options map[string]any, key string) bool {
	return mycnf.IsTruthy(optionString(options, key), false)
}

// optionInt resolves an option to an integer, returning fallback when the
// option is unset or is not a plain number. MySQL accepts unit suffixes on
// size options (128M), which is why a failed parse falls back rather than
// erroring: the affected options here are counts and intervals, where a
// suffixed value would be a misconfiguration rather than something to report.
func optionInt(options map[string]any, key string, fallback int64) int64 {
	raw := strings.TrimSpace(optionString(options, key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

// optionCount resolves an option that counts something, reporting whether the
// option files set it at all. An absent count is not a zero: max_connections=0
// is not a configuration a server can run with, and a field that reports one
// lets a bounds check pass on a server whose real limit is higher. The caller
// marks the field null in that case, so "the files do not say" stays distinct
// from "the files say zero".
//
// A value that does not parse is treated as absent for the same reason. These
// options are counts and intervals, where a suffixed or malformed value is a
// misconfiguration rather than a number to report.
func optionCount(options map[string]any, key string) (int64, bool) {
	raw := strings.TrimSpace(optionString(options, key))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func optionList(options map[string]any, key string) []any {
	return toAnySlice(mycnf.SplitList(optionString(options, key)))
}

// bindAddressList resolves bind_address. The server listens on every
// interface when the option is unset, which "*" denotes, so an empty result
// would misreport an unrestricted listener as no listener at all.
func bindAddressList(options map[string]any) []any {
	if strings.TrimSpace(optionString(options, "bind_address")) == "" {
		return []any{"*"}
	}
	return optionList(options, "bind_address")
}

// pluginLoadList resolves the plugins named across plugin_load and
// plugin_load_add. Both contribute, and plugin_load_add has already
// accumulated every occurrence through Merge.
func pluginLoadList(options map[string]any) []any {
	var names []string
	for _, key := range []string{"plugin_load", "plugin_load_add"} {
		for _, entry := range mycnf.SplitList(optionString(options, key)) {
			// Entries may be written as "name=library.so"; the plugin name
			// is what identifies it.
			name, _, _ := strings.Cut(entry, "=")
			name = strings.TrimSpace(name)
			if name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return toAnySlice(names)
}

// resolveRunAsUser turns the user option into the account the server drops
// privileges to.
//
// A miss is reported as null rather than as an error: an option file may name
// an account that does not exist on the host, and the user resource's own
// lookup fails hard in that case. The distinction the caller needs is between
// "no user option" and "a user option naming this account", and neither is
// served by failing the whole query.
func resolveRunAsUser(runtime *plugin.Runtime, options map[string]any) (*mqlUser, bool) {
	name := strings.TrimSpace(optionString(options, "user"))
	if name == "" {
		return nil, false
	}
	raw, err := NewResource(runtime, "user", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, false
	}
	user, ok := raw.(*mqlUser)
	if !ok {
		return nil, false
	}
	return user, true
}

// toAnySlice is defined in sudoers.go and shared across this package.

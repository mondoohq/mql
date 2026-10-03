// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/providers/os/resources/mycnf"
	"go.mondoo.com/mql/providers/os/resources/systemd"
	"go.mondoo.com/mql/types"
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
	// FreeBSD ports (mysql80, mysql84) install my.cnf.sample here. mysqld
	// 8.4 on FreeBSD 14 reads /usr/local/etc/my.cnf first, then this file.
	"/usr/local/etc/mysql/my.cnf",
	"/opt/homebrew/etc/my.cnf",
}

// mariadbConfPaths lists the paths a MariaDB server reads its root option file
// from, in probe order.
var mariadbConfPaths = []string{
	"/etc/my.cnf",
	"/etc/mysql/my.cnf",
	"/etc/mysql/mariadb.cnf",
	"/usr/local/etc/my.cnf",
	// FreeBSD ports (mariadb1011 through mariadb123) ship my.cnf.sample
	// here, including /usr/local/etc/mysql/conf.d.
	"/usr/local/etc/mysql/my.cnf",
	"/opt/homebrew/etc/my.cnf",
}

// debianAlternativeTargets maps the root option files Debian and Ubuntu install
// as targets of the my.cnf alternative to the link the server opens. No server
// reads these files under their own name: mysqld opens /etc/mysql/my.cnf, and
// update-alternatives decides which of them that reaches. Installing
// libmariadb3 next to Oracle MySQL, for example, points the link at
// mariadb.cnf (mariadb-common registers it at a higher priority than
// mysql-common's mysql.cnf), and mysqld then never reads mysql.conf.d.
var debianAlternativeTargets = map[string]string{
	"/etc/mysql/mysql.cnf":   "/etc/mysql/my.cnf",
	"/etc/mysql/mariadb.cnf": "/etc/mysql/my.cnf",
}

// readableCandidates drops the alternative targets whose link exists. While
// /etc/mysql/my.cnf exists the server reads whatever it reaches and nothing
// else, so falling through to mysql.cnf or mariadb.cnf after the link was
// judged to belong to the other product reports options the server ignores.
// A target is kept only when its link is missing, for example in an image
// whose /etc/alternatives link does not resolve.
func readableCandidates(candidates []string, exists func(path string) bool) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if link, ok := debianAlternativeTargets[c]; ok && exists(link) {
			continue
		}
		out = append(out, c)
	}
	return out
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
	// launch is how the server is started, when a running server process
	// or its systemd unit says. Its command line options override the
	// option files. The zero value, with an empty Binary, means no server
	// command line was found, and contributes nothing.
	launch mycnf.ServerLaunch
	// groups are the option groups the server binary says it reads, empty
	// when it could not be asked and the static per-product list applies.
	groups []string
	// persisted are the options a MySQL server applies from
	// <datadir>/mysqld-auto.cnf (SET PERSIST), after its command line.
	persisted []mycnf.Option
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

	if err := st.locate(runtime, afs, wantFlavor, candidates, explicitPath); err != nil {
		return err
	}
	if explicitPath == "" && st.rootPath != "" && wantFlavor == mycnf.FlavorMySQL {
		return st.loadPersisted(runtime, afs)
	}
	return nil
}

// locate is resolve's search for the option files, run under its lock.
func (st *mycnfState) locate(runtime *plugin.Runtime, afs *afero.Afero, wantFlavor string, candidates []string, explicitPath string) error {

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
			st.parseErr = classifyOptionFileError(err)
			return st.parseErr
		}
		st.rootPath = explicitPath
		st.conf = conf
		return nil
	}

	// How the server is started decides which option files it reads, ahead
	// of every well-known path.
	launch, launched := mysqlServerLaunch(runtime, afs, wantFlavor)
	if launched {
		st.launch = launch
		if launch.NoDefaults {
			// The server reads no option file at all. rootPath stays
			// empty, and only the command line contributes.
			return nil
		}
		// A defaults file that does not exist stops the server from
		// starting, so it says nothing about the server and the probe
		// below goes on. One this user cannot stat is still the file,
		// and parsing it reports the refusal.
		if p := launchPath(launch.DefaultsFile); p != "" {
			if _, err := afs.Stat(p); !errors.Is(err, fs.ErrNotExist) {
				conf, err := mycnf.Parse(p, reader, dirLister)
				st.rootPath = p
				st.conf = conf
				if err != nil {
					st.parseErr = classifyOptionFileError(err)
					return st.parseErr
				}
				return st.appendExtraFile(reader, dirLister)
			}
		}
	}

	// Without option file arguments the server reads every default option
	// file it names, in its order, and the groups it names.
	if done, err := st.readServerDefaults(runtime, afs, wantFlavor, reader, dirLister, probe); done {
		return err
	}

	isFile := func(path string) bool {
		exists, isDir := probe(path)
		return exists && !isDir
	}
	for _, candidate := range readableCandidates(candidates, isFile) {
		if !isFile(candidate) {
			continue
		}
		// Every candidate is parsed before it can be judged. On RHEL-family
		// hosts the two products ship an indistinguishable root file holding
		// only a [client-server] header and an !includedir, so nothing short
		// of the expanded configuration identifies the product.
		conf, err := mycnf.Parse(candidate, reader, dirLister)
		if err != nil && len(conf.Files) == 0 {
			// The root file itself could not be read, so there is nothing
			// to tell which product it belongs to.
			continue
		}
		banner := func() string { return installedServerFlavor(runtime) }
		if mycnf.DetectFlavor(conf, probe, banner) != wantFlavor {
			continue
		}
		st.rootPath = candidate
		st.conf = conf
		if err != nil {
			// The configuration belongs to this product but an included
			// fragment could not be read. The server reads that fragment,
			// so every value derived from the rest would be reported with
			// confidence it does not have.
			st.parseErr = classifyOptionFileError(err)
			return st.parseErr
		}
		return st.appendExtraFile(reader, dirLister)
	}

	// Nothing on this host belongs to wantFlavor. Leave rootPath empty so
	// every dependent field reports empty rather than an error.
	return nil
}

// readServerDefaults reads the default option files the installed server
// binary lists (`mysqld --verbose --help`), every one of them in its order,
// the way the server merges them: /etc/my.cnf, /etc/mysql/my.cnf, on Oracle
// and Percona builds /usr/etc/my.cnf, and the server account's ~/.my.cnf.
// It also keeps the groups the binary lists for serverOptions.
//
// It reports false when it decided nothing and the probe of well-known paths
// goes on: the binary could not be asked, it is the other product's, or,
// without structured errors, one of the global files was refused, which v13
// handled through the probe. A refused ~/.my.cnf is skipped then, as v13 never
// read it.
func (st *mycnfState) readServerDefaults(runtime *plugin.Runtime, afs *afero.Afero, wantFlavor string, reader mycnf.FileReader, dirLister mycnf.DirLister, probe mycnf.FileProbe) (bool, error) {
	raw, err := CreateResource(runtime, "mysql", nil)
	if err != nil {
		return false, nil
	}
	m, ok := raw.(*mqlMysql)
	if !ok {
		return false, nil
	}
	defaults, ok := m.serverDefaults()
	if !ok || productOf(m.bannerFlavor) != wantFlavor {
		return false, nil
	}

	home := serverHome(afs)
	conf := &mycnf.Conf{}
	root := ""
	var partial error
	for _, p := range defaults.Files {
		optional := false
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			if home == "" {
				continue
			}
			p = path.Join(home, rest)
			optional = true
		}
		_, err := afs.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		var c *mycnf.Conf
		if err == nil {
			c, err = mycnf.Parse(p, reader, dirLister)
		}
		if err != nil && (c == nil || len(c.Files) == 0) {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if errors.Is(err, fs.ErrPermission) && !plugin.StructuredErrors() {
				if optional {
					continue
				}
				return false, nil
			}
			st.parseErr = classifyOptionFileError(err)
			return true, st.parseErr
		}
		if root == "" {
			root = p
		}
		conf.Append(c)
		if err != nil && partial == nil {
			partial = err
		}
	}
	if root == "" {
		// No option file at all: the server runs on its built-in
		// defaults, and this resource reports no file.
		return true, nil
	}
	banner := func() string { return installedServerFlavor(runtime) }
	if mycnf.DetectFlavor(conf, probe, banner) != wantFlavor {
		return true, nil
	}
	st.rootPath = root
	st.conf = conf
	st.groups = defaults.Groups
	if partial != nil {
		st.parseErr = classifyOptionFileError(partial)
		return true, st.parseErr
	}
	return true, st.appendExtraFile(reader, dirLister)
}

// productOf maps a banner flavor to the product a conf resource covers.
func productOf(flavor string) string {
	if flavor == mycnf.FlavorPercona {
		return mycnf.FlavorMySQL
	}
	return flavor
}

// serverHome returns the home directory of the account the server's systemd
// unit runs it as, which is the HOME the server expands ~/.my.cnf with. A unit
// without User= runs the server as root. It is empty when no unit is found.
func serverHome(afs *afero.Afero) string {
	for _, unit := range mysqlServerUnits {
		env, ok := serverUnitEnv(afs, unit)
		if !ok {
			continue
		}
		user := env.User
		if user == "" {
			user = "root"
		}
		return passwdHome(afs, user)
	}
	return ""
}

// passwdHome returns an account's home directory from /etc/passwd.
func passwdHome(afs *afero.Afero, user string) string {
	data, err := afs.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[0] == user {
			return fields[5]
		}
	}
	return ""
}

// loadPersisted reads <datadir>/mysqld-auto.cnf, where a MySQL 8.0 or later
// server keeps what SET PERSIST and SET PERSIST_ONLY wrote, and applies it at
// startup after its option files and command line unless
// persisted_globals_load is off. A missing file persists nothing. A refused
// one is reported with structured errors and skipped without them, as v13
// never read it; Debian keeps the data directory at 0750.
func (st *mycnfState) loadPersisted(runtime *plugin.Runtime, afs *afero.Afero) error {
	version := installedServerVersion(runtime, "mysql")
	if major, err := strconv.Atoi(strings.SplitN(version, ".", 2)[0]); err != nil || major < 8 {
		// SET PERSIST arrived in 8.0.
		return nil
	}
	merged := mycnf.MergeWithArgs(st.conf, st.launch.Options, st.effectiveGroups(mycnf.ServerGroups(mycnf.FlavorMySQL, version))...)
	if v, ok := merged["persisted_globals_load"]; ok && !mycnf.IsTruthy(v, false) {
		return nil
	}
	datadir := strings.TrimSpace(merged["datadir"])
	if datadir == "" {
		datadir = "/var/lib/mysql"
	}
	p := path.Join(datadir, "mysqld-auto.cnf")
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
	if err != nil {
		return nil
	}
	f := raw.(*mqlFile)
	if exists := f.GetExists(); exists.Error == nil && !exists.Data {
		return nil
	}
	content := f.GetContent()
	if content.Error != nil {
		if errors.Is(content.Error, fs.ErrNotExist) {
			return nil
		}
		if errors.Is(content.Error, fs.ErrPermission) && !plugin.StructuredErrors() {
			return nil
		}
		st.parseErr = classifyOptionFileError(content.Error)
		return st.parseErr
	}
	if strings.TrimSpace(content.Data) == "" {
		return nil
	}
	opts, err := mycnf.ParsePersisted(content.Data)
	if err != nil {
		st.parseErr = llx.MalformedData(err)
		return st.parseErr
	}
	st.persisted = opts
	st.filesIdx[p] = f
	st.conf.Files = append(st.conf.Files, p)
	return nil
}

// effectiveGroups returns the groups the server binary listed, or else the
// static list, extended by the server's --defaults-group-suffix.
func (st *mycnfState) effectiveGroups(static []string) []string {
	groups := static
	if len(st.groups) > 0 {
		groups = st.groups
	}
	return mycnf.WithGroupSuffix(groups, st.launch.GroupSuffix)
}

// appendExtraFile reads the server's --defaults-extra-file after the option
// files already parsed, which is the order the server reads them in. A file
// that does not exist stops the server from starting and is skipped.
func (st *mycnfState) appendExtraFile(reader mycnf.FileReader, dirLister mycnf.DirLister) error {
	p := launchPath(st.launch.ExtraFile)
	if p == "" {
		return nil
	}
	extra, err := mycnf.Parse(p, reader, dirLister)
	if err != nil && len(extra.Files) == 0 && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	st.conf.Append(extra)
	if err != nil {
		st.parseErr = classifyOptionFileError(err)
		return st.parseErr
	}
	return nil
}

// launchPath resolves a path from a server command line. A relative path is
// resolved against the root directory, where systemd starts a service that
// sets no WorkingDirectory=.
func launchPath(p string) string {
	if p == "" || path.IsAbs(p) {
		return p
	}
	return path.Join("/", p)
}

// mysqlServerUnits are the systemd services that start a MySQL or MariaDB
// server: mariadb.service from MariaDB's packages, mysql.service from MySQL's
// Debian packages, and mysqld.service from its RPMs. MariaDB's packages
// install mysql.service and mysqld.service as symlinks to mariadb.service,
// and systemd reads the drop-ins of the unit's own name, so mariadb.service
// is resolved first: through an alias the drop-ins in mariadb.service.d would
// be missed.
var mysqlServerUnits = []string{"mariadb.service", "mysql.service", "mysqld.service"}

// mysqlServerPidsCmd lists the server processes. pgrep exits 1 when nothing
// matches.
const mysqlServerPidsCmd = "pgrep -x 'mysqld|mariadbd'"

// mysqlServerLaunch returns the command line the wantFlavor server is started
// with: a running server's own, read from /proc, or else the ExecStart= of
// its systemd unit with the unit's environment expanded. It reports false
// when neither names a server of this product.
func mysqlServerLaunch(runtime *plugin.Runtime, afs *afero.Afero, wantFlavor string) (mycnf.ServerLaunch, bool) {
	for _, argv := range runningServerArgs(runtime, afs) {
		if launch, ok := mycnf.ParseServerArgs(argv); ok && launchFlavorMatches(runtime, launch, wantFlavor) {
			return launch, true
		}
	}
	for _, unit := range mysqlServerUnits {
		if launch, ok := unitLaunch(afs, unit); ok && launchFlavorMatches(runtime, launch, wantFlavor) {
			return launch, true
		}
	}
	return mycnf.ServerLaunch{}, false
}

// serverUnitEnv resolves a server unit that starts something. A unit with no
// ExecStart= does not: that is also what an alias left dangling looks like,
// such as /etc/systemd/system/mysql.service pointing at the mariadb.service a
// removed package took with it, which systemd refuses to load. Where a
// filesystem reports such a link as present it cannot read it, so the unit
// resolves with no settings at all, and its missing User= would read as root.
func serverUnitEnv(afs *afero.Afero, unit string) (*systemd.UnitEnv, bool) {
	env, ok := systemd.ResolveUnitEnv(afs, unit)
	if !ok || env.ExecStart == "" {
		return nil, false
	}
	return env, true
}

// unitLaunch returns the server command line a systemd unit starts: its
// ExecStart= with the unit's environment expanded, or, for SUSE's units, the
// one mysql-systemd-helper execs.
func unitLaunch(afs *afero.Afero, unit string) (mycnf.ServerLaunch, bool) {
	env, ok := serverUnitEnv(afs, unit)
	if !ok {
		return mycnf.ServerLaunch{}, false
	}
	argv := haproxy.ExpandSystemdCommand(env.ExecStart, env.Vars)
	if launch, ok := mycnf.ParseServerArgs(argv); ok {
		return launch, true
	}
	return mycnf.ParseSuseHelperArgs(argv)
}

// launchFlavorMatches reports whether a server command line starts the
// product wantFlavor covers. A binary named mariadbd is MariaDB. One named
// mysqld is whatever the installed server's banner says, since MariaDB
// before 10.4 installs its server under that name only; when no banner can
// be read it is taken to be the product asked about, as a host runs one of
// the two.
func launchFlavorMatches(runtime *plugin.Runtime, launch mycnf.ServerLaunch, wantFlavor string) bool {
	if launch.Binary == "mariadbd" {
		return wantFlavor == mycnf.FlavorMariaDB
	}
	switch installedServerFlavor(runtime) {
	case mycnf.FlavorMariaDB:
		return wantFlavor == mycnf.FlavorMariaDB
	case mycnf.FlavorMySQL, mycnf.FlavorPercona:
		return wantFlavor == mycnf.FlavorMySQL
	}
	return true
}

// runningServerArgs reads the command line of every running server process
// from /proc. Where commands run, pgrep narrows the processes to read;
// otherwise every /proc entry is read. A process whose command line cannot be
// read is skipped: it may be gone by now.
func runningServerArgs(runtime *plugin.Runtime, afs *afero.Afero) [][]string {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	var pids []string
	listed := false
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
			"command": llx.StringData(mysqlServerPidsCmd),
		})
		if err == nil {
			cmd := o.(*mqlCommand)
			switch cmd.GetExitcode().Data {
			case 0:
				pids = strings.Fields(cmd.GetStdout().Data)
				listed = true
			case 1:
				return nil
			}
		}
	}
	if !listed {
		entries, err := afs.ReadDir("/proc")
		if err != nil {
			return nil
		}
		for _, e := range entries {
			pids = append(pids, e.Name())
		}
	}

	var out [][]string
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := afs.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		argv := haproxy.SplitProcCmdline(raw)
		if len(argv) > 0 && mycnf.IsServerBinary(argv[0]) {
			out = append(out, argv)
		}
	}
	return out
}

// serverOptionMap merges the server's option groups (the binary's list, or
// else groups), extended by its --defaults-group-suffix, then applies its
// command line options and, last, its persisted options.
func (st *mycnfState) serverOptionMap(groups []string) map[string]any {
	// The server applies its persisted options after its command line.
	args := append(slices.Clone(st.launch.Options), st.persisted...)
	merged := mycnf.MergeWithArgs(st.conf, args, st.effectiveGroups(groups)...)
	out := make(map[string]any, len(merged))
	for k, v := range merged {
		out[k] = v
	}
	return out
}

// classifyOptionFileError marks a failure to read an option file because of
// its permissions as a refusal, which is the common case for a scan that does
// not run as root against a fragment the server's own account can read.
func classifyOptionFileError(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return llx.Forbidden(err)
	}
	return err
}

// installedServerVersion returns the version of the server the named resource
// ("mysql" or "mariadb") reports, or the empty string when it reports none.
// Going through the resource shares its cached version detection.
func installedServerVersion(runtime *plugin.Runtime, resourceName string) string {
	raw, err := CreateResource(runtime, resourceName, nil)
	if err != nil {
		return ""
	}
	switch r := raw.(type) {
	case *mqlMysql:
		if v := r.GetVersion(); v.Error == nil {
			return v.Data
		}
	case *mqlMariadb:
		if v := r.GetVersion(); v.Error == nil {
			return v.Data
		}
	}
	return ""
}

// installedServerFlavor returns the product the installed server binary names
// in its --version banner, MariaDB included, or the empty string when no server
// binary could be run. It shares the mysql resource's cached detection, so the
// binary is run once per scan however many resources ask.
func installedServerFlavor(runtime *plugin.Runtime) string {
	raw, err := CreateResource(runtime, "mysql", nil)
	if err != nil {
		return ""
	}
	m, ok := raw.(*mqlMysql)
	if !ok {
		return ""
	}
	m.detect()
	return m.bannerFlavor
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
	// The reader serves only the file itself, so the parse cannot fail on the
	// root. The error it reports names the includes that were deliberately
	// not followed, and the file's own sections stand without them.
	conf, _ := mycnf.Parse(path, func(p string) (string, error) {
		if p == path {
			return content.Data, nil
		}
		return "", errors.New("per-user option files are not followed beyond themselves")
	}, nil)

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
//
// Several packagings install the server outside PATH (/usr/libexec on RHEL,
// /usr/local/libexec on FreeBSD), so after the bare names fail the known
// install paths that exist on the target are run directly.
func detectServerVersion(runtime *plugin.Runtime) (version string, flavor string) {
	version, flavor, _ = detectServer(runtime)
	return version, flavor
}

// detectServer is detectServerVersion that also returns the binary that
// answered.
func detectServer(runtime *plugin.Runtime) (version string, flavor string, bin string) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return "", "", ""
	}

	bins := []string{"mariadbd", "mysqld"}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, path := range mycnf.ServerBinaries() {
		if ok, err := afs.Exists(path); err == nil && ok {
			bins = append(bins, path)
		}
	}

	for _, bin := range bins {
		res, err := conn.RunCommand(bin + " --version")
		if err != nil || res.ExitStatus != 0 {
			continue
		}
		data, err := io.ReadAll(res.Stdout)
		if err != nil {
			continue
		}
		if v, f := mycnf.ParseVersion(string(data)); v != "" {
			return v, f, bin
		}
	}

	return "", "", ""
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
//
// An unset option reads false. That is only correct for options that default
// to off in every supported server version; use optionBoolIfSet for the rest.
func optionBool(options map[string]any, key string) bool {
	return mycnf.IsTruthy(optionString(options, key), false)
}

// optionBoolIfSet resolves an option to a boolean and reports whether any
// option file sets it. It is for options whose server default is on in at
// least one supported version (local_infile, symbolic_links,
// automatic_sp_privileges), where reading an unset option as false would
// report the feature disabled on a server that runs with it enabled. The
// caller marks the field null when the option is unset.
func optionBoolIfSet(options map[string]any, key string) (bool, bool) {
	v, ok := options[key]
	if !ok {
		return false, false
	}
	s, _ := v.(string)
	return mycnf.IsTruthy(s, false), true
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

// optionPathList resolves an option whose value is a list of directories.
// These use ":" (Unix) or ";" (Windows) rather than the comma/space form.
func optionPathList(options map[string]any, key string) []any {
	return toAnySlice(mycnf.SplitPathList(optionString(options, key)))
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

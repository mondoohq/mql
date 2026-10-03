// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	"go.mondoo.com/mql/providers/os/resources/serverlaunch"
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
// (/etc/postgresql/<MAJOR>/<CLUSTER> on Debian/Ubuntu, /var/lib/pgsql/<MAJOR>/data
// on RHEL, /var/db/postgres/data<MAJOR> on FreeBSD), so those groups are
// resolved by glob. Enumerating the majors
// by hand goes stale the day a new one ships: the list previously stopped at
// 17 and therefore found nothing at all on a PostgreSQL 18 install. The
// remaining paths (container images, initdb defaults, homebrew) carry no
// version and stay listed literally.
func postgresqlConfigSearchPaths(fs afero.Fs, name string) []string {
	paths := versionedPostgresqlPaths(fs, "/etc/postgresql", "main", name)
	paths = append(paths, otherDebianClusterPaths(fs, name)...)
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

// otherDebianClusterPaths expands /etc/postgresql/<version>/<cluster>/<name>
// for every cluster not named "main". Debian names a cluster when it is
// created (pg_createcluster 15 prod) and pg_renamecluster renames it, so a
// host may have no "main" at all. These come after every "main" cluster,
// which keeps the file a host with a main cluster resolved to before, and
// are ordered by version, highest first, then by cluster name. A running
// postmaster's config_file, probed before all of these, names the cluster
// the server actually loads.
func otherDebianClusterPaths(fs afero.Fs, name string) []string {
	all := versionedPostgresqlPaths(fs, "/etc/postgresql", "*", name)
	out := make([]string, 0, len(all))
	for _, p := range all {
		if path.Base(path.Dir(p)) != "main" {
			out = append(out, p)
		}
	}
	return out
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
	// Glob returns matches in lexical order; a stable sort keeps that order
	// among matches of the same version (Debian clusters of one major).
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].major > candidates[j].major
	})

	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.path)
	}
	return out
}

// findPostgresqlConfigFile returns the first candidate that exists, or "" if
// PostgreSQL keeps its config somewhere we do not know about (or is not
// installed at all). The preferred paths, which come from what the host says
// about its clusters (postgresqlInstances), are probed before the well-known
// search paths.
//
// A candidate that cannot be checked because a parent directory refuses the
// scanning user (RHEL's /var/lib/pgsql is 0700 postgres) is an error: the
// file may well be there, and reading the host as one without PostgreSQL
// would make every postgresql.* check pass or skip. v13 skipped such a
// candidate, and keeps doing so until structured errors are the default.
func findPostgresqlConfigFile(fs afero.Fs, name string, preferred ...string) (string, error) {
	afs := &afero.Afero{Fs: fs}
	candidates := append(append([]string{}, preferred...), postgresqlConfigSearchPaths(fs, name)...)
	seen := make(map[string]bool, len(candidates))
	for _, p := range candidates {
		if seen[p] {
			continue
		}
		seen[p] = true
		ok, err := afs.Exists(p)
		if err != nil {
			if errors.Is(err, os.ErrPermission) && plugin.StructuredErrors() {
				return "", llx.Forbidden(err)
			}
			continue
		}
		if ok {
			return p, nil
		}
	}
	return "", nil
}

// postgresqlInstances returns the clusters the host runs or is set up to
// start: running postmasters first, then systemd units. Either source may be
// unavailable (a container image has no processes, a host without systemd
// has no units) and then contributes nothing.
func postgresqlInstances(runtime *plugin.Runtime) (running, units []postgresql.Instance) {
	running = runningPostmasters(runtime)
	if len(running) == 0 {
		running = imagePostmasters(runtime)
	}
	return running, postgresqlUnits(runtime)
}

// postgresqlLaunch recognizes the postmaster in a container image's
// configuration (docker-entrypoint.sh postgres -c ...).
var postgresqlLaunch = serverLaunchSpec{Names: []string{"postgres", "postmaster"}, Env: true}

// imagePostmasters returns the postmaster a scanned container image starts,
// with the data directory from its PGDATA, or nil when the connection is
// not an image or the image starts something else.
func imagePostmasters(runtime *plugin.Runtime) []postgresql.Instance {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil
	}
	l := imageServerLaunch(conn, postgresqlLaunch)
	if l == nil {
		return nil
	}
	inst, ok := postgresql.ParsePostmasterArgs(l.Argv)
	if !ok {
		return nil
	}
	inst.ApplyEnv(l.Env)
	return []postgresql.Instance{inst}
}

// postgresqlPidsCmd lists the processes named postgres or postmaster: the
// postmaster and its backends, whose comm stays "postgres". pgrep exits 1
// when nothing matches.
const postgresqlPidsCmd = "pgrep -x 'postgres|postmaster'"

// runningPostmasters reads the command line of every running postmaster from
// /proc. Where commands run, pgrep narrows the processes to read; otherwise
// every /proc entry is read. A process whose command line cannot be read is
// skipped: it may be gone by now, and postmasters do not hide their command
// line.
func runningPostmasters(runtime *plugin.Runtime) []postgresql.Instance {
	conn := runtime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	var pids []string
	listed := false
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
			"command": llx.StringData(postgresqlPidsCmd),
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

	var out []postgresql.Instance
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := afs.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		inst, ok := postgresql.ParsePostmasterArgs(argv)
		if !ok {
			continue
		}
		inst.Pid, _ = strconv.Atoi(pid)
		// Without -D or config_file the data directory is PGDATA. The
		// environment is readable by the server's own account and root
		// with ptrace rights; otherwise postmaster.pid ties the process
		// to its data directory (see instanceFor).
		if inst.ConfigFile() == "" {
			if env, err := afs.ReadFile("/proc/" + pid + "/environ"); err == nil {
				inst.ApplyEnv(serverlaunch.ParseEnviron(env))
			}
		}
		out = append(out, inst)
	}
	return out
}

// postgresqlUnitsCmd shows the environment, environment files and ExecStart
// of every installed postgresql unit. The names come from the unit files: a
// unit pattern given to systemctl show only matches loaded units, and systemd
// unloads a stopped unit nothing depends on (PGDG's postgresql-17.service
// once stopped). Templates (Debian's postgresql@.service) carry no data
// directory and are skipped. Without any unit, xargs -r shows nothing rather
// than the manager's own properties. The command is a plain pipeline, not a
// shell assignment, so it still runs when an SSH scan with --sudo prefixes it
// with sudo.
const postgresqlUnitsCmd = `systemctl list-unit-files --no-legend 'postgresql*.service' 2>/dev/null | awk '$1 !~ /@\.service$/ {print $1}' | xargs -r systemctl show -p Id -p Environment -p EnvironmentFiles -p ExecStart`

// postgresqlUnits returns the clusters the postgresql systemd units start.
// A host without systemctl, or one where it fails, has no units to report.
func postgresqlUnits(runtime *plugin.Runtime) []postgresql.Instance {
	conn := runtime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil
	}
	out, ok, err := runShellCmd(runtime, postgresqlUnitsCmd)
	if err != nil || !ok {
		return nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	var insts []postgresql.Instance
	for _, u := range postgresql.ParseSystemctlShow(out) {
		// An environment file that cannot be read is skipped, as systemd
		// skips a missing optional one (and refuses to start the unit
		// otherwise, so its content never applied).
		for _, f := range u.EnvironmentFiles {
			if data, err := afs.ReadFile(f); err == nil {
				u.ApplyEnvironmentFile(string(data))
			}
		}
		if u.IsSuseStartScript() {
			u.Homes = postgresqlHomes(afs)
		}
		if inst, ok := postgresql.UnitInstance(u); ok {
			insts = append(insts, inst)
		}
	}
	return insts
}

// postgresqlHomes returns the home directory of the postgres account from
// /etc/passwd, which SUSE's sysconfig names as ~postgres.
func postgresqlHomes(afs *afero.Afero) map[string]string {
	data, err := afs.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[0] == "postgres" && fields[5] != "" {
			return map[string]string{"postgres": fields[5]}
		}
	}
	return nil
}

// postgresqlPreferredConfigs orders the config files of the given clusters
// for findPostgresqlConfigFile: running postmasters first, then the clusters
// of systemd units. Within each group, files at well-known paths keep the
// order the search paths give them, so a host running several Debian
// clusters, or with both the distro and the PGDG unit installed, still
// resolves to the one it always did. Files elsewhere (a relocated data
// directory) follow in discovery order.
func postgresqlPreferredConfigs(fs afero.Fs, running, units []postgresql.Instance) []string {
	rank := map[string]int{}
	for i, p := range postgresqlConfigSearchPaths(fs, "postgresql.conf") {
		if _, ok := rank[p]; !ok {
			rank[p] = i
		}
	}
	ordered := func(insts []postgresql.Instance) []string {
		paths := []string{}
		for _, inst := range insts {
			if p := inst.ConfigFile(); p != "" {
				paths = append(paths, p)
			}
		}
		sort.SliceStable(paths, func(i, j int) bool {
			ri, iok := rank[paths[i]]
			rj, jok := rank[paths[j]]
			if iok != jok {
				return iok
			}
			return iok && ri < rj
		})
		return paths
	}
	return append(ordered(running), ordered(units)...)
}

// postgresqlFileFound reports whether file names a file that exists: false
// when none was found on the host, or when an explicit path points nowhere.
func postgresqlFileFound(file *mqlFile) (bool, error) {
	if file == nil {
		return false, nil
	}
	exists := file.GetExists()
	if exists.Error != nil {
		return false, exists.Error
	}
	return exists.Data, nil
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

	instancesOnce sync.Once
	running       []postgresql.Instance
	units         []postgresql.Instance

	// inst is the cluster that loads the file, resolved by parse.
	inst *postgresql.Instance
}

// instances returns what the host says about its clusters, read once per
// resource.
func (s *mqlPostgresqlConf) instances() (running, units []postgresql.Instance) {
	s.instancesOnce.Do(func() {
		s.running, s.units = postgresqlInstances(s.MqlRuntime)
	})
	return s.running, s.units
}

// instance returns the cluster that loads this postgresql.conf, or nil when
// the host says nothing about it.
func (s *mqlPostgresqlConf) instance() *postgresql.Instance {
	if s.MqlRuntime == nil || s.File.Data == nil {
		return nil
	}
	if s.parse(s.File.Data) != nil {
		return nil
	}
	return s.inst
}

// instanceFor returns the cluster that loads the postgresql.conf at
// confPath, whose own settings are fileParams. A postmaster whose data
// directory is not known from its command line or environment is matched
// through the postmaster.pid it writes into its data directory.
func (s *mqlPostgresqlConf) instanceFor(confPath string, fileParams map[string]string) *postgresql.Instance {
	running, units := s.instances()
	if inst := postgresql.InstanceFor(confPath, running, units); inst != nil {
		return inst
	}
	var unplaced []postgresql.Instance
	for _, inst := range running {
		if inst.Pid != 0 && inst.ConfigFile() == "" {
			unplaced = append(unplaced, inst)
		}
	}
	if len(unplaced) == 0 {
		return nil
	}
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	dataDir := postgresql.DataDirectory(confPath, fileParams)
	raw, err := afs.ReadFile(path.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return nil
	}
	pid, ok := postgresql.ParsePostmasterPid(string(raw))
	if !ok {
		return nil
	}
	return postgresql.RunningByPid(unplaced, pid)
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
	fs := conn.FileSystem()

	running, units := s.instances()
	p, err := findPostgresqlConfigFile(fs, "postgresql.conf", postgresqlPreferredConfigs(fs, running, units)...)
	if err != nil {
		return nil, err
	}
	if p != "" {
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
	exists := file.GetExists()
	if exists.Error != nil && plugin.StructuredErrors() {
		err := exists.Error
		if errors.Is(err, os.ErrPermission) {
			err = llx.Forbidden(err)
		}
		s.setConfError(err)
		return err
	}
	if exists.Error != nil || !exists.Data {
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

	// The cluster that loads the file decides where postgresql.auto.conf
	// is, and its command line (-c name=value, --name=value, -p) overrides
	// both files.
	s.inst = s.instanceFor(file.Path.Data, cfg.Params)

	if err := s.applyAutoConf(cfg, file.Path.Data, fileReader, dirLister); err != nil {
		s.setConfError(err)
		return err
	}

	effective := postgresql.Overlay(cfg.Params, s.inst)
	params := make(map[string]any, len(effective))
	for k, v := range effective {
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

// applyAutoConf overlays postgresql.auto.conf, which ALTER SYSTEM writes in
// the data directory and the server reads after postgresql.conf, so each of
// its settings wins. The data directory is data_directory from the config,
// else the -D of the cluster that loads it, else the config's own directory,
// which is where RHEL and the PGDG packages keep postgresql.conf. A missing
// file means ALTER SYSTEM never ran. A refused one is a Forbidden error with
// structured errors; without them it is skipped, as v13 never read it, and
// Debian's data directory is 0700 postgres.
func (s *mqlPostgresqlConf) applyAutoConf(cfg *postgresql.Conf, confPath string, fileReader postgresql.FileReader, dirLister postgresql.DirLister) error {
	dataDir := cfg.Params["data_directory"]
	if dataDir == "" && s.inst != nil {
		dataDir = s.inst.DataDir
	}
	if dataDir == "" {
		dataDir = path.Dir(confPath)
	}
	autoPath := path.Join(dataDir, "postgresql.auto.conf")
	auto, err := postgresql.ParseConf(autoPath, fileReader, dirLister)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if errors.Is(err, os.ErrPermission) {
			if !plugin.StructuredErrors() {
				return nil
			}
			return llx.Forbidden(err)
		}
		return err
	}
	cfg.Overlay(auto)
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

	return postgresql.EffectivePort(paramString(params, "port"), s.instance()), nil
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

// postgresqlAuxFile returns the path of the pg_hba.conf or pg_ident.conf the
// server loads. When a postgresql.conf is found, that is its hba_file or
// ident_file setting, or the file of that name in the data directory: the
// server never probes for these files, so a pg_hba.conf at a well-known path
// that hba_file points away from is not in effect. Without a postgresql.conf
// the well-known paths are probed for name. It returns "" when nothing was
// found.
func postgresqlAuxFile(runtime *plugin.Runtime, param, name string) (string, error) {
	raw, err := NewResource(runtime, "postgresql.conf", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	conf := raw.(*mqlPostgresqlConf)
	confFile := conf.GetFile()
	if confFile.Error != nil {
		return "", confFile.Error
	}
	if confFile.Data != nil {
		params := conf.GetParams()
		if params.Error != nil {
			return "", params.Error
		}
		values := make(map[string]string, len(params.Data))
		for k, v := range params.Data {
			if str, ok := v.(string); ok {
				values[k] = str
			}
		}
		return postgresql.AuxFilePath(confFile.Data.Path.Data, values, param, name), nil
	}

	conn := runtime.Connection.(shared.Connection)
	return findPostgresqlConfigFile(conn.FileSystem(), name)
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
	p, err := postgresqlAuxFile(s.MqlRuntime, "hba_file", "pg_hba.conf")
	if err != nil {
		return nil, err
	}
	if p != "" {
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
	found, err := postgresqlFileFound(file)
	if err != nil {
		return nil, err
	}
	if !found {
		// No pg_hba.conf: there are no rules to report, which is not the
		// same as a file that holds none. An empty list would let
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
	p, err := postgresqlAuxFile(s.MqlRuntime, "ident_file", "pg_ident.conf")
	if err != nil {
		return nil, err
	}
	if p != "" {
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
	found, err := postgresqlFileFound(file)
	if err != nil {
		return nil, err
	}
	if !found {
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

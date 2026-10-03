// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/types"
)

// ======================================================================
// haproxy — root resource (version detection)
// ======================================================================

// haproxyVersionBinaries lists the well-known paths for the haproxy binary.
// They're scanned for an embedded version literal before we fall back to
// executing `haproxy -v`.
var haproxyVersionBinaries = []string{
	"/usr/sbin/haproxy",
	"/usr/local/sbin/haproxy",
	"/usr/local/bin/haproxy",
	"/usr/bin/haproxy",
	"/opt/haproxy/sbin/haproxy",
}

func (n *mqlHaproxy) version() (string, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	// `haproxy -v` is the source of truth — it reads the same constant the
	// binary uses for its own help output. Try it first so we always get
	// the real version when the asset supports exec.
	cmd, err := conn.RunCommand("haproxy -v 2>&1")
	if err == nil && cmd.ExitStatus == 0 {
		data, err := io.ReadAll(cmd.Stdout)
		if err == nil {
			if m := reHaproxyVersion.FindSubmatch(data); m != nil {
				return string(m[1]), nil
			}
		}
	}

	// Asset-snapshot connections can't exec — fall back to scanning the
	// haproxy binary for the embedded version literal.
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, bin := range haproxyVersionBinaries {
		if v := scanHaproxyBinary(afs, bin); v != "" {
			return v, nil
		}
	}

	n.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

// reHaproxyVersion matches both "HA-Proxy version 2.8.4..." (used by
// legacy 1.x branches) and "HAProxy version 2.8.4..." (modern 2.x+).
// The capture extends to the first whitespace so suffixes like
// "-eea79933d" or "-1ppa1~jammy" are preserved.
var reHaproxyVersion = regexp.MustCompile(`(?:HA-Proxy|HAProxy) version (\S+)`)

// reHaproxyEmbeddedVersion matches the version literal HAProxy embeds in
// its own binary alongside the build date — e.g. ` version 2.8.24-eea79933d,
// released 2026/05/11`. Anchoring on `, released YYYY/MM/DD` avoids the
// false positive from a deprecation error message in modern binaries
// (`...since HAProxy version 2.5.`) that the previous prefix-only scan
// kept hitting first.
var reHaproxyEmbeddedVersion = regexp.MustCompile(` version ([0-9][0-9A-Za-z.\-_+~]*), released [0-9]{4}/[0-9]{2}/[0-9]{2}`)

// scanHaproxyBinary reads the haproxy binary in chunks and looks for the
// embedded `, released YYYY/MM/DD` marker. Used as a fallback for
// connections (asset snapshots, sandboxes) that can't run `haproxy -v`.
func scanHaproxyBinary(fs *afero.Afero, path string) string {
	f, err := fs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	const chunkSize = 64 * 1024
	// Overlap covers the longest pattern we might split across a boundary
	// (` version ` + version body + `, released YYYY/MM/DD`).
	const overlap = 96
	buf := make([]byte, chunkSize+overlap)
	carry := 0

	for {
		n, err := f.Read(buf[carry:])
		if n == 0 && err != nil {
			break
		}
		active := buf[:carry+n]

		if m := reHaproxyEmbeddedVersion.FindSubmatch(active); m != nil {
			return string(m[1])
		}

		// Carry forward the tail in case a match straddles chunk boundary.
		if len(active) > overlap {
			copy(buf, active[len(active)-overlap:])
			carry = overlap
		} else {
			carry = 0
		}

		if err != nil {
			break
		}
	}
	return ""
}

// ======================================================================
// haproxy.config — file discovery + parse coordination
// ======================================================================

type mqlHaproxyConfigInternal struct {
	lock sync.Mutex
	cfg  *haproxy.Config

	launchOnce    sync.Once
	launchConfigs []string
}

// haproxyConfPaths maps platform names/families to their default config
// path. Most platforms standardize on /etc/haproxy/haproxy.cfg.
var haproxyConfPaths = map[string]string{
	"freebsd":      "/usr/local/etc/haproxy.conf",
	"dragonflybsd": "/usr/local/etc/haproxy.conf",
	"openbsd":      "/etc/haproxy/haproxy.cfg",
	"netbsd":       "/usr/pkg/etc/haproxy/haproxy.cfg",
}

const defaultHaproxyConf = "/etc/haproxy/haproxy.cfg"

func haproxyConfPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := haproxyConfPaths[asset.Platform.Name]; ok {
			return p
		}
		for _, family := range asset.Platform.Family {
			if p, ok := haproxyConfPaths[family]; ok {
				return p
			}
		}
	}
	return defaultHaproxyConf
}

func initHaproxyConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in haproxy.config initialization, it must be a string")
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

func (s *mqlHaproxyConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return file.Data.Path.Data, nil
}

func (s *mqlHaproxyConfig) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := haproxyConfPath(conn)
	if launch := s.loadedConfigFiles(); len(launch) > 0 {
		path = launch[0]
	}

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// reHaproxyGlob detects filepath glob meta-characters in `!includeglob` patterns.
var reHaproxyGlob = regexp.MustCompile(`[*?\[]`)

// expandHaproxyGlob walks the connection's filesystem to expand an
// `!includeglob` pattern. Matches afero-backed layouts (serialized asset
// snapshots, container FS) — filepath.Glob hits the host FS instead.
func (s *mqlHaproxyConfig) expandHaproxyGlob(pattern string) ([]string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	if !reHaproxyGlob.MatchString(pattern) {
		return []string{pattern}, nil
	}

	segments := strings.Split(pattern, "/")
	var paths []string
	if segments[0] == "" {
		paths = []string{"/"}
	} else {
		paths = []string{segments[0]}
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, segment := range segments[1:] {
		if !reHaproxyGlob.MatchString(segment) {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], segment)
			}
			continue
		}
		var nuPaths []string
		for _, path := range paths {
			files, err := afs.ReadDir(path)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			for j := range files {
				name := files[j].Name()
				ok, err := filepath.Match(segment, name)
				if err != nil {
					return nil, err
				}
				if ok {
					nuPaths = append(nuPaths, filepath.Join(path, name))
				}
			}
		}
		paths = nuPaths
	}
	return paths, nil
}

// initHaproxyConfigGlobal lets `haproxy.config.global { ... }` resolve via the
// parent's global accessor. Without this, the dotted form instantiates an
// empty husk (the resource name `haproxy.config.global` shadows the field
// accessor `global` on `haproxy.config`) and every field errors with
// `cannot convert primitive with NO type information`.
func initHaproxyConfigGlobal(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	cfg, err := NewResource(runtime, "haproxy.config", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	global := cfg.(*mqlHaproxyConfig).GetGlobal()
	if global.Error != nil {
		return nil, nil, global.Error
	}
	return args, global.Data, nil
}

const defaultHaproxyPidFile = "/run/haproxy.pid"

// loadedConfigFiles returns the configuration files haproxy loads, in load
// order, as given by its `-f` arguments (directories expanded to their
// `*.cfg` files the way haproxy does). The arguments come from the running
// haproxy process when there is one, otherwise from the haproxy systemd
// service with its Environment= and EnvironmentFile= settings
// (/etc/default/haproxy, /etc/sysconfig/haproxy). It returns nil when
// neither is available.
func (s *mqlHaproxyConfig) loadedConfigFiles() []string {
	s.launchOnce.Do(func() {
		conn := s.MqlRuntime.Connection.(shared.Connection)
		afs := &afero.Afero{Fs: conn.FileSystem()}

		unit := haproxyServiceLaunch(afs)
		pidFile := unit.PidFile
		if pidFile == "" {
			pidFile = defaultHaproxyPidFile
		}
		configs := haproxyProcessConfigs(afs, pidFile)
		if len(configs) == 0 {
			// No pid file: haproxy -db (the official image) writes none.
			configs = haproxyLaunchConfigs(s.MqlRuntime)
		}
		if len(configs) == 0 {
			configs = unit.Configs
		}

		var files []string
		for _, p := range configs {
			if !filepath.IsAbs(p) {
				// systemd starts services in /
				p = filepath.Join("/", p)
			}
			files = append(files, expandHaproxyConfigArg(afs, p)...)
		}
		s.launchConfigs = files
	})
	return s.launchConfigs
}

// haproxyServiceLaunch reads haproxy.service, its drop-ins and its
// environment files and returns the arguments ExecStart= passes.
func haproxyServiceLaunch(afs *afero.Afero) haproxy.LaunchArgs {
	argv := systemdServiceArgv(afs, "haproxy.service")
	if len(argv) == 0 {
		return haproxy.LaunchArgs{}
	}
	return haproxy.ParseLaunchArgs(argv[1:])
}

// haproxyProcessConfigs returns the `-f` arguments of the running haproxy
// process recorded in pidFile, or nil when it isn't running or its command
// line can't be read.
func haproxyProcessConfigs(afs *afero.Afero, pidFile string) []string {
	data, err := afs.ReadFile(pidFile)
	if err != nil {
		return nil
	}
	// A pid file can list several pids (the master first, then workers or
	// old processes during a reload). They all run with the same `-f`
	// arguments, so the first readable haproxy command line answers.
	for _, pid := range strings.Fields(string(data)) {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := afs.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		argv := haproxy.SplitProcCmdline(raw)
		// A stale pid file can point at an unrelated process.
		if len(argv) == 0 || !strings.Contains(filepath.Base(argv[0]), "haproxy") {
			continue
		}
		if configs := haproxy.ParseLaunchArgs(argv[1:]).Configs; len(configs) > 0 {
			return configs
		}
	}
	return nil
}

// haproxyLaunch recognizes haproxy's processes: the program is named
// haproxy (or a versioned build such as haproxy27).
var haproxyLaunch = serverLaunchSpec{
	Names: []string{"haproxy"},
	IsServer: func(argv []string) bool {
		return strings.Contains(filepath.Base(argv[0]), "haproxy")
	},
}

// haproxyLaunchConfigs returns the `-f` arguments, made absolute, of the
// running haproxy master found in /proc, or of the haproxy a scanned image
// starts. It returns nil when neither names a configuration.
func haproxyLaunchConfigs(runtime *plugin.Runtime) []string {
	for _, l := range findServerLaunches(runtime, haproxyLaunch) {
		configs := haproxy.ParseLaunchArgs(l.Argv[1:]).Configs
		if len(configs) == 0 {
			continue
		}
		for i := range configs {
			configs[i] = l.resolve(configs[i])
		}
		return configs
	}
	return nil
}

// expandHaproxyConfigArg turns one `-f` argument into files: a directory
// loads its `*.cfg` files in lexical order, as haproxy does; anything else
// is a file.
func expandHaproxyConfigArg(afs *afero.Afero, p string) []string {
	// Stat first: some connection filesystems (sudo over SSH) list a
	// plain file as a directory holding itself.
	if fi, err := afs.Stat(p); err != nil || !fi.IsDir() {
		return []string{p}
	}
	entries, err := afs.ReadDir(p)
	if err != nil {
		return []string{p}
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cfg") {
			continue
		}
		files = append(files, filepath.Join(p, e.Name()))
	}
	sort.Strings(files)
	return files
}

// parse runs the HAProxy parser against the configured file and every
// file pulled in through `!include` / `!includeglob`. When the file is the
// first one haproxy itself loads (see loadedConfigFiles), the other files
// passed with `-f` are parsed after it, in haproxy's load order.
func (s *mqlHaproxyConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cfg != nil {
		return nil
	}
	if file == nil {
		return errors.New("no base haproxy config file to read")
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := conn.FileSystem()

	openFn := func(path string) (io.ReadCloser, error) {
		return afs.Open(path)
	}
	globFn := func(pattern string) ([]string, error) {
		return s.expandHaproxyGlob(pattern)
	}

	// Always parse the primary file first so its `!include` directives
	// can pull in their dependencies and the resulting Section.File
	// values match the directives' source.
	primary := file.Path.Data
	cfg, err := haproxy.ParseFiles(primary, openFn, globFn)
	if err != nil {
		s.cfg = &haproxy.Config{}
		s.markParseErrors(err)
		return err
	}

	var extra []string
	if launch := s.loadedConfigFiles(); len(launch) > 0 && launch[0] == primary {
		extra = launch[1:]
	}
	for _, p := range extra {
		sub, perr := haproxy.ParseFiles(p, openFn, globFn)
		if perr != nil {
			// Don't abort on a single bad file: record it and continue
			// so the rest of the config still surfaces.
			cfg.Errors = append(cfg.Errors, haproxy.ParseError{File: p, Msg: perr.Error()})
			continue
		}
		cfg.Sections = append(cfg.Sections, sub.Sections...)
		cfg.Files = append(cfg.Files, sub.Files...)
		cfg.Errors = append(cfg.Errors, sub.Errors...)
	}

	s.cfg = cfg
	return nil
}

func (s *mqlHaproxyConfig) markParseErrors(err error) {
	errVal := plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	resVal := plugin.TValue[*mqlHaproxyConfigGlobal]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.Global = resVal
	s.Defaults = errVal
	s.Frontends = errVal
	s.Backends = errVal
	s.Listens = errVal
	s.Resolvers = errVal
	s.Userlists = errVal
	s.Peers = errVal
	s.Sections = errVal
	s.Files = errVal
}

func (s *mqlHaproxyConfig) files(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(s.cfg.Files))
	for _, p := range s.cfg.Files {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(p),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) sections(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(s.cfg.Sections))
	for i, sec := range s.cfg.Sections {
		id := fmt.Sprintf("%s#section/%d/%s/%s", s.__id, i, sec.Type, sec.Name)
		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.section", map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"type":       llx.StringData(sec.Type),
			"name":       llx.StringData(sec.Name),
			"inherits":   llx.StringData(sec.Inherits),
			"file":       llx.StringData(sec.File),
			"startLine":  llx.IntData(int64(sec.StartLine)),
			"endLine":    llx.IntData(int64(sec.EndLine)),
			"params":     llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"directives": llx.ArrayData(haproxy.DirectivesAsDicts(sec.Directives), types.Dict),
			"raw":        llx.StringData(sec.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) global(file *mqlFile) (*mqlHaproxyConfigGlobal, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	// HAProxy allows multiple `global` sections in theory; the parser
	// preserves all of them, but every directive past the first is just
	// merged into the runtime global state. We mirror that by combining
	// directives across global sections so the typed view sees them all.
	var dirs []haproxy.Directive
	var srcFile string
	for _, sec := range s.cfg.Sections {
		if sec.Type != "global" {
			continue
		}
		if srcFile == "" {
			srcFile = sec.File
		}
		dirs = append(dirs, sec.Directives...)
	}

	statsSocket, statsMode, statsLevel, statsUser, statsTimeout := parseStatsSocket(dirs)
	enabledOpt, disabledOpt := haproxy.CollectOptions(dirs)
	tuneDH, _ := haproxy.FindFirstInt(dirs, "tune.ssl.default-dh-param")
	maxconn, _ := haproxy.FindFirstInt(dirs, "maxconn")
	nbthread, _ := haproxy.FindFirstInt(dirs, "nbthread")
	nbproc, _ := haproxy.FindFirstInt(dirs, "nbproc")

	id := s.__id + "#global"
	obj, err := CreateResource(s.MqlRuntime, "haproxy.config.global", map[string]*llx.RawData{
		"__id":                         llx.StringData(id),
		"daemon":                       llx.BoolData(hasFlag(dirs, "daemon")),
		"masterWorker":                 llx.BoolData(hasFlag(dirs, "master-worker")),
		"user":                         llx.StringData(haproxy.FindLast(dirs, "user")),
		"group":                        llx.StringData(haproxy.FindLast(dirs, "group")),
		"chroot":                       llx.StringData(haproxy.FindLast(dirs, "chroot")),
		"pidfile":                      llx.StringData(haproxy.FindLast(dirs, "pidfile")),
		"maxconn":                      llx.IntData(maxconn),
		"nbthread":                     llx.IntData(nbthread),
		"nbproc":                       llx.IntData(nbproc),
		"hardStopAfter":                llx.StringData(haproxy.FindLast(dirs, "hard-stop-after")),
		"statsSocket":                  llx.StringData(statsSocket),
		"statsSocketMode":              llx.StringData(statsMode),
		"statsSocketLevel":             llx.StringData(statsLevel),
		"statsSocketUser":              llx.StringData(statsUser),
		"statsTimeout":                 llx.StringData(statsTimeout),
		"log":                          llx.ArrayData(stringSliceToAny(haproxy.CollectLog(dirs)), types.String),
		"sslDefaultBindCiphers":        llx.StringData(haproxy.FindLast(dirs, "ssl-default-bind-ciphers")),
		"sslDefaultBindCiphersuites":   llx.StringData(haproxy.FindLast(dirs, "ssl-default-bind-ciphersuites")),
		"sslDefaultBindOptions":        llx.StringData(haproxy.FindLast(dirs, "ssl-default-bind-options")),
		"sslDefaultBindCurves":         llx.StringData(haproxy.FindLast(dirs, "ssl-default-bind-curves")),
		"sslDefaultServerCiphers":      llx.StringData(haproxy.FindLast(dirs, "ssl-default-server-ciphers")),
		"sslDefaultServerCiphersuites": llx.StringData(haproxy.FindLast(dirs, "ssl-default-server-ciphersuites")),
		"sslDefaultServerOptions":      llx.StringData(haproxy.FindLast(dirs, "ssl-default-server-options")),
		"sslDefaultServerCurves":       llx.StringData(haproxy.FindLast(dirs, "ssl-default-server-curves")),
		"caBase":                       llx.StringData(haproxy.FindLast(dirs, "ca-base")),
		"crtBase":                      llx.StringData(haproxy.FindLast(dirs, "crt-base")),
		"tuneSslDefaultDhParam":        llx.IntData(tuneDH),
		"options":                      llx.ArrayData(stringSliceToAny(enabledOpt), types.String),
		"disabledOptions":              llx.ArrayData(stringSliceToAny(disabledOpt), types.String),
		"params":                       llx.MapData(stringMapToAny(haproxy.ParamsMap(dirs)), types.String),
		"file":                         llx.StringData(srcFile),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlHaproxyConfigGlobal), nil
}

// parseStatsSocket extracts the `stats socket` and `stats timeout`
// directives from a global section. HAProxy's grammar uses a single
// `stats` keyword followed by a sub-command, so we walk every `stats`
// line until we find one that matches.
func parseStatsSocket(dirs []haproxy.Directive) (path, mode, level, user, timeout string) {
	for _, d := range dirs {
		if d.Name != "stats" || len(d.Args) == 0 {
			continue
		}
		switch d.Args[0] {
		case "socket":
			if len(d.Args) < 2 {
				continue
			}
			path = d.Args[1]
			for i := 2; i < len(d.Args); i++ {
				switch d.Args[i] {
				case "mode":
					if i+1 < len(d.Args) {
						mode = d.Args[i+1]
						i++
					}
				case "level":
					if i+1 < len(d.Args) {
						level = d.Args[i+1]
						i++
					}
				case "user":
					if i+1 < len(d.Args) {
						user = d.Args[i+1]
						i++
					}
				}
			}
		case "timeout":
			if len(d.Args) >= 2 {
				timeout = d.Args[1]
			}
		}
	}
	return
}

func hasFlag(dirs []haproxy.Directive, name string) bool {
	for _, d := range dirs {
		if d.Name == name {
			return true
		}
	}
	return false
}

// ======================================================================
// defaults / frontend / backend / listen — typed section builders
// ======================================================================

func (s *mqlHaproxyConfig) defaults(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "defaults" {
			continue
		}
		retries, _ := haproxy.FindFirstInt(sec.Directives, "retries")
		maxconn, _ := haproxy.FindFirstInt(sec.Directives, "maxconn")
		enabledOpt, disabledOpt := haproxy.CollectOptions(sec.Directives)

		id := fmt.Sprintf("%s#defaults/%d/%s", s.__id, i, sec.Name)
		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.defaultsSection", map[string]*llx.RawData{
			"__id":            llx.StringData(id),
			"name":            llx.StringData(sec.Name),
			"inherits":        llx.StringData(sec.Inherits),
			"mode":            llx.StringData(haproxy.FindLast(sec.Directives, "mode")),
			"balance":         llx.StringData(haproxy.FindLast(sec.Directives, "balance")),
			"retries":         llx.IntData(retries),
			"maxconn":         llx.IntData(maxconn),
			"options":         llx.ArrayData(stringSliceToAny(enabledOpt), types.String),
			"disabledOptions": llx.ArrayData(stringSliceToAny(disabledOpt), types.String),
			"timeouts":        llx.MapData(stringMapToAny(haproxy.CollectTimeouts(sec.Directives)), types.String),
			"log":             llx.ArrayData(stringSliceToAny(haproxy.CollectLog(sec.Directives)), types.String),
			"params":          llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":            llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) frontends(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "frontend" {
			continue
		}
		id := fmt.Sprintf("%s#frontend/%d/%s", s.__id, i, sec.Name)
		binds, err := buildBindResources(s.MqlRuntime, id, haproxy.ParseBindLines(sec.Directives))
		if err != nil {
			return nil, err
		}
		enabledOpt, disabledOpt := haproxy.CollectOptions(sec.Directives)
		maxconn, _ := haproxy.FindFirstInt(sec.Directives, "maxconn")

		monitorURI := haproxy.FindLast(sec.Directives, "monitor-uri")
		var monitorFail string
		for _, d := range sec.Directives {
			if d.Name == "monitor" && len(d.Args) >= 1 && d.Args[0] == "fail" {
				monitorFail = strings.Join(d.Args[1:], " ")
			}
		}

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.frontend", map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"name":              llx.StringData(sec.Name),
			"inherits":          llx.StringData(sec.Inherits),
			"mode":              llx.StringData(haproxy.FindLast(sec.Directives, "mode")),
			"binds":             llx.ArrayData(binds, types.Resource("haproxy.config.bind")),
			"defaultBackend":    llx.StringData(haproxy.FindLast(sec.Directives, "default_backend")),
			"acls":              llx.ArrayData(aclsToDicts(haproxy.ParseACLs(sec.Directives)), types.Dict),
			"useBackends":       llx.ArrayData(useBackendsToDicts(haproxy.ParseUseBackends(sec.Directives)), types.Dict),
			"httpRequestRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-request")), types.String),
			"httpResponseRules": llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-response")), types.String),
			"tcpRequestRules":   llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-request")), types.String),
			"tcpResponseRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-response")), types.String),
			"captures":          llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "capture")), types.String),
			"redirects":         llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "redirect")), types.String),
			"monitorUri":        llx.StringData(monitorURI),
			"monitorFail":       llx.StringData(monitorFail),
			"options":           llx.ArrayData(stringSliceToAny(enabledOpt), types.String),
			"disabledOptions":   llx.ArrayData(stringSliceToAny(disabledOpt), types.String),
			"timeouts":          llx.MapData(stringMapToAny(haproxy.CollectTimeouts(sec.Directives)), types.String),
			"log":               llx.ArrayData(stringSliceToAny(haproxy.CollectLog(sec.Directives)), types.String),
			"maxconn":           llx.IntData(maxconn),
			"params":            llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":              llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) backends(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "backend" {
			continue
		}
		id := fmt.Sprintf("%s#backend/%d/%s", s.__id, i, sec.Name)
		servers, err := buildServerResources(s.MqlRuntime, id, haproxy.ParseServerLines(sec.Directives))
		if err != nil {
			return nil, err
		}
		enabledOpt, disabledOpt := haproxy.CollectOptions(sec.Directives)
		retries, _ := haproxy.FindFirstInt(sec.Directives, "retries")

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.backend", map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"name":              llx.StringData(sec.Name),
			"inherits":          llx.StringData(sec.Inherits),
			"mode":              llx.StringData(haproxy.FindLast(sec.Directives, "mode")),
			"balance":           llx.StringData(haproxy.FindLast(sec.Directives, "balance")),
			"hashType":          llx.StringData(haproxy.FindLast(sec.Directives, "hash-type")),
			"servers":           llx.ArrayData(servers, types.Resource("haproxy.config.server")),
			"defaultServer":     llx.DictData(defaultServerDict(haproxy.ParseDefaultServer(sec.Directives))),
			"source":            llx.StringData(haproxy.FindLast(sec.Directives, "source")),
			"httpCheck":         llx.DictData(httpCheckDict(haproxy.ParseHTTPCheck(sec.Directives))),
			"stickTable":        llx.StringData(haproxy.FindLast(sec.Directives, "stick-table")),
			"stickOn":           llx.StringData(haproxy.FindStickOn(sec.Directives)),
			"cookie":            llx.StringData(haproxy.FindLast(sec.Directives, "cookie")),
			"acls":              llx.ArrayData(aclsToDicts(haproxy.ParseACLs(sec.Directives)), types.Dict),
			"httpRequestRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-request")), types.String),
			"httpResponseRules": llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-response")), types.String),
			"tcpRequestRules":   llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-request")), types.String),
			"tcpResponseRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-response")), types.String),
			"options":           llx.ArrayData(stringSliceToAny(enabledOpt), types.String),
			"disabledOptions":   llx.ArrayData(stringSliceToAny(disabledOpt), types.String),
			"timeouts":          llx.MapData(stringMapToAny(haproxy.CollectTimeouts(sec.Directives)), types.String),
			"log":               llx.ArrayData(stringSliceToAny(haproxy.CollectLog(sec.Directives)), types.String),
			"retries":           llx.IntData(retries),
			"params":            llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":              llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) listens(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "listen" {
			continue
		}
		id := fmt.Sprintf("%s#listen/%d/%s", s.__id, i, sec.Name)
		binds, err := buildBindResources(s.MqlRuntime, id, haproxy.ParseBindLines(sec.Directives))
		if err != nil {
			return nil, err
		}
		servers, err := buildServerResources(s.MqlRuntime, id, haproxy.ParseServerLines(sec.Directives))
		if err != nil {
			return nil, err
		}
		enabledOpt, disabledOpt := haproxy.CollectOptions(sec.Directives)

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.listen", map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"name":              llx.StringData(sec.Name),
			"inherits":          llx.StringData(sec.Inherits),
			"mode":              llx.StringData(haproxy.FindLast(sec.Directives, "mode")),
			"binds":             llx.ArrayData(binds, types.Resource("haproxy.config.bind")),
			"balance":           llx.StringData(haproxy.FindLast(sec.Directives, "balance")),
			"servers":           llx.ArrayData(servers, types.Resource("haproxy.config.server")),
			"defaultServer":     llx.DictData(defaultServerDict(haproxy.ParseDefaultServer(sec.Directives))),
			"acls":              llx.ArrayData(aclsToDicts(haproxy.ParseACLs(sec.Directives)), types.Dict),
			"useBackends":       llx.ArrayData(useBackendsToDicts(haproxy.ParseUseBackends(sec.Directives)), types.Dict),
			"httpRequestRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-request")), types.String),
			"httpResponseRules": llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "http-response")), types.String),
			"tcpRequestRules":   llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-request")), types.String),
			"tcpResponseRules":  llx.ArrayData(stringSliceToAny(haproxy.CollectRules(sec.Directives, "tcp-response")), types.String),
			"httpCheck":         llx.DictData(httpCheckDict(haproxy.ParseHTTPCheck(sec.Directives))),
			"options":           llx.ArrayData(stringSliceToAny(enabledOpt), types.String),
			"disabledOptions":   llx.ArrayData(stringSliceToAny(disabledOpt), types.String),
			"timeouts":          llx.MapData(stringMapToAny(haproxy.CollectTimeouts(sec.Directives)), types.String),
			"log":               llx.ArrayData(stringSliceToAny(haproxy.CollectLog(sec.Directives)), types.String),
			"params":            llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":              llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) resolvers(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "resolvers" {
			continue
		}
		id := fmt.Sprintf("%s#resolvers/%d/%s", s.__id, i, sec.Name)

		var nameservers []any
		holds := map[string]string{}
		var resolveRetries int64
		var payload int64
		for _, d := range sec.Directives {
			switch d.Name {
			case "nameserver":
				ns := map[string]any{"name": "", "address": "", "port": int64(0)}
				if len(d.Args) >= 1 {
					ns["name"] = d.Args[0]
				}
				if len(d.Args) >= 2 {
					addr, port := haproxy.ParseAddrPort(d.Args[1])
					ns["address"] = addr
					ns["port"] = port
				}
				nameservers = append(nameservers, ns)
			case "hold":
				if len(d.Args) >= 2 {
					holds[d.Args[0]] = strings.Join(d.Args[1:], " ")
				}
			case "resolve_retries":
				if len(d.Args) >= 1 {
					if v, ok := parseInt64(d.Args[0]); ok {
						resolveRetries = v
					}
				}
			case "accepted_payload_size":
				if len(d.Args) >= 1 {
					if v, ok := parseInt64(d.Args[0]); ok {
						payload = v
					}
				}
			}
		}

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.resolversSection", map[string]*llx.RawData{
			"__id":                llx.StringData(id),
			"name":                llx.StringData(sec.Name),
			"nameservers":         llx.ArrayData(nameservers, types.Dict),
			"resolveRetries":      llx.IntData(resolveRetries),
			"timeouts":            llx.MapData(stringMapToAny(haproxy.CollectTimeouts(sec.Directives)), types.String),
			"acceptedPayloadSize": llx.IntData(payload),
			"holds":               llx.MapData(stringMapToAny(holds), types.String),
			"params":              llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":                llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) userlists(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "userlist" {
			continue
		}
		id := fmt.Sprintf("%s#userlist/%d/%s", s.__id, i, sec.Name)

		var users []any
		var groups []any
		for _, d := range sec.Directives {
			switch d.Name {
			case "user":
				// user <name> [password|insecure-password] <secret> [groups <g1,g2>]
				u := map[string]any{"name": "", "password": "", "hashed": false, "groups": []any{}}
				if len(d.Args) >= 1 {
					u["name"] = d.Args[0]
				}
				j := 1
				for j < len(d.Args) {
					switch d.Args[j] {
					case "password":
						if j+1 < len(d.Args) {
							u["password"] = d.Args[j+1]
							u["hashed"] = true
							j += 2
							continue
						}
					case "insecure-password":
						if j+1 < len(d.Args) {
							u["password"] = d.Args[j+1]
							u["hashed"] = false
							j += 2
							continue
						}
					case "groups":
						if j+1 < len(d.Args) {
							var gs []any
							for _, g := range strings.Split(d.Args[j+1], ",") {
								gs = append(gs, strings.TrimSpace(g))
							}
							u["groups"] = gs
							j += 2
							continue
						}
					}
					j++
				}
				users = append(users, u)
			case "group":
				g := map[string]any{"name": "", "users": []any{}}
				if len(d.Args) >= 1 {
					g["name"] = d.Args[0]
				}
				for j := 1; j < len(d.Args); j++ {
					if d.Args[j] == "users" && j+1 < len(d.Args) {
						var us []any
						for _, u := range strings.Split(d.Args[j+1], ",") {
							us = append(us, strings.TrimSpace(u))
						}
						g["users"] = us
						j++
					}
				}
				groups = append(groups, g)
			}
		}

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.userlist", map[string]*llx.RawData{
			"__id":   llx.StringData(id),
			"name":   llx.StringData(sec.Name),
			"users":  llx.ArrayData(users, types.Dict),
			"groups": llx.ArrayData(groups, types.Dict),
			"file":   llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlHaproxyConfig) peers(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	var res []any
	for i, sec := range s.cfg.Sections {
		if sec.Type != "peers" {
			continue
		}
		id := fmt.Sprintf("%s#peers/%d/%s", s.__id, i, sec.Name)
		servers, err := buildServerResources(s.MqlRuntime, id, haproxy.ParsePeerLines(sec.Directives))
		if err != nil {
			return nil, err
		}

		var tables []any
		for _, d := range sec.Directives {
			if d.Name != "table" || len(d.Args) == 0 {
				continue
			}
			t := map[string]any{"name": d.Args[0], "raw": strings.Join(d.Args, " ")}
			for j := 1; j < len(d.Args); j++ {
				switch d.Args[j] {
				case "type", "size", "expire", "store":
					if j+1 < len(d.Args) {
						t[d.Args[j]] = d.Args[j+1]
						j++
					}
				}
			}
			tables = append(tables, t)
		}

		obj, err := CreateResource(s.MqlRuntime, "haproxy.config.peersSection", map[string]*llx.RawData{
			"__id":    llx.StringData(id),
			"name":    llx.StringData(sec.Name),
			"bind":    llx.StringData(haproxy.FindLast(sec.Directives, "bind")),
			"servers": llx.ArrayData(servers, types.Resource("haproxy.config.server")),
			"tables":  llx.ArrayData(tables, types.Dict),
			"params":  llx.MapData(stringMapToAny(haproxy.ParamsMap(sec.Directives)), types.String),
			"file":    llx.StringData(sec.File),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// ======================================================================
// resource builders for bind / server / dict shapes
// ======================================================================

func buildBindResources(runtime *plugin.Runtime, parentID string, binds []haproxy.Bind) ([]any, error) {
	res := make([]any, len(binds))
	for i, b := range binds {
		id := fmt.Sprintf("%s/bind/%d/%s:%d", parentID, i, b.Address, b.Port)
		obj, err := CreateResource(runtime, "haproxy.config.bind", map[string]*llx.RawData{
			"__id":           llx.StringData(id),
			"raw":            llx.StringData(b.Raw),
			"address":        llx.StringData(b.Address),
			"port":           llx.IntData(b.Port),
			"portRangeStart": llx.IntData(b.PortRangeStart),
			"portRangeEnd":   llx.IntData(b.PortRangeEnd),
			"ssl":            llx.BoolData(b.SSL),
			"alpn":           llx.StringData(b.ALPN),
			"ciphers":        llx.StringData(b.Ciphers),
			"ciphersuites":   llx.StringData(b.Ciphersuites),
			"curves":         llx.StringData(b.Curves),
			"crt":            llx.StringData(b.Crt),
			"crtList":        llx.StringData(b.CrtList),
			"caFile":         llx.StringData(b.CAFile),
			"verify":         llx.StringData(b.Verify),
			"sslMinVer":      llx.StringData(b.SSLMinVer),
			"sslMaxVer":      llx.StringData(b.SSLMaxVer),
			"noSslv3":        llx.BoolData(b.NoSSLv3),
			"noTlsv10":       llx.BoolData(b.NoTLSv10),
			"noTlsv11":       llx.BoolData(b.NoTLSv11),
			"noTlsv12":       llx.BoolData(b.NoTLSv12),
			"noTlsv13":       llx.BoolData(b.NoTLSv13),
			"acceptProxy":    llx.BoolData(b.AcceptProxy),
			"transparent":    llx.BoolData(b.Transparent),
			"v4v6":           llx.BoolData(b.V4V6),
			"v6only":         llx.BoolData(b.V6Only),
			"params":         llx.MapData(stringMapToAny(b.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func buildServerResources(runtime *plugin.Runtime, parentID string, servers []haproxy.Server) ([]any, error) {
	res := make([]any, len(servers))
	for i, sv := range servers {
		id := fmt.Sprintf("%s/server/%d/%s", parentID, i, sv.Name)
		obj, err := CreateResource(runtime, "haproxy.config.server", map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"name":         llx.StringData(sv.Name),
			"address":      llx.StringData(sv.Address),
			"port":         llx.IntData(sv.Port),
			"check":        llx.BoolData(sv.Check),
			"ssl":          llx.BoolData(sv.SSL),
			"verify":       llx.StringData(sv.Verify),
			"caFile":       llx.StringData(sv.CAFile),
			"crt":          llx.StringData(sv.Crt),
			"sni":          llx.StringData(sv.SNI),
			"alpn":         llx.StringData(sv.ALPN),
			"weight":       llx.IntData(sv.Weight),
			"backup":       llx.BoolData(sv.Backup),
			"disabled":     llx.BoolData(sv.Disabled),
			"maxconn":      llx.IntData(sv.Maxconn),
			"maxqueue":     llx.IntData(sv.Maxqueue),
			"inter":        llx.StringData(sv.Inter),
			"fastInter":    llx.StringData(sv.FastInter),
			"downInter":    llx.StringData(sv.DownInter),
			"rise":         llx.IntData(sv.Rise),
			"fall":         llx.IntData(sv.Fall),
			"slowStart":    llx.StringData(sv.SlowStart),
			"observe":      llx.StringData(sv.Observe),
			"onError":      llx.StringData(sv.OnError),
			"onMarkedUp":   llx.StringData(sv.OnMarkedUp),
			"onMarkedDown": llx.StringData(sv.OnMarkedDwn),
			"cookie":       llx.StringData(sv.Cookie),
			"resolvers":    llx.StringData(sv.Resolvers),
			"initAddr":     llx.StringData(sv.InitAddr),
			"sendProxy":    llx.BoolData(sv.SendProxy),
			"sendProxyV2":  llx.BoolData(sv.SendProxyV2),
			"agentCheck":   llx.BoolData(sv.AgentCheck),
			"agentPort":    llx.IntData(sv.AgentPort),
			"agentAddr":    llx.StringData(sv.AgentAddr),
			"agentInter":   llx.StringData(sv.AgentInter),
			"params":       llx.MapData(stringMapToAny(sv.Params), types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func aclsToDicts(acls []haproxy.ACL) []any {
	out := make([]any, len(acls))
	for i, a := range acls {
		args := make([]any, len(a.Args))
		for j, v := range a.Args {
			args[j] = v
		}
		out[i] = map[string]any{
			"name":      a.Name,
			"criterion": a.Criterion,
			"args":      args,
			"line":      int64(a.Line),
			"raw":       a.Raw,
		}
	}
	return out
}

func useBackendsToDicts(rules []haproxy.UseBackend) []any {
	out := make([]any, len(rules))
	for i, r := range rules {
		out[i] = map[string]any{
			"backend":   r.Backend,
			"condition": r.Condition,
			"line":      int64(r.Line),
			"raw":       r.Raw,
		}
	}
	return out
}

func defaultServerDict(s *haproxy.Server) any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"check":        s.Check,
		"ssl":          s.SSL,
		"verify":       s.Verify,
		"caFile":       s.CAFile,
		"crt":          s.Crt,
		"sni":          s.SNI,
		"alpn":         s.ALPN,
		"weight":       s.Weight,
		"weightSet":    s.WeightSet,
		"backup":       s.Backup,
		"disabled":     s.Disabled,
		"maxconn":      s.Maxconn,
		"maxqueue":     s.Maxqueue,
		"inter":        s.Inter,
		"fastInter":    s.FastInter,
		"downInter":    s.DownInter,
		"rise":         s.Rise,
		"fall":         s.Fall,
		"slowStart":    s.SlowStart,
		"observe":      s.Observe,
		"onError":      s.OnError,
		"onMarkedUp":   s.OnMarkedUp,
		"onMarkedDown": s.OnMarkedDwn,
		"cookie":       s.Cookie,
		"resolvers":    s.Resolvers,
		"initAddr":     s.InitAddr,
		"sendProxy":    s.SendProxy,
		"sendProxyV2":  s.SendProxyV2,
		"agentCheck":   s.AgentCheck,
		"agentPort":    s.AgentPort,
		"agentAddr":    s.AgentAddr,
		"agentInter":   s.AgentInter,
		"params":       stringMapToAny(s.Params),
		"raw":          s.Raw,
	}
}

func httpCheckDict(hc haproxy.HTTPCheck) any {
	if hc.Method == "" && hc.URI == "" && len(hc.Send) == 0 && len(hc.Expect) == 0 && !hc.Disable {
		return nil
	}
	send := make([]any, len(hc.Send))
	for i, v := range hc.Send {
		send[i] = v
	}
	expect := make([]any, len(hc.Expect))
	for i, v := range hc.Expect {
		expect[i] = v
	}
	return map[string]any{
		"method":   hc.Method,
		"uri":      hc.URI,
		"version":  hc.Version,
		"send":     send,
		"expect":   expect,
		"disabled": hc.Disable,
	}
}

// ======================================================================
// helpers
// ======================================================================

func stringSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func stringMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseInt64(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

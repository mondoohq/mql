// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/nginx"
	"go.mondoo.com/mql/types"
)

// nginxVersionBinaries lists the well-known binary paths for the nginx server.
// The version string (e.g. "nginx/1.25.3") is embedded as a constant in the
// binary, so we can extract it by reading the file directly — no command
// execution required.
var nginxVersionBinaries = []string{
	"/usr/sbin/nginx",
	"/usr/local/sbin/nginx",
	"/usr/local/bin/nginx",
	"/usr/bin/nginx",
}

var nginxVersionTag = []byte("nginx/")

func (n *mqlNginx) version() (string, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// Prefer file-based detection: scan the nginx binary for the embedded
	// "nginx/x.y.z" version string without loading the full binary into memory.
	for _, bin := range nginxVersionBinaries {
		if v := scanBinaryForTag(afs, bin, nginxVersionTag, nil); v != "" {
			return v, nil
		}
	}

	// Fall back to running a command when the binary isn't readable (e.g.
	// non-standard install path). We use lowercase -v (not -V) because it
	// prints only the version line and is cheaper than -V which also dumps
	// all configure arguments.
	cmd, err := conn.RunCommand("nginx -v 2>&1")
	if err == nil && cmd.ExitStatus == 0 {
		data, err := io.ReadAll(cmd.Stdout)
		if err == nil {
			if m := reNginxVersion.FindSubmatch(data); m != nil {
				return string(m[1]), nil
			}
		}
	}

	// Nginx is likely not installed; return nil rather than an error.
	n.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

func (n *mqlNginx) modules() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	// Modules require "nginx -V" output (configure arguments are not in the binary).
	cmd, err := conn.RunCommand("nginx -V 2>&1")
	if err != nil {
		n.Modules = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	if cmd.ExitStatus != 0 {
		n.Modules = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	configured, _ := parseNginxConfigureModules(string(data))

	// A dynamic module only runs when the configuration loads it. Debian 9
	// to 11 build theirs out of tree, so nginx -V does not list them as
	// =dynamic, and only load_module names them.
	loaded, err := n.loadedNginxModules(n.launchInfo().conf)
	if err != nil {
		return nil, err
	}

	modules := nginxModules(configured, loaded)
	modulesData := make([]any, len(modules))
	for i, m := range modules {
		modulesData[i] = m
	}
	return modulesData, nil
}

// loadedNginxModules returns the load_module paths of the nginx config at path.
func (n *mqlNginx) loadedNginxModules(path string) ([]string, error) {
	o, err := NewResource(n.MqlRuntime, "nginx.conf", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	conf := o.(*mqlNginxConf)
	if params := conf.GetParams(); params.Error != nil {
		return nil, params.Error
	}
	conf.lock.Lock()
	defer conf.lock.Unlock()
	return conf.loadModules, nil
}

// nginxLoadModules returns the paths of the load_module directives in the
// main context, in the order nginx loads them.
func nginxLoadModules(directives []nginx.Directive) []string {
	var paths []string
	for _, d := range directives {
		if d.Name == "load_module" && !d.IsBlock() && len(d.Args) > 0 {
			paths = append(paths, d.Args[0])
		}
	}
	return paths
}

// reNginxVersion matches "nginx version: nginx/1.25.3" or "nginx/1.25.3".
var reNginxVersion = regexp.MustCompile(`nginx/(\S+)`)

// reNginxModule matches the module flags in configure arguments:
// --with-<name>_module, plus --with-stream and --with-mail, which name no
// _module suffix, each optionally built as a dynamic module with =dynamic.
var reNginxModule = regexp.MustCompile(`--with-([A-Za-z0-9_]+_module|stream|mail)(=dynamic)?(?:\s|$)`)

// reNginxConfPath matches the configuration path nginx was built with.
var reNginxConfPath = regexp.MustCompile(`--conf-path=(\S+)`)

// nginxConfigureModule is a module named in nginx's configure arguments.
type nginxConfigureModule struct {
	name    string
	dynamic bool
}

// parseNginxConfigureModules extracts the modules and the --conf-path from
// nginx -V output. --with-stream and --with-mail are reported as
// stream_module and mail_module, the names of their ngx_*_module.so files.
func parseNginxConfigureModules(output string) ([]nginxConfigureModule, string) {
	matches := reNginxModule.FindAllStringSubmatch(output, -1)
	modules := make([]nginxConfigureModule, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if name == "stream" || name == "mail" {
			name += "_module"
		}
		modules = append(modules, nginxConfigureModule{name: name, dynamic: m[2] != ""})
	}
	confPath := ""
	if m := reNginxConfPath.FindStringSubmatch(output); m != nil {
		confPath = strings.Trim(m[1], `'"`)
	}
	return modules, confPath
}

// nginxDynamicModuleFiles names the ngx_*.so file of a dynamic module whose
// file name differs from its configure flag.
var nginxDynamicModuleFiles = map[string]string{
	"http_xslt_module": "http_xslt_filter_module",
}

// nginxDynamicModuleFlags is nginxDynamicModuleFiles reversed: the module
// name of an ngx_*.so file.
var nginxDynamicModuleFlags = func() map[string]string {
	m := make(map[string]string, len(nginxDynamicModuleFiles))
	for flag, file := range nginxDynamicModuleFiles {
		m[file] = flag
	}
	return m
}()

// nginxModules returns the modules nginx runs with: every module compiled
// into the binary, each dynamic module whose ngx_<name>.so file one of the
// loaded paths names, and each loaded module the configure arguments do not
// name (built out of tree). When stream or mail is dynamic, their stream_*
// and mail_* submodules are built into that .so and run only when it is
// loaded.
func nginxModules(configured []nginxConfigureModule, loaded []string) []string {
	loadedSet := map[string]bool{}
	var loadedNames []string
	for _, path := range loaded {
		name := filepath.Base(strings.Trim(path, `'"`))
		name = strings.TrimSuffix(name, ".so")
		name = strings.TrimPrefix(name, "ngx_")
		if !loadedSet[name] {
			loadedSet[name] = true
			loadedNames = append(loadedNames, name)
		}
	}
	isLoaded := func(name string) bool {
		if file, ok := nginxDynamicModuleFiles[name]; ok {
			name = file
		}
		return loadedSet[name]
	}

	dynamicParent := map[string]bool{}
	for _, m := range configured {
		if m.dynamic && (m.name == "stream_module" || m.name == "mail_module") {
			dynamicParent[strings.TrimSuffix(m.name, "module")] = true
		}
	}

	modules := make([]string, 0, len(configured))
	for _, m := range configured {
		switch {
		case m.dynamic:
			if !isLoaded(m.name) {
				continue
			}
		case dynamicParent["stream_"] && strings.HasPrefix(m.name, "stream_"):
			if !isLoaded("stream_module") {
				continue
			}
		case dynamicParent["mail_"] && strings.HasPrefix(m.name, "mail_"):
			if !isLoaded("mail_module") {
				continue
			}
		}
		modules = append(modules, m.name)
	}

	listed := map[string]bool{}
	for _, m := range modules {
		listed[m] = true
		if file, ok := nginxDynamicModuleFiles[m]; ok {
			listed[file] = true
		}
	}
	for _, name := range loadedNames {
		if listed[name] {
			continue
		}
		if flag, ok := nginxDynamicModuleFlags[name]; ok {
			if listed[flag] {
				continue
			}
			name = flag
		}
		listed[name] = true
		modules = append(modules, name)
	}
	return modules
}

type mqlNginxConfInternal struct {
	lock sync.Mutex
	// loadModules holds the load_module paths of the main context
	loadModules []string
}

// nginxConfPaths maps platform names to their default nginx config location.
var nginxConfPaths = map[string]string{
	"freebsd":      "/usr/local/etc/nginx/nginx.conf",
	"dragonflybsd": "/usr/local/etc/nginx/nginx.conf",
	"openbsd":      "/etc/nginx/nginx.conf",
	"netbsd":       "/usr/pkg/etc/nginx/nginx.conf",
}

const defaultNginxConf = "/etc/nginx/nginx.conf"

// nginxPidFiles are the pid files to try after the one the configuration and
// the build name: the location every Linux distribution package uses, and its
// older spelling.
var nginxPidFiles = []string{"/run/nginx.pid", "/var/run/nginx.pid"}

type mqlNginxInternal struct {
	launchOnce sync.Once
	launch     nginxLaunch
}

// nginxLaunch is the configuration nginx runs with.
type nginxLaunch struct {
	// conf is the configuration file nginx loads.
	conf string
	// globals are the -g directives of the running master, which nginx reads
	// as part of the main context of conf.
	globals string
}

// launchInfo returns the configuration nginx runs with, worked out once.
func (n *mqlNginx) launchInfo() nginxLaunch {
	n.launchOnce.Do(func() {
		conn := n.MqlRuntime.Connection.(shared.Connection)
		n.launch = resolveNginxLaunch(&afero.Afero{Fs: conn.FileSystem()}, func(bin string) string {
			return nginxBuildOutput(conn, bin)
		}, nginxConfPath(conn))
	})
	return n.launch
}

// nginxBuildOutput returns the output of `<bin> -V`, or "" when it can't run.
func nginxBuildOutput(conn shared.Connection, bin string) string {
	cmd, err := conn.RunCommand(shellQuote(bin) + " -V 2>&1")
	if err != nil || cmd.ExitStatus != 0 {
		return ""
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return ""
	}
	return string(data)
}

// resolveNginxLaunch works out the configuration nginx runs with. A running
// master's command line wins: its -c, or the conf path its binary was built
// with, resolved against its -p prefix, plus its -g directives. Without a
// running master it is the conf path of the nginx binary on the PATH, and
// without that the platform default. buildOutput returns `<bin> -V` output.
func resolveNginxLaunch(afs *afero.Afero, buildOutput func(bin string) string, platformDefault string) nginxLaunch {
	build, built := nginx.ParseBuildInfo(buildOutput("nginx"))

	conf := platformDefault
	if built {
		conf = nginx.ConfFile(nginx.LaunchArgs{}, build)
	}

	// The pid directive of the configuration names the pid file; without one
	// it is the build's, and the distribution packages all use /run/nginx.pid.
	var pidFiles []string
	if p := nginxPidDirective(afs, conf); p != "" {
		pidFiles = append(pidFiles, p)
	}
	if built {
		pidFiles = append(pidFiles, nginx.FullPath(build.PidPath, nginx.LaunchArgs{}, build))
	}
	pidFiles = append(pidFiles, nginxPidFiles...)

	la, running := nginxMasterArgs(afs, pidFiles)
	if !running {
		return nginxLaunch{conf: conf}
	}

	// The master may run another binary than the one on the PATH, built
	// with other paths.
	if path.IsAbs(la.Binary) {
		if b, ok := nginx.ParseBuildInfo(buildOutput(la.Binary)); ok {
			build, built = b, true
		}
	}
	switch {
	case built:
		conf = nginx.ConfFile(la, build)
	case la.Conf != "":
		conf = nginx.FullPath(la.Conf, la, nginx.BuildInfo{Prefix: "/"})
	}
	return nginxLaunch{conf: conf, globals: la.Globals}
}

// nginxPidDirective returns the pid directive of the main context of the
// configuration file at confPath, or "" when it has none or can't be read.
// A relative pid path is left out, since its prefix is not known here.
func nginxPidDirective(afs *afero.Afero, confPath string) string {
	data, err := afs.ReadFile(confPath)
	if err != nil {
		return ""
	}
	directives, _ := nginx.Parse(string(data))
	pid := ""
	for _, d := range directives {
		if d.Name == "pid" && !d.IsBlock() && len(d.Args) == 1 {
			pid = d.Args[0]
		}
	}
	if !path.IsAbs(pid) {
		return ""
	}
	return pid
}

// nginxMasterArgs reads the command line of the nginx master whose pid is in
// the first of pidFiles that names a running nginx. running is false when
// none does.
func nginxMasterArgs(afs *afero.Afero, pidFiles []string) (nginx.LaunchArgs, bool) {
	seen := map[string]bool{}
	for _, pidFile := range pidFiles {
		if seen[pidFile] {
			continue
		}
		seen[pidFile] = true
		data, err := afs.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(data))
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := afs.ReadFile(path.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		if la, ok := nginx.ParseProcCmdline(raw); ok {
			return la, true
		}
	}
	return nginx.LaunchArgs{}, false
}

// nginxGlobalDirectives returns the -g directives nginx reads as part of the
// main context of the configuration file at confPath: those of the running
// master when confPath is the file it loads, otherwise none.
func nginxGlobalDirectives(launch nginxLaunch, confPath string) []nginx.Directive {
	if launch.globals == "" || launch.conf != confPath {
		return nil
	}
	directives, _ := nginx.Parse(launch.globals)
	return directives
}

// nginxResource returns the nginx resource, which knows the binary and the
// command line nginx runs with.
func (s *mqlNginxConf) nginxResource() (*mqlNginx, error) {
	o, err := NewResource(s.MqlRuntime, "nginx", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return o.(*mqlNginx), nil
}

func nginxConfPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := nginxConfPaths[asset.Platform.Name]; ok {
			return p
		}
		for _, family := range asset.Platform.Family {
			if p, ok := nginxConfPaths[family]; ok {
				return p
			}
		}
	}
	return defaultNginxConf
}

func initNginxConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in nginx.conf initialization, it must be a string")
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

func (s *mqlNginxConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return file.Data.Path.Data, nil
}

func (s *mqlNginxConf) file() (*mqlFile, error) {
	nx, err := s.nginxResource()
	if err != nil {
		return nil, err
	}
	path := nx.launchInfo().conf

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// reNginxGlob detects filepath glob meta-characters.
var reNginxGlob = regexp.MustCompile(`[*?\[]`)

// expandNginxGlob walks the connection's filesystem to expand an include
// pattern. Matches afero-backed layouts (including serialized asset
// snapshots) — filepath.Glob cannot be used because it hits the host FS.
func (s *mqlNginxConf) expandNginxGlob(pattern string) ([]string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	if !reNginxGlob.MatchString(pattern) {
		return []string{pattern}, nil
	}

	var paths []string
	segments := strings.Split(pattern, "/")
	if segments[0] == "" {
		paths = []string{"/"}
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, segment := range segments[1:] {
		if !reNginxGlob.MatchString(segment) {
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

// parse is the central method that invokes the nginx parser, then walks
// the resulting directive tree to populate all fields.
func (s *mqlNginxConf) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.Params.State == plugin.StateIsSet {
		return nil
	}

	if file == nil {
		return errors.New("no base nginx config file to read")
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := conn.FileSystem()

	openFn := func(path string) (io.ReadCloser, error) {
		return afs.Open(path)
	}
	globFn := func(pattern string) ([]string, error) {
		return s.expandNginxGlob(pattern)
	}

	cfg, err := nginx.ParseFiles(file.Path.Data, openFn, globFn)
	if err != nil {
		errSlice := plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		errMap := plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Params = errMap
		s.HttpParams = errMap
		s.StreamParams = errMap
		s.Servers = errSlice
		s.Upstreams = errSlice
		s.StreamServers = errSlice
		s.StreamUpstreams = errSlice
		s.ListenAddresses = errSlice
		s.Files = errSlice
		return err
	}

	directives := cfg.Directives
	if nx, err := s.nginxResource(); err == nil {
		directives = append(nginxGlobalDirectives(nx.launchInfo(), file.Path.Data), directives...)
	}

	w := walkNginxConfig(directives, nginxDefaultSSLProtocols(s.nginxVersion(), nginxRedHatTLS13Default(conn.Asset().GetPlatform())))
	s.loadModules = nginxLoadModules(directives)

	s.Params = plugin.TValue[map[string]any]{Data: w.params, State: plugin.StateIsSet}
	s.HttpParams = plugin.TValue[map[string]any]{Data: w.httpParams, State: plugin.StateIsSet}
	s.StreamParams = plugin.TValue[map[string]any]{Data: w.streamParams, State: plugin.StateIsSet}

	serverResources, err := nginxServers2Resources(w.servers, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.Servers = plugin.TValue[[]any]{Data: serverResources, State: plugin.StateIsSet}

	upstreamResources, err := nginxUpstreams2Resources(w.upstreams, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.Upstreams = plugin.TValue[[]any]{Data: upstreamResources, State: plugin.StateIsSet}

	// Stream resources take a distinct owner ID: server IDs are built from a
	// positional index and upstream IDs from the pool name, both of which
	// restart inside stream{} and would otherwise collide with their http{}
	// counterparts in the resource cache.
	streamOwnerID := s.__id + "/stream"

	streamServerResources, err := nginxServers2Resources(w.streamServers, s.MqlRuntime, streamOwnerID)
	if err != nil {
		return err
	}
	s.StreamServers = plugin.TValue[[]any]{Data: streamServerResources, State: plugin.StateIsSet}

	streamUpstreamResources, err := nginxUpstreams2Resources(w.streamUpstreams, s.MqlRuntime, streamOwnerID)
	if err != nil {
		return err
	}
	s.StreamUpstreams = plugin.TValue[[]any]{Data: streamUpstreamResources, State: plugin.StateIsSet}

	// Deduplicate listen addresses in first-seen order.
	seen := map[string]bool{}
	var uniqueAddrs []any
	for _, addr := range w.listenAddrs {
		if !seen[addr] {
			seen[addr] = true
			uniqueAddrs = append(uniqueAddrs, addr)
		}
	}
	s.ListenAddresses = plugin.TValue[[]any]{Data: uniqueAddrs, State: plugin.StateIsSet}

	// Build file resources for every file visited by the parser.
	fileResources := make([]any, 0, len(cfg.Files))
	for _, path := range cfg.Files {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return err
		}
		fileResources = append(fileResources, f)
	}
	s.Files = plugin.TValue[[]any]{Data: fileResources, State: plugin.StateIsSet}

	return nil
}

// nginxVersion returns the version of the nginx binary, or "" when it is not
// known.
func (s *mqlNginxConf) nginxVersion() string {
	nx, err := s.nginxResource()
	if err != nil {
		return ""
	}
	v := nx.GetVersion()
	if v.Error != nil || v.IsNull() {
		return ""
	}
	return v.Data
}

// nginxWalk is the parsed configuration before it becomes resources.
type nginxWalk struct {
	params          map[string]any
	httpParams      map[string]any
	streamParams    map[string]any
	servers         []nginxServer
	upstreams       []nginxUpstream
	streamServers   []nginxServer
	streamUpstreams []nginxUpstream
	listenAddrs     []string
}

// walkNginxConfig turns the top-level directives of a configuration (includes
// expanded) into params, servers and upstreams. The typed fields of each
// server and location report what nginx runs with: the directives the block
// sets, those it inherits from the blocks around it, and nginx's defaults
// (sslProtocols, from nginxDefaultSSLProtocols, when ssl_protocols is unset).
func walkNginxConfig(directives []nginx.Directive, sslProtocols string) nginxWalk {
	mainParams := map[string]any{}
	w := nginxWalk{
		httpParams:   map[string]any{},
		streamParams: map[string]any{},
	}
	var httpScope, streamScope nginxScope

	for _, d := range directives {
		switch d.Name {
		case "http":
			httpScope = nginxBlockScope(d.Block)
			walkHTTPBlock(d.Block, w.httpParams, &w.servers, &w.upstreams, &w.listenAddrs)
		case "stream":
			streamScope = nginxBlockScope(d.Block)
			walkStreamBlock(d.Block, w.streamParams, &w.streamServers, &w.streamUpstreams)
		case "events":
			for _, ed := range d.Block {
				if !ed.IsBlock() {
					setNginxParam(mainParams, ed.Name, strings.Join(ed.Args, " "))
				}
			}
		default:
			if !d.IsBlock() {
				setNginxParam(mainParams, d.Name, strings.Join(d.Args, " "))
			}
		}
	}

	for i := range w.servers {
		resolveNginxServer(&w.servers[i], httpScope, sslProtocols, true)
	}
	for i := range w.streamServers {
		resolveNginxServer(&w.streamServers[i], streamScope, sslProtocols, false)
	}

	// Merge main + http params for the top-level params field.
	w.params = make(map[string]any, len(mainParams)+len(w.httpParams))
	for k, v := range mainParams {
		w.params[k] = v
	}
	for k, v := range w.httpParams {
		w.params[k] = v
	}
	return w
}

// nginxInheritedDirectives are the directives a server{} block takes from the
// http{} or stream{} block around it, and a location{} block from its
// server{}, when it does not set them itself. add_header is inherited as a
// whole, see nginxScope.child.
var nginxInheritedDirectives = map[string]bool{
	"ssl_protocols":             true,
	"ssl_ciphers":               true,
	"ssl_prefer_server_ciphers": true,
	"ssl_session_tickets":       true,
	"ssl_session_timeout":       true,
	"ssl_certificate":           true,
	"ssl_certificate_key":       true,
	"server_tokens":             true,
	"root":                      true,
	"add_header_inherit":        true,
}

// nginxScope holds the directives of one block that nested blocks inherit.
type nginxScope struct {
	// values holds the last value of each of nginxInheritedDirectives the
	// block sets.
	values map[string]string
	// addHeaders holds the block's add_header directives (name -> values),
	// nil when it has none.
	addHeaders map[string][]string
}

// nginxBlockScope collects the inheritable directives a block sets itself.
func nginxBlockScope(directives []nginx.Directive) nginxScope {
	sc := nginxScope{values: map[string]string{}}
	for _, d := range directives {
		if d.IsBlock() {
			continue
		}
		if nginxInheritedDirectives[d.Name] {
			sc.values[d.Name] = strings.Join(d.Args, " ")
		}
		if d.Name == "add_header" {
			if sc.addHeaders == nil {
				sc.addHeaders = map[string][]string{}
			}
			if len(d.Args) >= 2 {
				sc.addHeaders[d.Args[0]] = append(sc.addHeaders[d.Args[0]], nginxAddHeaderValue(d.Args))
			}
		}
	}
	return sc
}

// child returns the effective scope of a block nested in parent that sets
// the directives in own. A directive own sets replaces the parent's. The
// add_header directives are inherited only when own has none, unless
// add_header_inherit (nginx 1.29.3) says off (never inherit) or merge
// (the parent's come first, then own's).
func (parent nginxScope) child(own nginxScope) nginxScope {
	eff := nginxScope{values: make(map[string]string, len(parent.values)+len(own.values))}
	for k, v := range parent.values {
		eff.values[k] = v
	}
	for k, v := range own.values {
		eff.values[k] = v
	}

	switch eff.values["add_header_inherit"] {
	case "off":
		eff.addHeaders = own.addHeaders
	case "merge":
		if parent.addHeaders != nil || own.addHeaders != nil {
			eff.addHeaders = map[string][]string{}
		}
		for k, v := range parent.addHeaders {
			eff.addHeaders[k] = append(eff.addHeaders[k], v...)
		}
		for k, v := range own.addHeaders {
			eff.addHeaders[k] = append(eff.addHeaders[k], v...)
		}
	default:
		eff.addHeaders = own.addHeaders
		if eff.addHeaders == nil {
			eff.addHeaders = parent.addHeaders
		}
	}
	return eff
}

// resolveNginxServer sets the typed fields of a server{} block and its
// location{} blocks to what nginx runs with: the block's own directives,
// then those of parent (the http{} or stream{} block), then nginx's
// defaults. params keeps the directives written in the block. ssl stays
// what the block itself says, since an ssl_certificate inherited from
// http{} does not make a plain-HTTP listener serve TLS. http is false for
// a stream server, which has no server_tokens, root or add_header.
func resolveNginxServer(srv *nginxServer, parent nginxScope, defaultSSLProtocols string, http bool) {
	eff := parent.child(srv.scope)
	v := eff.values

	srv.SSLProtocols = nginxValueOr(v, "ssl_protocols", defaultSSLProtocols)
	srv.SSLCiphers = v["ssl_ciphers"]
	srv.SSLCertificate = v["ssl_certificate"]
	srv.SSLCertificateKey = v["ssl_certificate_key"]
	srv.SSLPreferServerCiphers = strings.EqualFold(nginxValueOr(v, "ssl_prefer_server_ciphers", "off"), "on")
	srv.SSLSessionTickets = nginxValueOr(v, "ssl_session_tickets", "on")
	srv.SSLSessionTimeout = nginxValueOr(v, "ssl_session_timeout", "5m")
	if !http {
		return
	}
	srv.ServerTokens = nginxValueOr(v, "server_tokens", "on")
	srv.Root = v["root"]
	srv.AddHeaders = map[string][]string{}
	for k, vals := range eff.addHeaders {
		srv.AddHeaders[k] = append([]string(nil), vals...)
	}
	for i := range srv.Locations {
		loc := &srv.Locations[i]
		loc.Root = eff.child(loc.scope).values["root"]
	}
}

func nginxValueOr(values map[string]string, name, def string) string {
	if v, ok := values[name]; ok && v != "" {
		return v
	}
	return def
}

// nginxAddHeaderValue returns the value of `add_header NAME VALUE [always]`.
// always says the header is sent with every response code; it is not part
// of the value.
func nginxAddHeaderValue(args []string) string {
	if len(args) >= 3 && args[len(args)-1] == "always" {
		return strings.Join(args[1:len(args)-1], " ")
	}
	return strings.Join(args[1:], " ")
}

// nginxRedHatTLS13Default reports a platform whose nginx package Red Hat
// patched to enable TLSv1.3 by default ("enable TLS 1.3 by default
// (#1643647)"): RHEL 8 and 9 and their rebuilds. EPEL's nginx for RHEL 7
// has no such patch, and Fedora and Amazon Linux build their own packages.
func nginxRedHatTLS13Default(p *inventory.Platform) bool {
	if p == nil || !p.IsFamily("redhat") {
		return false
	}
	switch p.Name {
	case "fedora", "amazonlinux":
		return false
	}
	major, _, _ := strings.Cut(p.Version, ".")
	n, err := strconv.Atoi(major)
	return err == nil && n >= 8
}

// nginxDefaultSSLProtocols returns the protocols nginx enables when the
// configuration sets no ssl_protocols (src/http/modules/ngx_http_ssl_module.c
// and the stream counterpart). 1.9.1 disabled SSLv3, 1.23.4 enabled TLSv1.3,
// and 1.27.3 disabled TLSv1 and TLSv1.1. redHatTLS13 adds TLSv1.3 from 1.13.0
// on, which first knew it, for Red Hat's patched builds (see
// nginxRedHatTLS13Default). When the version is not known this returns every
// protocol a release from 1.9.1 on may enable, so a check that an old
// protocol is off does not pass on a guess.
func nginxDefaultSSLProtocols(version string, redHatTLS13 bool) string {
	const unknown = "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
	v, ok := parseNginxVersion(version)
	if !ok {
		return unknown
	}
	switch {
	case nginxVersionLess(v, [3]int{1, 9, 1}):
		return "SSLv3 TLSv1 TLSv1.1 TLSv1.2"
	case nginxVersionLess(v, [3]int{1, 23, 4}):
		if redHatTLS13 && !nginxVersionLess(v, [3]int{1, 13, 0}) {
			return "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
		}
		return "TLSv1 TLSv1.1 TLSv1.2"
	case nginxVersionLess(v, [3]int{1, 27, 3}):
		return "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"
	default:
		return "TLSv1.2 TLSv1.3"
	}
}

// parseNginxVersion reads "major.minor.patch" from the start of version.
func parseNginxVersion(version string) ([3]int, bool) {
	var v [3]int
	parts := strings.SplitN(strings.TrimSpace(version), ".", 3)
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			return v, false
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func nginxVersionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Field methods — all delegate to parse().

func (s *mqlNginxConf) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) httpParams(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) servers(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) upstreams(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) streamParams(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) streamServers(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) streamUpstreams(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlNginxConf) listenAddresses(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

// Derived fields from params.

func (s *mqlNginxConf) user(params map[string]any) (string, error) {
	if v, ok := params["user"]; ok {
		if str, ok := v.(string); ok {
			return str, nil
		}
	}
	return "", nil
}

// workerProcesses reports 1, nginx's default, when worker_processes is unset.
func (s *mqlNginxConf) workerProcesses(params map[string]any) (string, error) {
	if v, ok := params["worker_processes"]; ok {
		if str, ok := v.(string); ok && str != "" {
			return str, nil
		}
	}
	return "1", nil
}

func (s *mqlNginxConf) errorLog(params map[string]any) (string, error) {
	if v, ok := params["error_log"]; ok {
		if str, ok := v.(string); ok {
			return str, nil
		}
	}
	return "", nil
}

// Internal types for collecting parsed data before converting to MQL resources.

type nginxServer struct {
	ServerName             string
	Listen                 string
	Listens                []nginxListen
	Root                   string
	SSL                    bool
	SSLProtocols           string
	SSLCiphers             string
	SSLCertificate         string
	SSLCertificateKey      string
	SSLPreferServerCiphers bool
	SSLSessionTickets      string
	SSLSessionTimeout      string
	AddHeaders             map[string][]string // collected from `add_header NAME VALUE [...flags]`
	ServerTokens           string
	Locations              []nginxLocation
	Params                 map[string]any
	// scope holds the inheritable directives the block sets itself.
	scope nginxScope
}

// nginxListen is a parsed `listen` directive.
type nginxListen struct {
	Raw           string // original argument string
	Address       string // optional address part (e.g. "127.0.0.1" or "[::]")
	Port          int64  // numeric port; 0 if the directive used a unix:/path target
	SSL           bool   // `ssl` flag present
	HTTP2         bool   // `http2` flag present
	UDP           bool   // `udp` flag present (stream listeners only)
	DefaultServer bool   // `default_server` flag present
	ProxyProtocol bool   // `proxy_protocol` flag present
}

type nginxUpstream struct {
	Name                string
	Servers             []string
	ServerDetails       []nginxUpstreamServer
	LoadBalancingMethod string
	Keepalive           int64
	Params              map[string]any
}

// nginxUpstreamServer is a parsed `server` directive inside an upstream{} block.
type nginxUpstreamServer struct {
	Address     string
	Weight      int64
	MaxFails    int64
	FailTimeout string
	Backup      bool
	Down        bool
	SlowStart   string
	Route       string
}

type nginxLocation struct {
	Path        string
	Modifier    string
	ProxyPass   string
	Root        string
	TryFiles    string
	Return      string
	FastcgiPass string
	Params      map[string]any
	// scope holds the inheritable directives the block sets itself.
	scope nginxScope
}

// walkHTTPBlock processes the http{} block's directives.
func walkHTTPBlock(directives []nginx.Directive, httpParams map[string]any, servers *[]nginxServer, upstreams *[]nginxUpstream, listenAddrs *[]string) {
	for _, d := range directives {
		switch d.Name {
		case "server":
			srv := parseNginxServerBlock(d.Block)
			*servers = append(*servers, srv)
			if srv.Listen != "" {
				for _, l := range strings.Split(srv.Listen, ",") {
					*listenAddrs = append(*listenAddrs, strings.TrimSpace(l))
				}
			}
		case "upstream":
			name := ""
			if len(d.Args) > 0 {
				name = d.Args[0]
			}
			up := parseNginxUpstreamBlock(name, d.Block)
			*upstreams = append(*upstreams, up)
		default:
			if !d.IsBlock() {
				setNginxParam(httpParams, d.Name, strings.Join(d.Args, " "))
			}
		}
	}
}

// walkStreamBlock processes the stream{} block's directives. A stream server
// proxies TCP or UDP rather than HTTP, but the block's grammar is identical to
// http{} — flat directives, server{}, and upstream{} — so the same walker
// handles both. Stream listeners are deliberately kept out of listenAddresses,
// which reports the http server blocks.
func walkStreamBlock(directives []nginx.Directive, streamParams map[string]any, servers *[]nginxServer, upstreams *[]nginxUpstream) {
	var listenAddrs []string
	walkHTTPBlock(directives, streamParams, servers, upstreams, &listenAddrs)
}

// parseNginxServerBlock extracts structured data from a server{} block.
func parseNginxServerBlock(directives []nginx.Directive) nginxServer {
	srv := nginxServer{
		Params:     map[string]any{},
		AddHeaders: map[string][]string{},
	}

	var listens []string
	for _, d := range directives {
		args := strings.Join(d.Args, " ")

		switch d.Name {
		case "server_name":
			srv.ServerName = args
			setNginxParam(srv.Params, d.Name, args)
		case "listen":
			listens = append(listens, args)
			l := parseNginxListen(d.Args)
			srv.Listens = append(srv.Listens, l)
			if l.SSL {
				srv.SSL = true
			}
			setNginxParam(srv.Params, d.Name, args)
		case "root":
			srv.Root = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_certificate":
			srv.SSL = true
			srv.SSLCertificate = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_certificate_key":
			srv.SSLCertificateKey = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_protocols":
			srv.SSLProtocols = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_ciphers":
			srv.SSLCiphers = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_prefer_server_ciphers":
			srv.SSLPreferServerCiphers = strings.EqualFold(args, "on")
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_session_tickets":
			srv.SSLSessionTickets = args
			setNginxParam(srv.Params, d.Name, args)
		case "ssl_session_timeout":
			srv.SSLSessionTimeout = args
			setNginxParam(srv.Params, d.Name, args)
		case "server_tokens":
			srv.ServerTokens = args
			setNginxParam(srv.Params, d.Name, args)
		case "add_header":
			if len(d.Args) >= 2 {
				name := d.Args[0]
				srv.AddHeaders[name] = append(srv.AddHeaders[name], nginxAddHeaderValue(d.Args))
			}
			setNginxParam(srv.Params, d.Name, args)
		case "location":
			loc := parseNginxLocationBlock(args, d.Block)
			srv.Locations = append(srv.Locations, loc)
		default:
			if !d.IsBlock() {
				setNginxParam(srv.Params, d.Name, args)
			}
		}
	}

	srv.Listen = strings.Join(listens, ",")
	srv.scope = nginxBlockScope(directives)
	return srv
}

// parseNginxListen breaks a `listen` directive's arguments into structured
// fields. Nginx accepts a wide variety of shapes; this handler covers the
// common ones used in audits: a bare port, an address:port, the
// `default_server` / `ssl` / `http2` / `proxy_protocol` flags, and
// `unix:/path` sockets (which produce port=0 with the path stored on Address).
func parseNginxListen(args []string) nginxListen {
	l := nginxListen{Raw: strings.Join(args, " ")}
	if len(args) == 0 {
		return l
	}
	// First positional arg is the listen target.
	addr := args[0]
	rest := args[1:]
	if strings.HasPrefix(addr, "unix:") {
		l.Address = addr
	} else if strings.HasPrefix(addr, "[") && strings.Contains(addr, "]") {
		// IPv6 form: [::]:443 or [::1]:443
		idx := strings.LastIndex(addr, "]")
		l.Address = addr[:idx+1]
		if idx+2 < len(addr) && addr[idx+1] == ':' {
			l.Port, _ = parsePort(addr[idx+2:])
		}
	} else if i := strings.LastIndex(addr, ":"); i >= 0 {
		l.Address = addr[:i]
		l.Port, _ = parsePort(addr[i+1:])
	} else {
		// Could be just a port number, or just an address.
		if p, ok := parsePort(addr); ok {
			l.Port = p
		} else {
			l.Address = addr
		}
	}
	for _, flag := range rest {
		switch flag {
		case "ssl":
			l.SSL = true
		case "http2":
			l.HTTP2 = true
		case "udp":
			l.UDP = true
		case "default_server", "default":
			l.DefaultServer = true
		case "proxy_protocol":
			l.ProxyProtocol = true
		}
	}
	return l
}

func parsePort(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}

// parseNginxLocationBlock extracts structured data from a location{} block.
// The `path` argument from the parent is the joined `args` string, which may
// include a leading modifier ("=", "~", "~*", "^~").
func parseNginxLocationBlock(path string, directives []nginx.Directive) nginxLocation {
	mod, p := splitLocationModifier(path)
	loc := nginxLocation{
		Path:     p,
		Modifier: mod,
		Params:   map[string]any{},
	}

	for _, d := range directives {
		if d.IsBlock() {
			continue
		}
		args := strings.Join(d.Args, " ")
		setNginxParam(loc.Params, d.Name, args)

		switch d.Name {
		case "proxy_pass":
			loc.ProxyPass = args
		case "root":
			loc.Root = args
		case "try_files":
			loc.TryFiles = args
		case "return":
			loc.Return = args
		case "fastcgi_pass":
			loc.FastcgiPass = args
		}
	}

	loc.scope = nginxBlockScope(directives)
	return loc
}

// splitLocationModifier separates a leading modifier from the path argument
// of a location{} block. nginx recognizes "=", "~", "~*", "^~"; anything
// else is treated as a prefix path with an empty modifier.
func splitLocationModifier(arg string) (string, string) {
	arg = strings.TrimSpace(arg)
	for _, m := range []string{"~*", "~", "^~", "="} {
		prefix := m + " "
		if strings.HasPrefix(arg, prefix) {
			return m, strings.TrimSpace(arg[len(prefix):])
		}
		if arg == m {
			return m, ""
		}
	}
	return "", arg
}

// parseNginxUpstreamBlock extracts structured data from an upstream{} block.
//
// In addition to the raw `server` directive arguments (kept for backward
// compatibility), this also parses the per-server suffix flags (weight,
// max_fails, fail_timeout, backup, down, slow_start, route) and the
// load-balancing method (least_conn, ip_hash, hash, random, least_time —
// otherwise "round_robin" by default).
func parseNginxUpstreamBlock(name string, directives []nginx.Directive) nginxUpstream {
	up := nginxUpstream{
		Name:                name,
		Params:              map[string]any{},
		LoadBalancingMethod: "round_robin",
	}

	for _, d := range directives {
		if d.IsBlock() {
			continue
		}
		args := strings.Join(d.Args, " ")
		switch d.Name {
		case "server":
			up.Servers = append(up.Servers, args)
			up.ServerDetails = append(up.ServerDetails, parseUpstreamServer(d.Args))
		case "least_conn":
			up.LoadBalancingMethod = "least_conn"
			setNginxParam(up.Params, d.Name, args)
		case "ip_hash":
			up.LoadBalancingMethod = "ip_hash"
			setNginxParam(up.Params, d.Name, args)
		case "hash":
			up.LoadBalancingMethod = "hash"
			setNginxParam(up.Params, d.Name, args)
		case "random":
			up.LoadBalancingMethod = "random"
			setNginxParam(up.Params, d.Name, args)
		case "least_time":
			up.LoadBalancingMethod = "least_time"
			setNginxParam(up.Params, d.Name, args)
		case "keepalive":
			// keepalive is a connection-count, not a TCP port — must not be
			// capped at 65535. High-traffic upstreams legitimately use
			// values like `keepalive 128` or higher.
			if n, err := strconv.ParseInt(args, 10, 64); err == nil && n >= 0 {
				up.Keepalive = n
			}
			setNginxParam(up.Params, d.Name, args)
		default:
			setNginxParam(up.Params, d.Name, args)
		}
	}

	return up
}

// parseUpstreamServer decodes the per-server flags on an upstream `server`
// directive: `server ADDRESS [weight=N] [max_fails=N] [fail_timeout=T] [backup] [down] [slow_start=T] [route=...]`.
func parseUpstreamServer(args []string) nginxUpstreamServer {
	s := nginxUpstreamServer{}
	if len(args) == 0 {
		return s
	}
	s.Address = args[0]
	for _, a := range args[1:] {
		switch {
		case a == "backup":
			s.Backup = true
		case a == "down":
			s.Down = true
		case strings.HasPrefix(a, "weight="):
			// weight is a count, not a port — no 65535 cap.
			if n, err := strconv.ParseInt(strings.TrimPrefix(a, "weight="), 10, 64); err == nil && n >= 0 {
				s.Weight = n
			}
		case strings.HasPrefix(a, "max_fails="):
			// max_fails is a count, not a port — no 65535 cap.
			if n, err := strconv.ParseInt(strings.TrimPrefix(a, "max_fails="), 10, 64); err == nil && n >= 0 {
				s.MaxFails = n
			}
		case strings.HasPrefix(a, "fail_timeout="):
			s.FailTimeout = strings.TrimPrefix(a, "fail_timeout=")
		case strings.HasPrefix(a, "slow_start="):
			s.SlowStart = strings.TrimPrefix(a, "slow_start=")
		case strings.HasPrefix(a, "route="):
			s.Route = strings.TrimPrefix(a, "route=")
		}
	}
	return s
}

// setNginxParam sets a directive value. For directives that can appear
// multiple times, values are comma-concatenated (matching the Apache pattern).
func setNginxParam(m map[string]any, key, value string) {
	if isNginxMultiParam[key] {
		if v, ok := m[key]; ok {
			m[key] = v.(string) + "," + value
			return
		}
	}
	m[key] = value
}

// isNginxMultiParam lists directives that can appear multiple times and should
// be concatenated rather than overwritten.
var isNginxMultiParam = map[string]bool{
	"listen":           true,
	"server_name":      true,
	"include":          true,
	"add_header":       true,
	"set":              true,
	"rewrite":          true,
	"allow":            true,
	"deny":             true,
	"fastcgi_param":    true,
	"proxy_set_header": true,
	// main context: RHEL and Debian load each dynamic module from its own
	// include file, and error_log and env may be given once per target
	"load_module": true,
	"error_log":   true,
	"env":         true,
}

// Resource conversion functions.

func nginxServers2Resources(servers []nginxServer, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(servers))
	for i, srv := range servers {
		id := fmt.Sprintf("%s/server/%d-%s-%s", ownerID, i, srv.ServerName, srv.Listen)

		locations, err := nginxLocations2Resources(srv.Locations, runtime, id)
		if err != nil {
			return nil, err
		}

		listens := make([]any, len(srv.Listens))
		for j, l := range srv.Listens {
			listens[j] = map[string]any{
				"raw":           l.Raw,
				"address":       l.Address,
				"port":          l.Port,
				"ssl":           l.SSL,
				"http2":         l.HTTP2,
				"udp":           l.UDP,
				"defaultServer": l.DefaultServer,
				"proxyProtocol": l.ProxyProtocol,
			}
		}

		addHeaders := make(map[string]any, len(srv.AddHeaders))
		for name, values := range srv.AddHeaders {
			addHeaders[name] = convert.SliceAnyToInterface(values)
		}

		obj, err := CreateResource(runtime, "nginx.conf.server", map[string]*llx.RawData{
			"__id":                   llx.StringData(id),
			"serverName":             llx.StringData(srv.ServerName),
			"listen":                 llx.StringData(srv.Listen),
			"listens":                llx.ArrayData(listens, types.Dict),
			"root":                   llx.StringData(srv.Root),
			"ssl":                    llx.BoolData(srv.SSL),
			"sslProtocols":           llx.StringData(srv.SSLProtocols),
			"sslCiphers":             llx.StringData(srv.SSLCiphers),
			"sslCertificate":         llx.StringData(srv.SSLCertificate),
			"sslCertificateKey":      llx.StringData(srv.SSLCertificateKey),
			"sslPreferServerCiphers": llx.BoolData(srv.SSLPreferServerCiphers),
			"sslSessionTickets":      llx.StringData(srv.SSLSessionTickets),
			"sslSessionTimeout":      llx.StringData(srv.SSLSessionTimeout),
			"addHeaders":             llx.MapData(addHeaders, types.Array(types.String)),
			"serverTokens":           llx.StringData(srv.ServerTokens),
			"locations":              llx.ArrayData(locations, types.Resource("nginx.conf.location")),
			"params":                 llx.MapData(srv.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func nginxUpstreams2Resources(upstreams []nginxUpstream, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(upstreams))
	for i, up := range upstreams {
		serversData := make([]any, len(up.Servers))
		for j, s := range up.Servers {
			serversData[j] = s
		}

		details := make([]any, len(up.ServerDetails))
		for j, d := range up.ServerDetails {
			details[j] = map[string]any{
				"address":     d.Address,
				"weight":      d.Weight,
				"maxFails":    d.MaxFails,
				"failTimeout": d.FailTimeout,
				"backup":      d.Backup,
				"down":        d.Down,
				"slowStart":   d.SlowStart,
				"route":       d.Route,
			}
		}

		obj, err := CreateResource(runtime, "nginx.conf.upstream", map[string]*llx.RawData{
			"__id":                llx.StringData(ownerID + "/upstream/" + up.Name),
			"name":                llx.StringData(up.Name),
			"servers":             llx.ArrayData(serversData, types.String),
			"serverDetails":       llx.ArrayData(details, types.Dict),
			"loadBalancingMethod": llx.StringData(up.LoadBalancingMethod),
			"keepalive":           llx.IntData(up.Keepalive),
			"params":              llx.MapData(up.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func nginxLocations2Resources(locations []nginxLocation, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(locations))
	for i, loc := range locations {
		obj, err := CreateResource(runtime, "nginx.conf.location", map[string]*llx.RawData{
			"__id":      llx.StringData(fmt.Sprintf("%s/location/%d-%s", ownerID, i, loc.Path)),
			"path":      llx.StringData(loc.Path),
			"modifier":  llx.StringData(loc.Modifier),
			"proxyPass": llx.StringData(loc.ProxyPass),
			"root":      llx.StringData(loc.Root),
			"tryFiles":  llx.StringData(loc.TryFiles),
			"return":    llx.StringData(loc.Return),
			// returnDirective duplicates return: the field name `return` is an
			// MQL keyword and gets eaten by the parser inside a block.
			"returnDirective": llx.StringData(loc.Return),
			"fastcgiPass":     llx.StringData(loc.FastcgiPass),
			"params":          llx.MapData(loc.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func (s *mqlNginxConfServer) certificate() ([]any, error) {
	path := s.SslCertificate.Data
	if path == "" {
		return []any{}, nil
	}
	return readCertificatesFromPath(s.MqlRuntime, path)
}

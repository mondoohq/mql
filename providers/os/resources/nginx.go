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
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/nginx"
	"go.mondoo.com/mql/v13/types"
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
		if v := scanBinaryForTag(afs, bin, nginxVersionTag); v != "" {
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

	modules := parseNginxModules(string(data))
	modulesData := make([]any, len(modules))
	for i, m := range modules {
		modulesData[i] = m
	}
	return modulesData, nil
}

// reNginxVersion matches "nginx version: nginx/1.25.3" or "nginx/1.25.3".
var reNginxVersion = regexp.MustCompile(`nginx/(\S+)`)

// reNginxModule matches --with-*_module flags in configure arguments.
var reNginxModule = regexp.MustCompile(`--with-(\S+_module)`)

// parseNginxModules extracts compiled-in module names from nginx -V output.
func parseNginxModules(output string) []string {
	matches := reNginxModule.FindAllStringSubmatch(output, -1)
	modules := make([]string, 0, len(matches))
	for _, m := range matches {
		modules = append(modules, m[1])
	}
	return modules
}

type mqlNginxConfInternal struct {
	lock sync.Mutex
}

// nginxConfPaths maps platform names to their default nginx config location.
var nginxConfPaths = map[string]string{
	"freebsd":      "/usr/local/etc/nginx/nginx.conf",
	"dragonflybsd": "/usr/local/etc/nginx/nginx.conf",
	"openbsd":      "/etc/nginx/nginx.conf",
	"netbsd":       "/usr/pkg/etc/nginx/nginx.conf",
}

const defaultNginxConf = "/etc/nginx/nginx.conf"

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
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := nginxConfPath(conn)

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

	mainParams := map[string]any{}
	httpParams := map[string]any{}
	streamParams := map[string]any{}
	var servers []nginxServer
	var upstreams []nginxUpstream
	var streamServers []nginxServer
	var streamUpstreams []nginxUpstream
	var allListenAddrs []string

	for _, d := range cfg.Directives {
		switch d.Name {
		case "http":
			walkHTTPBlock(d.Block, httpParams, &servers, &upstreams, &allListenAddrs)
		case "stream":
			walkStreamBlock(d.Block, streamParams, &streamServers, &streamUpstreams)
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

	// Merge main + http params for the top-level params field.
	mergedParams := make(map[string]any, len(mainParams)+len(httpParams))
	for k, v := range mainParams {
		mergedParams[k] = v
	}
	for k, v := range httpParams {
		mergedParams[k] = v
	}

	s.Params = plugin.TValue[map[string]any]{Data: mergedParams, State: plugin.StateIsSet}
	s.HttpParams = plugin.TValue[map[string]any]{Data: httpParams, State: plugin.StateIsSet}
	s.StreamParams = plugin.TValue[map[string]any]{Data: streamParams, State: plugin.StateIsSet}

	serverResources, err := nginxServers2Resources(servers, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.Servers = plugin.TValue[[]any]{Data: serverResources, State: plugin.StateIsSet}

	upstreamResources, err := nginxUpstreams2Resources(upstreams, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.Upstreams = plugin.TValue[[]any]{Data: upstreamResources, State: plugin.StateIsSet}

	// Stream resources take a distinct owner ID: server IDs are built from a
	// positional index and upstream IDs from the pool name, both of which
	// restart inside stream{} and would otherwise collide with their http{}
	// counterparts in the resource cache.
	streamOwnerID := s.__id + "/stream"

	streamServerResources, err := nginxServers2Resources(streamServers, s.MqlRuntime, streamOwnerID)
	if err != nil {
		return err
	}
	s.StreamServers = plugin.TValue[[]any]{Data: streamServerResources, State: plugin.StateIsSet}

	streamUpstreamResources, err := nginxUpstreams2Resources(streamUpstreams, s.MqlRuntime, streamOwnerID)
	if err != nil {
		return err
	}
	s.StreamUpstreams = plugin.TValue[[]any]{Data: streamUpstreamResources, State: plugin.StateIsSet}

	// Deduplicate listen addresses in first-seen order.
	seen := map[string]bool{}
	var uniqueAddrs []any
	for _, addr := range allListenAddrs {
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

func (s *mqlNginxConf) workerProcesses(params map[string]any) (string, error) {
	if v, ok := params["worker_processes"]; ok {
		if str, ok := v.(string); ok {
			return str, nil
		}
	}
	return "", nil
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
				value := strings.Join(d.Args[1:], " ")
				srv.AddHeaders[name] = append(srv.AddHeaders[name], value)
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

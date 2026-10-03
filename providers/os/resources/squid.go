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
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/providers/os/resources/squid"
	"go.mondoo.com/mql/providers/os/resources/systemd"
	"go.mondoo.com/mql/types"
)

func (s *mqlSquid) id() (string, error) {
	return "squid", nil
}

// squidVersionBinaries lists the well-known paths for the squid daemon
// binary. Like apache2/nginx, the version string is embedded as a
// constant ("Squid Cache: Version X.Y") so we can extract it by reading
// the file directly — no command execution required.
var squidVersionBinaries = []string{
	"/usr/sbin/squid",
	"/usr/local/sbin/squid",
	"/usr/local/squid/sbin/squid",
	"/opt/squid/sbin/squid",
}

// squidVersionCommands are tried as a fallback when the binary cannot be read.
var squidVersionCommands = []string{"squid", "squid3"}

var squidVersionTag = []byte("Squid Cache: Version ")

var reSquidVersion = regexp.MustCompile(`Squid Cache:\s+Version\s+(\S+)`)

func (s *mqlSquid) version() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, bin := range squidVersionBinaries {
		if v := scanBinaryForSquidVersion(afs, bin); v != "" {
			return v, nil
		}
	}

	for _, bin := range squidVersionCommands {
		cmd, err := conn.RunCommand(bin + " -v")
		if err != nil {
			continue
		}
		if cmd.ExitStatus != 0 {
			continue
		}
		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			continue
		}
		if m := reSquidVersion.FindSubmatch(data); m != nil {
			return string(m[1]), nil
		}
	}

	// Squid binary not found anywhere we looked. Return an empty string;
	// the runtime stores that as the field value. Setting StateIsNull and
	// then also returning a value is contradictory — the return value
	// always wins, so we just return the empty string.
	return "", nil
}

// scanBinaryForSquidVersion reads a file in chunks, finds the "Squid
// Cache: Version " tag, and grabs the dot-and-digit run that follows.
// Mirrors scanBinaryForTag in apache2.go but handles the slightly wider
// Squid version alphabet (digits, dots, dashes, letters — e.g.,
// "5.7-rc1").
func scanBinaryForSquidVersion(fs *afero.Afero, path string) string {
	f, err := fs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	tag := squidVersionTag
	return scanReaderForTag(f, tag, len(tag)+32, isSquidVersionByte, nil)
}

// isSquidVersionByte reports whether b belongs to a Squid version literal,
// whose alphabet is wider than the numeric Apache form (e.g. "5.7-rc1").
func isSquidVersionByte(b byte) bool {
	if b >= '0' && b <= '9' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	return b == '.' || b == '-' || b == '_' || b == '+'
}

type mqlSquidConfInternal struct {
	lock sync.Mutex
}

// squidConfByFamily maps platform families/names to their default
// squid.conf location. Lookup checks platform.Name first, then walks
// Family[].
var squidConfByFamily = map[string]string{
	"debian":      "/etc/squid/squid.conf",
	"redhat":      "/etc/squid/squid.conf",
	"suse":        "/etc/squid/squid.conf",
	"arch":        "/etc/squid/squid.conf",
	"alpine":      "/etc/squid/squid.conf",
	"amazonlinux": "/etc/squid/squid.conf",
	"gentoo":      "/etc/squid/squid.conf",
	"freebsd":     "/usr/local/etc/squid/squid.conf",
	"bsd":         "/usr/local/etc/squid/squid.conf",
}

const defaultSquidConf = "/etc/squid/squid.conf"

func squidConfPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := squidConfByFamily[asset.Platform.Name]; ok {
			return p
		}
		for _, family := range asset.Platform.Family {
			if p, ok := squidConfByFamily[family]; ok {
				return p
			}
		}
	}
	return defaultSquidConf
}

func initSquidConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in squid.conf initialization, it must be a string")
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

func (s *mqlSquidConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "squid.conf", nil
	}
	return file.Data.Path.Data, nil
}

// file is the default getter: try the platform-preferred squid.conf
// location and fall back to anything in our known-locations map.
func (s *mqlSquidConf) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	afs := &afero.Afero{Fs: conn.FileSystem()}

	// The -f squid is started with replaces its compiled-in default. A file
	// it names that does not exist would keep squid from starting, so it
	// says nothing about the server and the defaults are probed instead;
	// one this user cannot stat is still the right file, and reading it
	// reports the refusal.
	if p := squidLaunchConfig(s.MqlRuntime, afs); p != "" {
		if _, err := afs.Stat(p); err == nil || !errors.Is(err, os.ErrNotExist) {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(p),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	preferred := squidConfPath(conn)
	seen := map[string]bool{preferred: true}
	candidates := []string{preferred}
	for _, p := range squidConfByFamily {
		if !seen[p] {
			seen[p] = true
			candidates = append(candidates, p)
		}
	}

	for _, path := range candidates {
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

	// Squid likely not installed — mark set+null so downstream fields
	// return empty data instead of cascading file-not-found errors.
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// squidLaunch recognizes squid's master process. Its kids rename their
// command line to "(squid-1)", "(squid-coord-3)" and so on.
var squidLaunch = serverLaunchSpec{Names: []string{"squid"}}

// squidUnit starts squid on systemd hosts. RHEL's runs
// `squid --foreground $SQUID_OPTS -f ${SQUID_CONF}` with both from
// /etc/sysconfig/squid; Debian's and SUSE's pass no -f.
const squidUnit = "squid.service"

// squidLaunchConfig returns the configuration file squid is started with: the
// -f of the running master, or of the squid a scanned image starts, or else
// of the systemd unit's ExecStart= with its environment expanded. A relative
// path resolves against the server's working directory. It returns "" when
// squid reads its compiled-in default.
func squidLaunchConfig(runtime *plugin.Runtime, afs *afero.Afero) string {
	if launches := findServerLaunches(runtime, squidLaunch); len(launches) > 0 {
		// a running squid without -f reads its default, whatever the unit
		// says about the next start
		l := launches[0]
		return l.resolve(squid.ConfigFromArgs(l.Argv[1:]))
	}
	env, ok := systemd.ResolveUnitEnv(afs, squidUnit)
	if !ok || env.ExecStart == "" {
		return ""
	}
	argv := haproxy.ExpandSystemdCommand(env.ExecStart, env.Vars)
	if len(argv) == 0 || filepath.Base(argv[0]) != "squid" {
		return ""
	}
	return serverLaunch{}.resolve(squid.ConfigFromArgs(argv[1:]))
}

var reSquidGlob = regexp.MustCompile(`[*?\[]`)

// expandSquidGlob walks the connection's filesystem to expand an
// include pattern. We can't reach `filepath.Glob` because it operates
// on the host FS — the connection may be a remote SSH session or a
// captured asset snapshot served by afero.
func (s *mqlSquidConf) expandSquidGlob(pattern string) ([]string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	// Squid resolves relative include paths against its sysconfdir. We
	// don't try to discover that at runtime — instead we resolve against
	// the directory of the squid.conf file we found, which is correct
	// on every distro layout we ship for.
	if !filepath.IsAbs(pattern) {
		base := s.confDir()
		pattern = filepath.Join(base, pattern)
	}

	if !reSquidGlob.MatchString(pattern) {
		return []string{pattern}, nil
	}

	var paths []string
	segments := strings.Split(pattern, "/")
	if segments[0] == "" {
		paths = []string{"/"}
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, segment := range segments[1:] {
		if !reSquidGlob.MatchString(segment) {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], segment)
			}
			continue
		}
		var nuPaths []string
		for _, p := range paths {
			files, err := afs.ReadDir(p)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			for j := range files {
				name := files[j].Name()
				match, err := filepath.Match(segment, name)
				if err != nil {
					return nil, err
				}
				if match {
					nuPaths = append(nuPaths, filepath.Join(p, name))
				}
			}
		}
		paths = nuPaths
	}
	return paths, nil
}

func (s *mqlSquidConf) confDir() string {
	file := s.GetFile()
	if file.Error == nil && file.Data != nil {
		return filepath.Dir(file.Data.Path.Data)
	}
	conn := s.MqlRuntime.Connection.(shared.Connection)
	return filepath.Dir(squidConfPath(conn))
}

func (s *mqlSquidConf) setEmpty() {
	empty := plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}
	emptySlice := plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	emptyAuth := plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}

	s.Params = empty
	s.HttpPorts = emptySlice
	s.HttpsPorts = emptySlice
	s.Acls = emptySlice
	s.AccessRules = emptySlice
	s.CachePeers = emptySlice
	s.CacheDirs = emptySlice
	s.RefreshPatterns = emptySlice
	s.AuthParams = emptyAuth
	s.AccessLogs = emptySlice
	s.Files = emptySlice
}

func (s *mqlSquidConf) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.Params.State == plugin.StateIsSet {
		return nil
	}

	if file == nil {
		s.setEmpty()
		return nil
	}
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		s.setEmpty()
		return nil
	}

	filesIdx := map[string]*mqlFile{
		file.Path.Data: file,
	}

	fileContent := func(path string) (string, error) {
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

	globExpand := func(pattern string) ([]string, error) {
		return s.expandSquidGlob(pattern)
	}

	cfg, err := squid.ParseWithGlob(file.Path.Data, fileContent, globExpand)
	if err != nil {
		errSlice := plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		errMap := plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Params = errMap
		s.HttpPorts = errSlice
		s.HttpsPorts = errSlice
		s.Acls = errSlice
		s.AccessRules = errSlice
		s.CachePeers = errSlice
		s.CacheDirs = errSlice
		s.RefreshPatterns = errSlice
		s.AuthParams = errMap
		s.AccessLogs = errSlice
		s.Files = errSlice
		return err
	}

	params := make(map[string]any, len(cfg.Params))
	for k, v := range cfg.Params {
		params[k] = v
	}
	s.Params = plugin.TValue[map[string]any]{Data: params, State: plugin.StateIsSet}

	httpPorts, err := squidListens2Resources(cfg.HTTPPorts, s.MqlRuntime, s.__id, "http")
	if err != nil {
		return err
	}
	s.HttpPorts = plugin.TValue[[]any]{Data: httpPorts, State: plugin.StateIsSet}

	httpsPorts, err := squidListens2Resources(cfg.HTTPSPorts, s.MqlRuntime, s.__id, "https")
	if err != nil {
		return err
	}
	s.HttpsPorts = plugin.TValue[[]any]{Data: httpsPorts, State: plugin.StateIsSet}

	acls, err := squidACLs2Resources(cfg.ACLs, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.Acls = plugin.TValue[[]any]{Data: acls, State: plugin.StateIsSet}

	rules, err := squidAccessRules2Resources(cfg.AccessRules, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.AccessRules = plugin.TValue[[]any]{Data: rules, State: plugin.StateIsSet}

	peers, err := squidCachePeers2Resources(cfg.CachePeers, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.CachePeers = plugin.TValue[[]any]{Data: peers, State: plugin.StateIsSet}

	dirs, err := squidCacheDirs2Resources(cfg.CacheDirs, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.CacheDirs = plugin.TValue[[]any]{Data: dirs, State: plugin.StateIsSet}

	patterns, err := squidRefreshPatterns2Resources(cfg.RefreshPatterns, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.RefreshPatterns = plugin.TValue[[]any]{Data: patterns, State: plugin.StateIsSet}

	authParams := make(map[string]any, len(cfg.AuthParams))
	for scheme, kv := range cfg.AuthParams {
		inner := make(map[string]any, len(kv))
		for k, v := range kv {
			inner[k] = v
		}
		authParams[scheme] = inner
	}
	s.AuthParams = plugin.TValue[map[string]any]{Data: authParams, State: plugin.StateIsSet}

	logs, err := squidAccessLogs2Resources(cfg.AccessLogs, s.MqlRuntime, s.__id)
	if err != nil {
		return err
	}
	s.AccessLogs = plugin.TValue[[]any]{Data: logs, State: plugin.StateIsSet}

	files := make([]any, 0, len(filesIdx))
	for _, f := range filesIdx {
		files = append(files, f)
	}
	s.Files = plugin.TValue[[]any]{Data: files, State: plugin.StateIsSet}

	return nil
}

// Field accessors — all delegate to parse().

func (s *mqlSquidConf) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) httpPorts(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) httpsPorts(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) acls(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) accessRules(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) cachePeers(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) cacheDirs(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) refreshPatterns(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) authParams(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSquidConf) accessLogs(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

// Scalar derivations from the params map.

func (s *mqlSquidConf) visibleHostname(params map[string]any) (string, error) {
	return squidParamScalar(params, "visible_hostname"), nil
}

func (s *mqlSquidConf) uniqueHostname(params map[string]any) (string, error) {
	return squidParamScalar(params, "unique_hostname"), nil
}

func (s *mqlSquidConf) cacheLog(params map[string]any) (string, error) {
	return squidParamScalar(params, "cache_log"), nil
}

func (s *mqlSquidConf) cacheStoreLog(params map[string]any) (string, error) {
	return squidParamScalar(params, "cache_store_log"), nil
}

func (s *mqlSquidConf) pidFilename(params map[string]any) (string, error) {
	return squidParamScalar(params, "pid_filename"), nil
}

func (s *mqlSquidConf) coredumpDir(params map[string]any) (string, error) {
	return squidParamScalar(params, "coredump_dir"), nil
}

func (s *mqlSquidConf) via(params map[string]any) (string, error) {
	return squidParamScalar(params, "via"), nil
}

func (s *mqlSquidConf) forwardedFor(params map[string]any) (string, error) {
	return squidParamScalar(params, "forwarded_for"), nil
}

func (s *mqlSquidConf) httpdSuppressVersionString(params map[string]any) (string, error) {
	return squidParamScalar(params, "httpd_suppress_version_string"), nil
}

func (s *mqlSquidConf) dnsV4First(params map[string]any) (string, error) {
	return squidParamScalar(params, "dns_v4_first"), nil
}

func (s *mqlSquidConf) cacheMem(params map[string]any) (string, error) {
	return squidParamScalar(params, "cache_mem"), nil
}

func (s *mqlSquidConf) maximumObjectSize(params map[string]any) (string, error) {
	return squidParamScalar(params, "maximum_object_size"), nil
}

// squidParamScalar returns the first segment of the comma-joined value
// (matching the apacheParamScalar helper). Squid directives are
// case-sensitive, so a simple map lookup is enough.
func squidParamScalar(params map[string]any, name string) string {
	v, ok := params[name]
	if !ok {
		return ""
	}
	str, ok := v.(string)
	if !ok {
		return ""
	}
	if comma := strings.IndexByte(str, ','); comma >= 0 {
		return strings.TrimSpace(str[:comma])
	}
	return str
}

// certificates aggregates the X.509 certificates referenced by every
// http_port / https_port entry that carries a cert= or tls-cert= path.
// Files that are unreadable contribute zero certs (matching the apache
// and nginx behavior) so a misconfigured path doesn't blow up the audit.
func (s *mqlSquidConf) certificates() ([]any, error) {
	if err := s.parse(s.GetFile().Data); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var paths []string
	for _, list := range [][]any{s.HttpPorts.Data, s.HttpsPorts.Data} {
		for _, raw := range list {
			l, ok := raw.(*mqlSquidConfListen)
			if !ok {
				continue
			}
			p := l.Cert.Data
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			paths = append(paths, p)
		}
	}
	var out []any
	for _, p := range paths {
		certs, err := readCertificatesFromPath(s.MqlRuntime, p)
		if err != nil {
			continue
		}
		out = append(out, certs...)
	}
	if out == nil {
		out = []any{}
	}
	return out, nil
}

// ----------------------------------------------------------------------
// Resource conversion helpers
// ----------------------------------------------------------------------

func squidListens2Resources(listens []squid.Listen, runtime *plugin.Runtime, ownerID, kind string) ([]any, error) {
	res := make([]any, len(listens))
	for i, l := range listens {
		flags := convert.SliceAnyToInterface(l.Flags)
		options := make(map[string]any, len(l.Options))
		for k, v := range l.Options {
			options[k] = v
		}
		obj, err := CreateResource(runtime, "squid.conf.listen", map[string]*llx.RawData{
			"__id":      llx.StringData(fmt.Sprintf("%s/%s/%d-%s-%d", ownerID, kind, i, l.Address, l.Port)),
			"directive": llx.StringData(l.Directive),
			"address":   llx.StringData(l.Address),
			"port":      llx.IntData(l.Port),
			"tls":       llx.BoolData(l.TLS),
			"flags":     llx.ArrayData(flags, types.String),
			"cert":      llx.StringData(l.Cert),
			"key":       llx.StringData(l.Key),
			"options":   llx.MapData(options, types.String),
			"raw":       llx.StringData(l.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidACLs2Resources(acls []squid.ACL, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(acls))
	for i, a := range acls {
		obj, err := CreateResource(runtime, "squid.conf.acl", map[string]*llx.RawData{
			"__id":   llx.StringData(ownerID + "/acl/" + a.Name),
			"name":   llx.StringData(a.Name),
			"type":   llx.StringData(a.Type),
			"flags":  llx.ArrayData(convert.SliceAnyToInterface(a.Flags), types.String),
			"values": llx.ArrayData(convert.SliceAnyToInterface(a.Values), types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidAccessRules2Resources(rules []squid.AccessRule, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(rules))
	for i, r := range rules {
		obj, err := CreateResource(runtime, "squid.conf.accessRule", map[string]*llx.RawData{
			"__id":   llx.StringData(fmt.Sprintf("%s/rule/%s/%d", ownerID, r.Kind, r.Index)),
			"kind":   llx.StringData(r.Kind),
			"index":  llx.IntData(int64(r.Index)),
			"action": llx.StringData(r.Action),
			"acls":   llx.ArrayData(convert.SliceAnyToInterface(r.ACLs), types.String),
			"raw":    llx.StringData(r.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidCachePeers2Resources(peers []squid.CachePeer, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(peers))
	for i, p := range peers {
		obj, err := CreateResource(runtime, "squid.conf.cachePeer", map[string]*llx.RawData{
			"__id":     llx.StringData(fmt.Sprintf("%s/peer/%d-%s:%d", ownerID, i, p.Host, p.HTTPPort)),
			"host":     llx.StringData(p.Host),
			"type":     llx.StringData(p.Type),
			"httpPort": llx.IntData(p.HTTPPort),
			"icpPort":  llx.IntData(p.ICPPort),
			"options":  llx.ArrayData(convert.SliceAnyToInterface(p.Options), types.String),
			"raw":      llx.StringData(p.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidCacheDirs2Resources(dirs []squid.CacheDir, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(dirs))
	for i, d := range dirs {
		obj, err := CreateResource(runtime, "squid.conf.cacheDir", map[string]*llx.RawData{
			"__id":    llx.StringData(fmt.Sprintf("%s/cacheDir/%d-%s", ownerID, i, d.Path)),
			"type":    llx.StringData(d.Type),
			"path":    llx.StringData(d.Path),
			"sizeMb":  llx.IntData(d.SizeMB),
			"l1":      llx.IntData(d.L1),
			"l2":      llx.IntData(d.L2),
			"options": llx.ArrayData(convert.SliceAnyToInterface(d.Options), types.String),
			"raw":     llx.StringData(d.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidRefreshPatterns2Resources(patterns []squid.RefreshPattern, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(patterns))
	for i, r := range patterns {
		obj, err := CreateResource(runtime, "squid.conf.refreshPattern", map[string]*llx.RawData{
			"__id":            llx.StringData(fmt.Sprintf("%s/refresh/%d-%s", ownerID, i, r.Pattern)),
			"pattern":         llx.StringData(r.Pattern),
			"caseInsensitive": llx.BoolData(r.CaseInsensitive),
			"min":             llx.IntData(r.Min),
			"percent":         llx.IntData(r.Percent),
			"max":             llx.IntData(r.Max),
			"options":         llx.ArrayData(convert.SliceAnyToInterface(r.Options), types.String),
			"raw":             llx.StringData(r.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func squidAccessLogs2Resources(logs []squid.AccessLog, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(logs))
	for i, a := range logs {
		obj, err := CreateResource(runtime, "squid.conf.accessLog", map[string]*llx.RawData{
			"__id":   llx.StringData(fmt.Sprintf("%s/accessLog/%d-%s", ownerID, i, a.Target)),
			"target": llx.StringData(a.Target),
			"format": llx.StringData(a.Format),
			"acls":   llx.ArrayData(convert.SliceAnyToInterface(a.ACLs), types.String),
			"raw":    llx.StringData(a.Raw),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

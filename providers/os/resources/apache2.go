// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
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
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/apache2"
	"go.mondoo.com/mql/providers/os/resources/haproxy"
	"go.mondoo.com/mql/types"
)

func (s *mqlApache2) id() (string, error) {
	return "apache2", nil
}

// apacheBinaries lists the well-known binary paths for the Apache httpd
// server. Both the version string (e.g. "Apache/2.4.62") and the compiled-in
// configuration layout are embedded as constants in the binary, so we can
// extract them by reading the file directly — no command execution required,
// which keeps this working on image and filesystem scans.
var apacheBinaries = []string{
	"/usr/sbin/apache2",
	"/usr/sbin/httpd",
	"/usr/local/sbin/httpd",
	"/usr/local/bin/httpd",
	// A source build defaults to --prefix=/usr/local/apache2 and keeps its
	// binary, configuration and content under it. The upstream httpd container
	// image is built this way.
	"/usr/local/apache2/bin/httpd",
	// Homebrew, on Apple Silicon and Intel respectively.
	"/opt/homebrew/bin/httpd",
	"/usr/local/opt/httpd/bin/httpd",
}

// apacheVersionCommands are tried as a fallback when the binary cannot be read.
var apacheVersionCommands = []string{"apache2ctl", "httpd", "apachectl"}

var apacheVersionTag = []byte("Apache/")

func (s *mqlApache2) version() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// Prefer file-based detection: scan the httpd binary for the embedded
	// "Apache/x.y.z" version string without loading the full binary into memory.
	for _, bin := range apacheBinaries {
		if v := scanBinaryForTag(afs, bin, apacheVersionTag, isFullApacheVersion); v != "" {
			return v, nil
		}
	}

	// Fall back to running a command when the binary isn't readable (e.g.
	// non-standard install path).
	for _, bin := range apacheVersionCommands {
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
		// Output looks like: "Server version: Apache/2.4.62 (Ubuntu)"
		if m := reApacheVersion.FindSubmatch(data); m != nil {
			return string(m[1]), nil
		}
	}

	// Apache is likely not installed; return nil rather than an error.
	s.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

var reApacheVersion = regexp.MustCompile(`Apache/(\S+)`)

// isFullApacheVersion accepts only a major.minor.patch version. httpd embeds
// the reduced ServerTokens forms "Apache/2" and "Apache/2.4" next to the full
// "Apache/2.4.68", and the linker may place either of them first.
func isFullApacheVersion(v []byte) bool {
	parts := bytes.Split(v, []byte("."))
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
	}
	return true
}

// scanBinaryForTag reads a file in chunks and looks for tag followed by a
// dot-separated version number (e.g. "Apache/2.4.62"). This avoids loading
// multi-megabyte binaries entirely into memory. When accept is not nil, a
// match it rejects is skipped and the scan continues with the next one.
func scanBinaryForTag(fs *afero.Afero, path string, tag []byte, accept func([]byte) bool) string {
	f, err := fs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Overlap must be at least len(tag) + max version length to avoid
	// missing a match that spans two chunks.
	return scanReaderForTag(f, tag, len(tag)+20, isApacheVersionByte, accept)
}

// isApacheVersionByte reports whether b belongs to an Apache/nginx style
// dot-separated numeric version (e.g. "2.4.62").
func isApacheVersionByte(b byte) bool {
	return b == '.' || (b >= '0' && b <= '9')
}

// The server's compiled-in layout. `httpd -V` prints these two values, but they
// are plain string constants in the binary, so reading the file gives the same
// answer on an asset we cannot run commands on.
var (
	apacheRootTag       = []byte(`-D HTTPD_ROOT="`)
	apacheConfigFileTag = []byte(`-D SERVER_CONFIG_FILE="`)
)

// isNotDoubleQuote terminates a scan at the closing quote of a `-D NAME="value"`
// literal.
func isNotDoubleQuote(b byte) bool { return b != '"' }

// maxApacheLayoutValue bounds how far a scan will run looking for that closing
// quote, so a spurious tag match cannot walk the rest of a binary.
const maxApacheLayoutValue = 512

// apacheLayout is where a particular build of httpd keeps its configuration.
type apacheLayout struct {
	// root is HTTPD_ROOT, the directory relative paths resolve against.
	root string
	// conf is SERVER_CONFIG_FILE. Every vendor build observed states it
	// relative to root, but an absolute value is legal and is honoured.
	conf string
}

// confPath returns the absolute path of the main configuration file, or "" when
// the layout is too incomplete to name one.
func (l apacheLayout) confPath() string {
	if l.conf == "" {
		return ""
	}
	if filepath.IsAbs(l.conf) {
		return l.conf
	}
	if l.root == "" {
		return ""
	}
	return filepath.Join(l.root, l.conf)
}

// apacheLayoutFromBinary reads the layout out of an httpd binary.
func apacheLayoutFromBinary(fs *afero.Afero, path string) apacheLayout {
	return apacheLayout{
		root: scanBinaryForQuotedTag(fs, path, apacheRootTag),
		conf: scanBinaryForQuotedTag(fs, path, apacheConfigFileTag),
	}
}

// scanBinaryForQuotedTag returns the value of a `-D NAME="value"` literal.
func scanBinaryForQuotedTag(fs *afero.Afero, path string, tag []byte) string {
	f, err := fs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// The overlap has to cover the tag plus the longest value we are willing to
	// read, so a literal straddling two chunks is not truncated.
	return scanReaderForTag(f, tag, len(tag)+maxApacheLayoutValue, isNotDoubleQuote, nil)
}

var (
	reApacheRoot       = regexp.MustCompile(`-D HTTPD_ROOT="([^"]*)"`)
	reApacheConfigFile = regexp.MustCompile(`-D SERVER_CONFIG_FILE="([^"]*)"`)
)

// apacheLayoutFromCommand asks the server itself. This is the last resort: it
// covers a build whose binary sits somewhere apacheBinaries does not list, and
// it only works on an asset we can run commands on.
func apacheLayoutFromCommand(conn shared.Connection) apacheLayout {
	for _, bin := range apacheVersionCommands {
		cmd, err := conn.RunCommand(bin + " -V")
		if err != nil || cmd.ExitStatus != 0 {
			continue
		}
		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			continue
		}
		var layout apacheLayout
		if m := reApacheRoot.FindSubmatch(data); m != nil {
			layout.root = string(m[1])
		}
		if m := reApacheConfigFile.FindSubmatch(data); m != nil {
			layout.conf = string(m[1])
		}
		if layout.confPath() != "" {
			return layout
		}
	}
	return apacheLayout{}
}

// apacheDebianStaticModules are the modules Debian and Ubuntu compile into
// apache2, as `apache2 -l` prints them on Ubuntu 16.04 through 26.04 (26.04
// adds mod_systemd.c). They are used when the binary cannot be asked.
var apacheDebianStaticModules = []string{
	"core.c", "mod_so.c", "mod_watchdog.c", "http_core.c",
	"mod_log_config.c", "mod_logio.c", "mod_version.c", "mod_unixd.c",
}

// apacheMinimalStaticModules are compiled into every httpd build that can
// load modules at all.
var apacheMinimalStaticModules = []string{"core.c", "mod_so.c", "http_core.c"}

// apacheStaticModules returns the modules compiled into the installed httpd,
// which satisfy <IfModule> without a LoadModule line. `httpd -l` needs no
// configuration and no privileges; when no binary can be run (an image or
// filesystem scan) it falls back to the platform's known set.
func apacheStaticModules(conn shared.Connection, afs *afero.Afero) []string {
	for _, bin := range apacheBinaries {
		if ok, _ := afs.Exists(bin); !ok {
			continue
		}
		cmd, err := conn.RunCommand(bin + " -l")
		if err != nil || cmd.ExitStatus != 0 {
			continue
		}
		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			continue
		}
		if mods := apache2.ParseStaticModuleList(string(data)); len(mods) > 0 {
			return mods
		}
	}
	if apacheEnvvarsPath(conn) != "" {
		return apacheDebianStaticModules
	}
	return apacheMinimalStaticModules
}

// apacheDiscoverLayout finds where the installed server keeps its
// configuration, preferring the binary over running anything.
func apacheDiscoverLayout(conn shared.Connection, afs *afero.Afero) apacheLayout {
	for _, bin := range apacheBinaries {
		if layout := apacheLayoutFromBinary(afs, bin); layout.confPath() != "" {
			return layout
		}
	}
	return apacheLayoutFromCommand(conn)
}

// scanReaderForTag streams r in chunks, looking for tag followed by a run of
// version bytes (as classified by isVersionByte). It is the reader-based core
// shared by the binary version scanners; the caller owns opening/closing the
// underlying file. `overlap` is the number of trailing bytes retained between
// chunks so a match spanning a chunk boundary isn't missed. When accept is not
// nil, matches it rejects are skipped and the scan moves on to the next match.
func scanReaderForTag(r io.Reader, tag []byte, overlap int, isVersionByte func(byte) bool, accept func([]byte) bool) string {
	const chunkSize = 64 * 1024
	buf := make([]byte, chunkSize+overlap)
	carry := 0

read:
	for {
		n, err := r.Read(buf[carry:])
		active := buf[:carry+n]

		for search := 0; search < len(active); {
			rel := bytes.Index(active[search:], tag)
			if rel < 0 {
				break
			}
			idx := search + rel
			start := idx + len(tag)
			end := start
			for end < len(active) && isVersionByte(active[end]) {
				end++
			}
			if end > start {
				// If the version run reaches the end of the current buffer
				// and more data may still follow (err == nil), the literal
				// might continue into the next chunk. Carry the tag and the
				// partial run forward and keep reading rather than returning
				// a truncated version (e.g. "2.4.6" instead of "2.4.62").
				// The len(active)-idx guard ensures carrying from the tag
				// frees room in the buffer for the next read (avoiding an
				// infinite loop when a run fills the whole buffer).
				if end == len(active) && err == nil && len(active)-idx < len(buf) {
					copy(buf, active[idx:])
					carry = len(active) - idx
					continue read
				}
				if accept == nil || accept(active[start:end]) {
					return string(active[start:end])
				}
			}
			search = idx + 1
		}

		// Stop once the reader is drained. `active` was already scanned
		// above, so any tail carried from a previous iteration has had its
		// final chance to match.
		if err != nil {
			break
		}

		// Keep the last `overlap` bytes so a tag spanning chunks isn't
		// missed. On a short read (len(active) <= overlap) retain the whole
		// buffer instead of discarding it, so a tag split across two short
		// reads is still found.
		if len(active) > overlap {
			copy(buf, active[len(active)-overlap:])
			carry = overlap
		} else {
			copy(buf, active)
			carry = len(active)
		}
	}
	return ""
}

type mqlApache2ConfInternal struct {
	lock sync.Mutex
	// serverRoot comes from the config's own ServerRoot directive and wins.
	serverRoot string
	// binaryServerRoot is the server's compiled-in HTTPD_ROOT, discovered while
	// locating the config file. It is only consulted when the config does not
	// state a ServerRoot, and is written once by file() before any parsing.
	binaryServerRoot string
	// defaultFile is set when file() chose the configuration file, rather
	// than apache2.conf(path) naming it.
	defaultFile bool
	// launch is how httpd is started (see apacheLaunch), read once.
	launchOnce sync.Once
	launch     *apache2.Launch
	launchErr  error
}

// apacheConfByFamily maps platform families (and a few standalone platform
// names that don't belong to the matching family) to their default Apache
// config path. The lookup checks platform name first, then walks Family[].
var apacheConfByFamily = map[string]string{
	// families
	"debian": "/etc/apache2/apache2.conf",
	"redhat": "/etc/httpd/conf/httpd.conf",
	"suse":   "/etc/apache2/httpd.conf",
	"arch":   "/etc/httpd/conf/httpd.conf",
	"bsd":    "/etc/apache2/httpd.conf",
	// standalone platforms (not in matching families above)
	"amazonlinux": "/etc/httpd/conf/httpd.conf",
	"gentoo":      "/etc/apache2/httpd.conf",
	"freebsd":     "/usr/local/etc/apache24/httpd.conf",
}

const defaultApacheConf = "/etc/httpd/conf/httpd.conf"

func apacheConfPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := apacheConfByFamily[asset.Platform.Name]; ok {
			return p
		}
		for _, family := range asset.Platform.Family {
			if p, ok := apacheConfByFamily[family]; ok {
				return p
			}
		}
	}
	return defaultApacheConf
}

// apacheServerRootByFamily maps platform families/names to their default
// ServerRoot directory for resolving relative Include paths.
var apacheServerRootByFamily = map[string]string{
	"debian":  "/etc/apache2",
	"suse":    "/etc/apache2",
	"bsd":     "/etc/apache2",
	"freebsd": "/usr/local/etc/apache24",
	"gentoo":  "/etc/apache2",
}

const defaultApacheServerRoot = "/etc/httpd"

// apacheEnvvarsByFamily maps platform families/names to the shell-style
// envvars file Apache sources at startup. On Debian/Ubuntu, /etc/apache2/envvars
// defines APACHE_RUN_USER, APACHE_RUN_GROUP, etc. — values that directives
// like `User ${APACHE_RUN_USER}` depend on.
var apacheEnvvarsByFamily = map[string]string{
	"debian": "/etc/apache2/envvars",
}

// apacheEnvvarsPath returns the path to the Apache envvars file for the asset's
// platform, or "" if the platform doesn't use one.
func apacheEnvvarsPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return ""
	}
	if p, ok := apacheEnvvarsByFamily[asset.Platform.Name]; ok {
		return p
	}
	for _, family := range asset.Platform.Family {
		if p, ok := apacheEnvvarsByFamily[family]; ok {
			return p
		}
	}
	return ""
}

// apacheServerRoot returns the ServerRoot directory for resolving relative
// Include paths. Defaults based on platform.
func apacheServerRoot(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := apacheServerRootByFamily[asset.Platform.Name]; ok {
			return p
		}
		for _, family := range asset.Platform.Family {
			if p, ok := apacheServerRootByFamily[family]; ok {
				return p
			}
		}
	}
	return defaultApacheServerRoot
}

// prescanServerRoot does a quick scan of the config content for a ServerRoot
// directive so that relative Include paths can be resolved before full parsing.
func prescanServerRoot(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		idx := strings.IndexAny(line, " \t")
		if idx < 0 {
			continue
		}
		if strings.EqualFold(line[:idx], "ServerRoot") {
			value := strings.TrimSpace(line[idx+1:])
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			return value
		}
	}
	return ""
}

func initApache2Conf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in apache2.conf initialization, it must be a string")
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

func (s *mqlApache2Conf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	// When Apache isn't installed we leave File set+null; use a stable ID so
	// the resource still caches cleanly instead of nil-dereferencing.
	if file.Data == nil {
		return "apache2.conf", nil
	}
	return file.Data.Path.Data, nil
}

// file is the default getter for the file field. It is only called when
// apache2.conf is created without a path argument. When a path IS provided,
// initApache2Conf converts it to a file resource that the framework stores
// directly, bypassing this method entirely (same pattern as sshd.config).
func (s *mqlApache2Conf) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	s.defaultFile = true

	// A configuration file named on httpd's command line (-f) is the one it
	// loads.
	launch, err := s.launchArgs()
	if err != nil {
		return nil, err
	}
	if launch != nil && launch.ConfigFile != "" {
		path := apacheLaunchConfigFile(conn, launch)
		if ok, _ := (&afero.Afero{Fs: conn.FileSystem()}).Exists(path); ok {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	// Try the platform-preferred path first, then fall back to all known paths.
	preferred := apacheConfPath(conn)
	candidates := []string{preferred}
	for _, p := range apacheConfByFamily {
		if p != preferred {
			candidates = append(candidates, p)
		}
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}
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

	// Nothing at a packaged location. Ask the installed server where it keeps
	// its configuration: a source build with a custom --prefix puts everything
	// under that prefix, which no vendor path list can anticipate. The vendor
	// paths are still tried first, so a packaged install is unaffected by this.
	if layout := apacheDiscoverLayout(conn, afs); layout.confPath() != "" {
		path := layout.confPath()
		if ok, _ := afs.Exists(path); ok {
			// Relative Include paths resolve against HTTPD_ROOT. The platform
			// default would be wrong for a custom prefix, and the config's own
			// ServerRoot directive (which takes precedence) is not read yet.
			s.binaryServerRoot = layout.root

			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return nil, err
			}
			return f.(*mqlFile), nil
		}
	}

	// No config file found anywhere — Apache likely isn't installed. Mark the
	// field as set+null so downstream field accessors (params, modules, ...)
	// return empty data instead of bubbling up "file does not exist" errors.
	s.File.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

var reApacheGlob = regexp.MustCompile(`[*?\[]`)

func (s *mqlApache2Conf) expandGlob(pattern string) ([]string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	// Resolve relative paths against ServerRoot: the directive in the config
	// wins, then the server's compiled-in HTTPD_ROOT, then the platform default.
	if !filepath.IsAbs(pattern) {
		serverRoot := s.serverRoot
		if serverRoot == "" {
			serverRoot = s.binaryServerRoot
		}
		if serverRoot == "" {
			serverRoot = apacheServerRoot(conn)
		}
		pattern = filepath.Join(serverRoot, pattern)
	}

	// SUSE's start_apache2 passes "Include /etc/apache2/sysconfig.d//global.conf"
	pattern = filepath.Clean(pattern)

	if !reApacheGlob.MatchString(pattern) {
		return []string{pattern}, nil
	}

	// Walk the filesystem to expand the glob
	var paths []string
	segments := strings.Split(pattern, "/")
	if segments[0] == "" {
		paths = []string{"/"}
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, segment := range segments[1:] {
		if !reApacheGlob.MatchString(segment) {
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
				if match, err := filepath.Match(segment, name); err != nil {
					return nil, err
				} else if match {
					nuPaths = append(nuPaths, filepath.Join(path, name))
				}
			}
		}
		paths = nuPaths
	}

	return paths, nil
}

func (s *mqlApache2Conf) setEmpty() {
	s.Params = plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}
	s.Modules = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.VirtualHosts = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Directories = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.Locations = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	s.SecurityHeaders = plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}
	s.Files = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
}

func (s *mqlApache2Conf) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.Params.State == plugin.StateIsSet {
		return nil
	}

	if file == nil {
		s.setEmpty()
		return nil
	}

	// When the config file doesn't exist (e.g. Apache is not installed),
	// return empty data instead of cascading errors.
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		s.setEmpty()
		return nil
	}

	// Pre-scan root file for ServerRoot directive so that relative Include
	// paths are resolved correctly during parsing.
	if content := file.GetContent(); content.Error == nil {
		if sr := prescanServerRoot(content.Data); sr != "" {
			s.serverRoot = sr
		}
	}

	filesIdx := map[string]*mqlFile{
		file.Path.Data: file,
	}

	// fileContent creates file resources and reads their content
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
		return s.expandGlob(pattern)
	}

	// Load platform envvars (e.g. Debian's /etc/apache2/envvars) so that
	// directives like `User ${APACHE_RUN_USER}` are resolved.
	envvars := s.loadEnvvars(fileContent)

	// <IfModule> and <IfDefine> are evaluated against the modules compiled
	// into the binary plus those loaded by LoadModule, and against -D
	// parameters (Debian passes APACHE_ARGUMENTS from envvars) plus Define.
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	defines := apache2.DefinesFromArguments(envvars["APACHE_ARGUMENTS"])

	// Without an envvars file, httpd gets its environment and -D parameters
	// from its systemd unit; RHEL 7's reads /etc/sysconfig/httpd
	var unitErr error
	if apacheEnvvarsPath(conn) == "" {
		var unitEnv map[string]string
		var unitDefines []string
		unitEnv, unitDefines, unitErr = apacheUnitEnvironment(afs)
		if len(unitEnv) > 0 {
			envvars = unitEnv
		}
		defines = append(defines, unitDefines...)
	}

	// httpd's own command line: the running master's, or on SUSE the one
	// start_apache2 builds from /etc/sysconfig/apache2. It applies to the
	// file httpd loads, not to another file named with apache2.conf(path).
	var preDirectives, postDirectives []string
	launch, launchErr := s.launchArgs()
	if launch != nil && (s.defaultFile || (launch.ConfigFile != "" && apacheLaunchConfigFile(conn, launch) == file.Path.Data)) {
		defines = append(defines, launch.Defines...)
		preDirectives = launch.PreDirectives
		postDirectives = launch.PostDirectives
		if launch.ServerRoot != "" {
			s.binaryServerRoot = launch.ServerRoot
		}
	}

	opts := apache2.ParseOptions{
		StaticModules:  apacheStaticModules(conn, afs),
		Defines:        defines,
		PreDirectives:  preDirectives,
		PostDirectives: postDirectives,
	}

	var cfg *apache2.Config
	err := unitErr
	if err == nil {
		err = launchErr
	}
	if err == nil {
		cfg, err = apache2.ParseWithGlobOptions(file.Path.Data, fileContent, globExpand, envvars, opts)
	}

	if err != nil {
		errState := plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Params = errState
		s.Modules = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.VirtualHosts = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Directories = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Locations = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.SecurityHeaders = plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Files = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	} else {
		s.Params = plugin.TValue[map[string]any]{Data: cfg.Params, State: plugin.StateIsSet}

		modules, err := apacheModules2Resources(cfg.Modules, s.MqlRuntime, s.__id)
		if err != nil {
			return err
		}
		s.Modules = plugin.TValue[[]any]{Data: modules, State: plugin.StateIsSet}

		vhosts, err := apacheVHosts2Resources(cfg.VHosts, s.MqlRuntime, s.__id)
		if err != nil {
			return err
		}
		s.VirtualHosts = plugin.TValue[[]any]{Data: vhosts, State: plugin.StateIsSet}

		dirs, err := apacheDirs2Resources(cfg.Dirs, s.MqlRuntime, s.__id)
		if err != nil {
			return err
		}
		s.Directories = plugin.TValue[[]any]{Data: dirs, State: plugin.StateIsSet}

		locations, err := apacheLocations2Resources(cfg.Locations, s.MqlRuntime, s.__id)
		if err != nil {
			return err
		}
		s.Locations = plugin.TValue[[]any]{Data: locations, State: plugin.StateIsSet}

		// Headers map: map[string][]string keyed by header name.
		// The generated field type is map[string]any (with []any values).
		headersOut := make(map[string]any, len(cfg.Headers))
		for name, values := range cfg.Headers {
			headersOut[name] = convert.SliceAnyToInterface(values)
		}
		s.SecurityHeaders = plugin.TValue[map[string]any]{Data: headersOut, State: plugin.StateIsSet}

		files := make([]any, 0, len(filesIdx))
		for _, f := range filesIdx {
			files = append(files, f)
		}
		s.Files = plugin.TValue[[]any]{Data: files, State: plugin.StateIsSet}
	}

	return err
}

func (s *mqlApache2Conf) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) modules(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) virtualHosts(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) directories(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) locations(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlApache2Conf) securityHeaders(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

// serverTokens / serverSignature / traceEnable derive from the params map.
// They take params() as input so the .lr-declared dependency is correct.
// When the config does not set the directive, httpd runs with its compiled-in
// default (https://httpd.apache.org/docs/2.4/mod/core.html), so that is what
// these report rather than an empty string.
func (s *mqlApache2Conf) serverTokens(params map[string]any) (string, error) {
	return apacheParamScalarOr(params, "ServerTokens", "Full"), nil
}

func (s *mqlApache2Conf) serverSignature(params map[string]any) (string, error) {
	return apacheParamScalarOr(params, "ServerSignature", "Off"), nil
}

func (s *mqlApache2Conf) traceEnable(params map[string]any) (string, error) {
	return apacheParamScalarOr(params, "TraceEnable", "On"), nil
}

// apacheParamScalarOr is apacheParamScalar with a default for a directive the
// config does not set. httpd rejects these directives without an argument, so
// an empty value only occurs when the directive is absent.
func apacheParamScalarOr(params map[string]any, name string, def string) string {
	if v := apacheParamScalar(params, name); v != "" {
		return v
	}
	return def
}

// apacheParamScalar returns the first scalar value from the case-insensitive
// param map. Apache directive names are case-insensitive; the parser
// preserves whatever casing the config used, so we scan keys case-insensitively.
// When the same directive appears multiple times (concatenated as "a,b" by
// setParam), the first segment is returned.
func apacheParamScalar(params map[string]any, name string) string {
	for k, v := range params {
		if !strings.EqualFold(k, name) {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if comma := strings.IndexByte(s, ','); comma >= 0 {
			return strings.TrimSpace(s[:comma])
		}
		return s
	}
	return ""
}

// loadEnvvars reads the platform's Apache envvars file (if any) via the
// provided fileContent function and returns the parsed assignments. A missing
// file or parse failure returns an empty map — envvars are best-effort.
func (s *mqlApache2Conf) loadEnvvars(fileContent func(string) (string, error)) map[string]string {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := apacheEnvvarsPath(conn)
	if path == "" {
		return nil
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	if ok, _ := afs.Exists(path); !ok {
		return nil
	}
	content, err := fileContent(path)
	if err != nil {
		return nil
	}
	return apache2.ParseEnvvars(content)
}

// apachePidFiles are where httpd records its master's pid: SUSE's
// start_apache2 passes -C "PidFile /run/httpd.pid", Red Hat's httpd.conf
// sets /run/httpd/httpd.pid and Debian's envvars /run/apache2/apache2.pid.
var apachePidFiles = []string{"/run/httpd.pid", "/run/httpd/httpd.pid", "/run/apache2/apache2.pid"}

const (
	// apacheSUSEStartScript is the wrapper SUSE's apache2.service runs. It
	// builds httpd's command line from apacheSUSESysconfig.
	apacheSUSEStartScript = "/usr/sbin/start_apache2"
	apacheSUSESysconfig   = "/etc/sysconfig/apache2"
)

// launchArgs returns how httpd is started, read once per resource.
func (s *mqlApache2Conf) launchArgs() (*apache2.Launch, error) {
	s.launchOnce.Do(func() {
		conn := s.MqlRuntime.Connection.(shared.Connection)
		s.launch, s.launchErr = apacheLaunch(&afero.Afero{Fs: conn.FileSystem()})
	})
	return s.launch, s.launchErr
}

// apacheLaunch returns the command line httpd runs with: the running
// master's, found through its pid file, or when no httpd runs on SUSE the one
// start_apache2 builds from /etc/sysconfig/apache2. It returns nil when
// neither applies, and httpd then reads its configuration file as is.
func apacheLaunch(afs *afero.Afero) (*apache2.Launch, error) {
	if l := apacheRunningLaunch(afs); l != nil {
		return l, nil
	}
	return apacheSUSELaunch(afs)
}

// apacheRunningLaunch reads the command line of the httpd master recorded in
// a pid file. A missing or stale pid file gives nil.
func apacheRunningLaunch(afs *afero.Afero) *apache2.Launch {
	for _, pidFile := range apachePidFiles {
		data, err := afs.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(data))
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := afs.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		argv := haproxy.SplitProcCmdline(raw)
		if len(argv) == 0 {
			continue
		}
		// SUSE runs httpd-prefork (or -worker, -event), Debian apache2
		base := filepath.Base(argv[0])
		if !strings.HasPrefix(base, "httpd") && !strings.HasPrefix(base, "apache2") {
			continue
		}
		l := apache2.ParseLaunchArgs(argv[1:])
		return &l
	}
	return nil
}

// apacheSUSELaunch returns the command line SUSE's start_apache2 runs httpd
// with, built from /etc/sysconfig/apache2, or nil on any other layout.
func apacheSUSELaunch(afs *afero.Afero) (*apache2.Launch, error) {
	if ok, _ := afs.Exists(apacheSUSEStartScript); !ok {
		return nil, nil
	}
	data, err := afs.ReadFile(apacheSUSESysconfig)
	if errors.Is(err, fs.ErrNotExist) {
		// start_apache2 then leaves out -DSYSCONFIG, and httpd.conf loads
		// the static loadmodule.conf and global.conf itself
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	vars := apache2.ParseEnvironmentFile(string(data))
	mpm := vars["APACHE_MPM"]
	if mpm == "" {
		mpm = apacheSUSEMPM(afs)
	}
	var unitArgs []string
	if argv := systemdServiceArgv(afs, "apache2.service"); len(argv) > 1 {
		unitArgs = argv[1:]
	}
	l := apache2.SUSESysconfig{
		Vars:     vars,
		MPM:      mpm,
		UnitArgs: unitArgs,
		Exists: func(p string) bool {
			ok, _ := afs.Exists(p)
			return ok
		},
	}.Launch()
	return &l, nil
}

// apacheSUSEMPMs are the httpd binaries SUSE ships, one per MPM.
var apacheSUSEMPMs = []string{"prefork", "worker", "event"}

// apacheSUSEMPM returns the MPM start_apache2 picks when APACHE_MPM is unset:
// the target of the /usr/sbin/httpd alternative (/usr/sbin/httpd-prefork).
// When the link cannot be read, a single installed httpd-<mpm> binary is the
// answer; otherwise it is unknown.
func apacheSUSEMPM(afs *afero.Afero) string {
	if lr, ok := afs.Fs.(afero.LinkReader); ok {
		target := "/usr/sbin/httpd"
		for range 2 {
			next, err := lr.ReadlinkIfPossible(target)
			if err != nil {
				break
			}
			if !filepath.IsAbs(next) {
				next = filepath.Join(filepath.Dir(target), next)
			}
			target = next
		}
		if mpm, ok := strings.CutPrefix(target, "/usr/sbin/httpd-"); ok {
			return mpm
		}
	}
	found := ""
	for _, mpm := range apacheSUSEMPMs {
		if ok, _ := afs.Exists("/usr/sbin/httpd-" + mpm); ok {
			if found != "" {
				return ""
			}
			found = mpm
		}
	}
	return found
}

// apacheLaunchConfigFile resolves the -f argument: a relative path is
// relative to the -d ServerRoot, or the platform's.
func apacheLaunchConfigFile(conn shared.Connection, launch *apache2.Launch) string {
	if launch.ConfigFile == "" || filepath.IsAbs(launch.ConfigFile) {
		return launch.ConfigFile
	}
	root := launch.ServerRoot
	if root == "" {
		root = apacheServerRoot(conn)
	}
	return filepath.Join(root, launch.ConfigFile)
}

// apacheServiceUnitDirs are where systemd looks for the httpd service unit
// and its httpd.service.d drop-ins, highest priority first.
var apacheServiceUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// apacheUnitEnvironment returns the environment systemd starts httpd with
// (Environment= plus the EnvironmentFile= files, which take precedence) and
// the -D parameters of its ExecStart line. Apache resolves ${VAR} from that
// environment. A missing unit or file contributes nothing; one that can't be
// read is an error. These files are not Apache configuration, so they are
// read directly rather than listed in files.
func apacheUnitEnvironment(afs *afero.Afero) (map[string]string, []string, error) {
	var contents []string
	for _, dir := range apacheServiceUnitDirs {
		content, err := afs.ReadFile(dir + "/httpd.service")
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		contents = append(contents, string(content))
		break
	}
	if len(contents) == 0 {
		return nil, nil, nil
	}

	// drop-ins apply in file-name order; a name in a higher-priority
	// directory hides the same name further down
	dropIns := map[string]string{}
	for i := len(apacheServiceUnitDirs) - 1; i >= 0; i-- {
		dir := apacheServiceUnitDirs[i] + "/httpd.service.d"
		entries, err := afs.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				dropIns[e.Name()] = dir + "/" + e.Name()
			}
		}
	}
	names := make([]string, 0, len(dropIns))
	for name := range dropIns {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content, err := afs.ReadFile(dropIns[name])
		if err != nil {
			return nil, nil, err
		}
		contents = append(contents, string(content))
	}

	unit := apache2.ParseServiceUnit(contents...)
	env := unit.Environment
	for _, f := range unit.EnvironmentFiles {
		data, err := afs.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		for k, v := range apache2.ParseEnvironmentFile(string(data)) {
			env[k] = v
		}
	}
	return env, apache2.UnitDefines(unit.ExecStart, env), nil
}

// envvars returns the apache2.conf.envvars resource representing the parsed
// envvars file. When the platform doesn't use one or the file is missing,
// the field is marked set+null so the resource is cleanly absent rather than
// rendering as an error or placeholder.
func (s *mqlApache2Conf) envvars() (*mqlApache2ConfEnvvars, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := apacheEnvvarsPath(conn)
	if path == "" {
		s.Envvars.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}
	if ok, _ := afs.Exists(path); !ok {
		s.Envvars.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// CreateResource does not run initApache2ConfEnvvars, so pass the file
	// resource the schema declares rather than the init-only path argument.
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(s.MqlRuntime, "apache2.conf.envvars", map[string]*llx.RawData{
		"__id": llx.StringData("apache2.conf.envvars/" + path),
		"file": llx.ResourceData(f, "file"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlApache2ConfEnvvars), nil
}

// initApache2ConfEnvvars resolves the envvars file path from the platform
// default when the resource is created directly (no arguments).
func initApache2ConfEnvvars(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in apache2.conf.envvars initialization, it must be a string")
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

func (s *mqlApache2ConfEnvvars) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "apache2.conf.envvars", nil
	}
	return "apache2.conf.envvars/" + file.Data.Path.Data, nil
}

// file is the default getter: if the envvars resource was constructed without
// an explicit file, resolve it from the host's platform.
func (s *mqlApache2ConfEnvvars) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := apacheEnvvarsPath(conn)
	if path == "" {
		s.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// params reads the envvars file and returns the parsed assignments.
func (s *mqlApache2ConfEnvvars) params(file *mqlFile) (map[string]any, error) {
	if file == nil {
		return map[string]any{}, nil
	}
	if exists := file.GetExists(); exists.Error != nil || !exists.Data {
		return map[string]any{}, nil
	}
	content := file.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	out := map[string]any{}
	for k, v := range apache2.ParseEnvvars(content.Data) {
		out[k] = v
	}
	return out, nil
}

func (s *mqlApache2Conf) listenAddresses(params map[string]any) ([]any, error) {
	str, ok := apache2.ParamValue(params, "Listen")
	if !ok {
		return nil, nil
	}

	parts := strings.Split(str, ",")
	res := make([]any, len(parts))
	for i, p := range parts {
		res[i] = strings.TrimSpace(p)
	}
	return res, nil
}

func apacheModules2Resources(modules []apache2.Module, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(modules))
	for i, mod := range modules {
		obj, err := CreateResource(runtime, "apache2.conf.module", map[string]*llx.RawData{
			"__id": llx.StringData(ownerID + "/module/" + mod.Name),
			"name": llx.StringData(mod.Name),
			"path": llx.StringData(mod.Path),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func apacheVHosts2Resources(vhosts []apache2.VirtualHost, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(vhosts))
	for i, vh := range vhosts {
		aliases := convert.SliceAnyToInterface(vh.ServerAliases)
		redirects := make([]any, len(vh.Redirects))
		for j, r := range vh.Redirects {
			redirects[j] = map[string]any{
				"type":   r.Type,
				"status": r.Status,
				"match":  r.Match,
				"target": r.Target,
			}
		}

		obj, err := CreateResource(runtime, "apache2.conf.virtualHost", map[string]*llx.RawData{
			"__id":                    llx.StringData(ownerID + "/vhost/" + strconv.Itoa(i) + "/" + vh.Address),
			"address":                 llx.StringData(vh.Address),
			"serverName":              llx.StringData(vh.ServerName),
			"serverAliases":           llx.ArrayData(aliases, types.String),
			"documentRoot":            llx.StringData(vh.DocumentRoot),
			"ssl":                     llx.BoolData(vh.SSL),
			"sslProtocol":             llx.StringData(vh.SSLProtocol),
			"sslCipherSuite":          llx.StringData(vh.SSLCipherSuite),
			"sslHonorCipherOrder":     llx.BoolData(vh.SSLHonorCipherOrder),
			"sslCertificateFile":      llx.StringData(vh.SSLCertificateFile),
			"sslCertificateKeyFile":   llx.StringData(vh.SSLCertificateKeyFile),
			"sslCertificateChainFile": llx.StringData(vh.SSLCertificateChainFile),
			"redirects":               llx.ArrayData(redirects, types.Dict),
			"params":                  llx.MapData(vh.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func apacheDirs2Resources(dirs []apache2.Directory, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(dirs))
	for i, d := range dirs {
		obj, err := CreateResource(runtime, "apache2.conf.directory", map[string]*llx.RawData{
			"__id":          llx.StringData(ownerID + "/dir/" + strconv.Itoa(i) + "/" + d.Path),
			"path":          llx.StringData(d.Path),
			"options":       llx.StringData(d.Options),
			"allowOverride": llx.StringData(d.AllowOverride),
			"require":       llx.ArrayData(convert.SliceAnyToInterface(d.Require), types.String),
			"params":        llx.MapData(d.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func apacheLocations2Resources(locs []apache2.Location, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(locs))
	for i, loc := range locs {
		obj, err := CreateResource(runtime, "apache2.conf.location", map[string]*llx.RawData{
			"__id":      llx.StringData(ownerID + "/loc/" + strconv.Itoa(i) + "/" + loc.Path),
			"path":      llx.StringData(loc.Path),
			"isMatch":   llx.BoolData(loc.IsMatch),
			"authType":  llx.StringData(loc.AuthType),
			"authName":  llx.StringData(loc.AuthName),
			"require":   llx.ArrayData(convert.SliceAnyToInterface(loc.Require), types.String),
			"proxyPass": llx.StringData(loc.ProxyPass),
			"params":    llx.MapData(loc.Params, types.String),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

func (v *mqlApache2ConfVirtualHost) certificate() ([]any, error) {
	path := v.SslCertificateFile.Data
	if path == "" {
		return []any{}, nil
	}
	return readCertificatesFromPath(v.MqlRuntime, path)
}

// readCertificatesFromPath reads a PEM file via the runtime's file resource
// and returns the parsed []network.certificate. Returns an empty slice when
// the file is unreadable so audits don't blow up on a misconfigured path.
func readCertificatesFromPath(runtime *plugin.Runtime, path string) ([]any, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return []any{}, nil
	}
	mqlF := f.(*mqlFile)
	content := mqlF.GetContent()
	if content.Error != nil || content.Data == "" {
		return []any{}, nil
	}
	c, err := runtime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(content.Data),
	})
	if err != nil {
		return []any{}, nil
	}
	list, err := runtime.GetSharedData("certificates", c.MqlID(), "list")
	if err != nil || list == nil {
		return []any{}, nil
	}
	if v, ok := list.Value.([]any); ok {
		return v, nil
	}
	return []any{}, nil
}

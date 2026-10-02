// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/sshd"
	"go.mondoo.com/mql/types"
)

type mqlSshdConfigInternal struct {
	lock                 sync.Mutex
	effectiveLock        sync.Mutex
	effectiveFetched     bool
	effectiveParamsCache map[string]string
	effectiveParamsErr   error
}

func initSshdConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in sshd.config initialization, it must be a string")
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

const defaultSshdConfig = "/etc/ssh/sshd_config"

// On Windows, OpenSSH Server reads %ProgramData%\ssh\sshd_config and
// resolves relative Include paths against %ProgramData%\ssh. Win32-OpenSSH
// compiles SSHDIR as "__PROGRAMDATA__\\ssh" and substitutes the token with
// the ProgramData folder at runtime, so the same token may also appear as a
// path prefix inside the configuration itself.
// https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
const (
	windowsProgramData            = `C:\ProgramData`
	windowsSshdDir                = windowsProgramData + `\ssh`
	windowsDefaultSshdConfig      = windowsSshdDir + `\sshd_config`
	windowsProgramDataPlaceholder = "__PROGRAMDATA__"
)

const sshdEffectiveConfigCommand = "sshd -T"

// defaultSshdPidFile is where sshd writes its pid unless PidFile says
// otherwise.
const defaultSshdPidFile = "/var/run/sshd.pid"

var sshdPidRegex = regexp.MustCompile(`^[0-9]+$`)

// Solaris and illumos install sshd in /usr/lib/ssh, which is on no user's
// PATH, not even root's.
const solarisSshdEffectiveConfigCommand = "/usr/lib/ssh/sshd -T"

func (s *mqlSshdConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}

	return file.Data.Path.Data, nil
}

// isWindows reports whether the connected asset is a Windows system, where
// sshd uses a different configuration directory and commands run under cmd.exe
// (WinRM) or PowerShell (local) rather than a POSIX shell.
func (s *mqlSshdConfig) isWindows() bool {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil || conn.Asset().Platform == nil {
		return false
	}
	return conn.Asset().Platform.IsFamily(inventory.FAMILY_WINDOWS)
}

func (s *mqlSshdConfig) isSolaris() bool {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil || conn.Asset().Platform == nil {
		return false
	}
	return conn.Asset().Platform.Name == "solaris"
}

func (s *mqlSshdConfig) file() (*mqlFile, error) {
	path := defaultSshdConfig
	if s.isWindows() {
		path = windowsDefaultSshdConfig
	} else if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok {
		// Vendor defaults such as /usr/etc/ssh exist only on Linux.
		path = resolveVendorConfigPath(conn.FileSystem(), defaultSshdConfig)
	}

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func matchBlocks2Resources(m sshd.MatchBlocks, runtime *plugin.Runtime, ownerID string) ([]any, error) {
	res := make([]any, len(m))
	for i := range m {
		cur := m[i]

		fobj, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(cur.Context.Path),
		})
		if err != nil {
			return nil, err
		}

		cobj, err := CreateResource(runtime, "file.context", map[string]*llx.RawData{
			"file":  llx.ResourceData(fobj, "file"),
			"range": llx.RangeData(cur.Context.Range),
		})
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(runtime, "sshd.config.matchBlock", map[string]*llx.RawData{
			"__id":     llx.StringData(ownerID + "/" + cur.Criteria),
			"criteria": llx.StringData(cur.Criteria),
			"params":   llx.MapData(cur.Params, types.String),
			"context":  llx.ResourceData(cobj, "file.context"),
		})
		if err != nil {
			return nil, err
		}
		res[i] = obj
	}
	return res, nil
}

var reGlob = regexp.MustCompile(`.*\*.*`)

func (s *mqlSshdConfig) expandGlob(glob string) ([]string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	if s.isWindows() {
		return expandWindowsSshdGlob(afs, glob)
	}
	return expandSshdGlob(afs, glob)
}

// expandWindowsSshdGlob expands an sshd_config Include pattern the way
// Win32-OpenSSH does. A pattern is absolute when it starts with a slash, a
// backslash, a drive letter, or the __PROGRAMDATA__ token; anything else is
// resolved from %ProgramData%\ssh. Win32-OpenSSH converts the pattern to
// forward slashes before globbing, so both separators are accepted here.
// The returned paths use backslashes.
func expandWindowsSshdGlob(afs *afero.Afero, glob string) ([]string, error) {
	if len(glob) >= len(windowsProgramDataPlaceholder) && strings.EqualFold(glob[:len(windowsProgramDataPlaceholder)], windowsProgramDataPlaceholder) {
		glob = windowsProgramData + glob[len(windowsProgramDataPlaceholder):]
	}
	glob = strings.ReplaceAll(glob, `\`, "/")
	if !isWindowsAbsPath(glob) {
		glob = strings.ReplaceAll(windowsSshdDir, `\`, "/") + "/" + glob
	}

	var paths []string
	if !reGlob.MatchString(glob) {
		paths = []string{glob}
	} else {
		segments := strings.Split(glob, "/")
		// The first segment is the root: a drive ("C:") or empty for a
		// root-relative path ("/foo").
		paths = []string{segments[0] + "/"}
		for _, segment := range segments[1:] {
			if segment == "" {
				continue
			}
			if !reGlob.MatchString(segment) {
				for i := range paths {
					paths[i] = pathpkg.Join(paths[i], segment)
				}
				continue
			}

			var nuPaths []string
			for _, dir := range paths {
				files, err := afs.ReadDir(dir)
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					return nil, err
				}
				for _, file := range files {
					name := file.Name()
					// Win32-OpenSSH uses the OpenBSD glob, which compares
					// names case-sensitively even on NTFS.
					match, err := filepath.Match(segment, name)
					if err != nil {
						return nil, err
					}
					if match {
						nuPaths = append(nuPaths, pathpkg.Join(dir, name))
					}
				}
			}
			paths = nuPaths
		}
	}

	for i := range paths {
		paths[i] = strings.ReplaceAll(paths[i], "/", `\`)
	}
	return paths, nil
}

// isWindowsAbsPath mirrors Win32-OpenSSH's is_absolute_path for a pattern
// already converted to forward slashes: "/abc" or "c:/abc".
func isWindowsAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// expandSshdGlob expands an sshd_config Include glob against afs. Relative
// patterns are resolved from /etc/ssh, matching sshd_config(5):
// https://man7.org/linux/man-pages/man5/sshd_config.5.html
func expandSshdGlob(afs *afero.Afero, glob string) ([]string, error) {
	if !reGlob.MatchString(glob) {
		if !filepath.IsAbs(glob) {
			glob = filepath.Join("/etc/ssh", glob)
		}
		return []string{glob}, nil
	}

	var paths []string
	segments := strings.Split(glob, "/")
	if segments[0] == "" {
		// Absolute pattern: the leading segment is the empty string before the
		// root "/", so start at root and consume the remaining segments.
		paths = []string{"/"}
		segments = segments[1:]
	} else {
		// Relative pattern: sshd expands it from /etc/ssh. Every segment is a
		// real path component here, so all of them must be consumed below.
		paths = []string{"/etc/ssh"}
	}

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		if !reGlob.MatchString(segment) {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], segment)
			}
			continue
		}

		var nuPaths []string
		for _, path := range paths {
			files, err := afs.ReadDir(path)
			if err != nil {
				// If the directory doesn't exist, treat it as "no matches" (empty result)
				// This is consistent with standard glob behavior where a non-existent directory
				// results in an empty match set, not an error
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}

			for j := range files {
				file := files[j]
				name := file.Name()
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

func (s *mqlSshdConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if file == nil {
		return errors.New("no base sshd config file to read")
	}

	filesIdx := map[string]*mqlFile{
		file.Path.Data: file,
	}
	// Function to get file content by path
	fileContent := func(path string) (string, error) {
		file, ok := filesIdx[path]
		if !ok {
			raw, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(path),
			})
			if err != nil {
				return "", err
			}
			file = raw.(*mqlFile)
			filesIdx[path] = file
		}

		fileContent, err := fileRequiredContent(file)
		if err != nil {
			return "", err
		}

		return fileContent + "\n", nil
	}

	// Function to expand glob patterns
	globExpand := func(glob string) ([]string, error) {
		return s.expandGlob(glob)
	}

	matchBlocks, err := sshd.ParseBlocksWithGlob(file.Path.Data, fileContent, globExpand)
	// TODO: check if not ready on I/O
	if err != nil {
		s.Params = plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Blocks = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		s.Files = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}

	} else {
		s.Params = plugin.TValue[map[string]any]{Data: matchBlocks.Flatten(), State: plugin.StateIsSet}

		blocks, err := matchBlocks2Resources(matchBlocks, s.MqlRuntime, s.__id)
		if err != nil {
			return err
		}
		s.Blocks = plugin.TValue[[]any]{Data: blocks, State: plugin.StateIsSet}

		files := make([]any, len(filesIdx))
		i := 0
		for _, v := range filesIdx {
			files[i] = v
			i++
		}
		s.Files = plugin.TValue[[]any]{Data: files, State: plugin.StateIsSet}
	}

	return err
}

func (s *mqlSshdConfig) files(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshdConfig) params(file *mqlFile) (map[string]any, error) {
	return nil, s.parse(file)
}

func (s *mqlSshdConfig) blocks(file *mqlFile) ([]any, error) {
	return nil, s.parse(file)
}

func parseConfigEntrySlice(raw any) ([]any, error) {
	str, ok := raw.(string)
	if !ok {
		return nil, errors.New("value is not a valid string")
	}

	res := []any{}
	entries := strings.Split(str, ",")
	for i := range entries {
		val := strings.TrimSpace(entries[i])
		res = append(res, val)
	}

	return res, nil
}

func (s *mqlSshdConfig) ciphers(params map[string]any) ([]any, error) {
	rawCiphers, ok := params["Ciphers"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawCiphers)
}

func (s *mqlSshdConfig) macs(params map[string]any) ([]any, error) {
	rawMacs, ok := params["MACs"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawMacs)
}

func (s *mqlSshdConfig) kexs(params map[string]any) ([]any, error) {
	rawkexs, ok := params["KexAlgorithms"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawkexs)
}

func parseEffectiveSshdConfig(input string) map[string]string {
	res := map[string]string{}
	lines := strings.Split(input, "\n")
	for i := range lines {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, " ")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok {
			res[key] = ""
			continue
		}
		res[key] = strings.TrimSpace(value)
	}
	return res
}

func (s *mqlSshdConfig) effectiveParams() (map[string]string, error) {
	s.effectiveLock.Lock()
	defer s.effectiveLock.Unlock()
	if s.effectiveFetched {
		return s.effectiveParamsCache, s.effectiveParamsErr
	}
	defer func() {
		s.effectiveFetched = true
	}()

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		s.effectiveParamsCache = map[string]string{}
		return s.effectiveParamsCache, nil
	}

	command, err := s.effectiveConfigCommand()
	if err != nil {
		s.effectiveParamsErr = err
		return nil, err
	}

	params, err := runEffectiveSshdConfig(conn, command)
	if err != nil {
		s.effectiveParamsErr = err
		return nil, err
	}

	// Options on the running daemon's command line override sshd_config.
	// RHEL 8 passes the system crypto policy that way, so ask sshd -T again
	// with the same options to report what the daemon accepts.
	if opts := s.daemonOptions(conn, params); len(opts) > 0 {
		params, err = runEffectiveSshdConfig(conn, sshdCommandWithOptions(command, opts))
		if err != nil {
			s.effectiveParamsErr = err
			return nil, err
		}
	}

	s.effectiveParamsCache = params
	return s.effectiveParamsCache, nil
}

// sshdCommandWithOptions appends each option as a shell-quoted -o argument.
func sshdCommandWithOptions(command string, opts []string) string {
	var sb strings.Builder
	sb.WriteString(command)
	for _, opt := range opts {
		sb.WriteString(" -o ")
		sb.WriteString(shared.ShellEscape(opt))
	}
	return sb.String()
}

func runEffectiveSshdConfig(conn shared.Connection, command string) (map[string]string, error) {
	cmd, err := conn.RunCommand(command)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("%s failed (exit %d): %s", command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}

	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseEffectiveSshdConfig(string(stdout)), nil
}

// daemonOptions returns the -o options of the running sshd when it reads the
// configuration file this resource describes. It finds the daemon through
// the PidFile sshd -T reported and reads its command line from /proc, so it
// only applies to Linux. No running daemon, or one that cannot be read,
// leaves the sshd_config view as it is.
func (s *mqlSshdConfig) daemonOptions(conn shared.Connection, params map[string]string) []string {
	if s.isWindows() || s.isSolaris() {
		return nil
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil || !asset.Platform.IsFamily(inventory.FAMILY_LINUX) {
		return nil
	}

	configPath := defaultSshdConfig
	if file := s.GetFile(); file.Error == nil && file.Data != nil && file.Data.Path.Data != "" {
		configPath = file.Data.Path.Data
	}

	pidFile := params["pidfile"]
	if pidFile == "" {
		pidFile = defaultSshdPidFile
	}
	if strings.EqualFold(pidFile, "none") {
		return nil
	}

	afs := &afero.Afero{Fs: conn.FileSystem()}
	rawPid, err := afs.ReadFile(pidFile)
	if err != nil {
		log.Debug().Err(err).Str("pidfile", pidFile).Msg("sshd> cannot read the running daemon's pid file")
		return nil
	}
	pid := strings.TrimSpace(string(rawPid))
	if !sshdPidRegex.MatchString(pid) {
		return nil
	}

	// read through a command: /proc files report a size of 0 and some
	// file transfer backends cannot stat them
	cmd, err := conn.RunCommand("cat /proc/" + pid + "/cmdline")
	if err != nil {
		log.Debug().Err(err).Str("pid", pid).Msg("sshd> cannot read the running daemon's command line")
		return nil
	}
	if cmd.ExitStatus != 0 {
		return nil
	}
	cmdline, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		log.Debug().Err(err).Str("pid", pid).Msg("sshd> cannot read the running daemon's command line")
		return nil
	}
	daemon, ok := sshd.ParseDaemonCommandLine(cmdline)
	if !ok {
		return nil
	}
	daemonConfig := daemon.ConfigFile
	if daemonConfig == "" {
		daemonConfig = defaultSshdConfig
	}
	if pathpkg.Clean(daemonConfig) != pathpkg.Clean(configPath) {
		return nil
	}
	return daemon.Options
}

func (s *mqlSshdConfig) effectiveConfigCommand() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	command := sshdEffectiveConfigCommand
	if s.isSolaris() {
		command = solarisSshdEffectiveConfigCommand
	}
	if file.Data == nil || file.Data.Path.Data == "" {
		return command, nil
	}
	path := file.Data.Path.Data
	if s.isWindows() {
		// sshd.exe defaults to %ProgramData%\ssh\sshd_config, the same file
		// this resource reads, so -f is only needed for a custom path.
		// WinRM runs commands under cmd.exe and a local scan under
		// PowerShell. Both strip double quotes, cmd.exe does not strip single
		// quotes, and a Windows path cannot contain a double quote.
		if strings.EqualFold(path, windowsDefaultSshdConfig) {
			return command, nil
		}
		// Inside double quotes cmd.exe still expands %VAR% and PowerShell
		// expands $var, $(...) and backtick escapes; & | < > stay literal.
		if strings.ContainsAny(path, "\"%$`") {
			return "", fmt.Errorf("cannot run sshd -T for %q: the path contains a character the Windows shell would expand", path)
		}
		return command + ` -f "` + path + `"`, nil
	}
	if path == defaultSshdConfig {
		return command, nil
	}
	return command + " -f " + shared.ShellEscape(path), nil
}

func effectiveConfigEntrySlice(params map[string]string, key string) ([]any, error) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}
	return parseConfigEntrySlice(raw)
}

func (s *mqlSshdConfig) effectiveCiphers() ([]any, error) {
	params, err := s.effectiveParams()
	if err != nil {
		return nil, err
	}
	return effectiveConfigEntrySlice(params, "ciphers")
}

func (s *mqlSshdConfig) effectiveMacs() ([]any, error) {
	params, err := s.effectiveParams()
	if err != nil {
		return nil, err
	}
	return effectiveConfigEntrySlice(params, "macs")
}

func (s *mqlSshdConfig) effectiveKexs() ([]any, error) {
	params, err := s.effectiveParams()
	if err != nil {
		return nil, err
	}
	return effectiveConfigEntrySlice(params, "kexalgorithms")
}

func (s *mqlSshdConfig) hostkeys(params map[string]any) ([]any, error) {
	rawHostKeys, ok := params["HostKey"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawHostKeys)
}

func (s *mqlSshdConfig) hostkeyalgorithms(params map[string]any) ([]any, error) {
	rawHostKeyAlgorithms, ok := params["HostKeyAlgorithms"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawHostKeyAlgorithms)
}

func (s *mqlSshdConfig) permitRootLogin(params map[string]any) ([]any, error) {
	rawPermitRootLogin, ok := params["PermitRootLogin"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawPermitRootLogin)
}

func (s *mqlSshdConfigMatchBlock) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for sshd.config match block")
}

func (s *mqlSshdConfigMatchBlock) ciphers(params map[string]any) ([]any, error) {
	rawCiphers, ok := params["Ciphers"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawCiphers)
}

func (s *mqlSshdConfigMatchBlock) macs(params map[string]any) ([]any, error) {
	rawMacs, ok := params["MACs"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawMacs)
}

func (s *mqlSshdConfigMatchBlock) kexs(params map[string]any) ([]any, error) {
	rawkexs, ok := params["KexAlgorithms"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawkexs)
}

func (s *mqlSshdConfigMatchBlock) hostkeys(params map[string]any) ([]any, error) {
	rawHostKeys, ok := params["HostKey"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawHostKeys)
}

func (s *mqlSshdConfigMatchBlock) hostkeyalgorithms(params map[string]any) ([]any, error) {
	rawHostKeyAlgorithms, ok := params["HostKeyAlgorithms"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawHostKeyAlgorithms)
}

func (s *mqlSshdConfigMatchBlock) permitRootLogin(params map[string]any) ([]any, error) {
	rawPermitRootLogin, ok := params["PermitRootLogin"]
	if !ok {
		return nil, nil
	}

	return parseConfigEntrySlice(rawPermitRootLogin)
}

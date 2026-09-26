// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// chronyConfPaths lists the default chrony configuration file locations.
// RHEL/Fedora/SUSE ship /etc/chrony.conf; Debian/Ubuntu use
// /etc/chrony/chrony.conf. Each is also looked up under /usr/etc, where
// openSUSE Leap 16 ships the default: its chronyd.service starts chronyd with
// -f /usr/etc/chrony.conf when /etc/chrony.conf does not exist. The first one
// that exists wins.
var chronyConfPaths = []string{
	"/etc/chrony.conf",
	"/etc/chrony/chrony.conf",
}

// chronyMaxIncludeLevel matches MAX_INCLUDE_LEVEL in chrony's conf.c.
const chronyMaxIncludeLevel = 10

type mqlChronyConfInternal struct {
	lock   sync.Mutex
	loaded *chronyConfig
}

func initChronyConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in chrony.conf initialization, it must be a string")
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

func (s *mqlChronyConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "", errors.New("cannot get file for chrony.conf")
	}
	return file.Data.Path.Data, nil
}

func (s *mqlChronyConf) file() (*mqlFile, error) {
	for _, primary := range chronyConfPaths {
		for _, candidate := range vendorConfigCandidates(primary) {
			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(candidate),
			})
			if err != nil {
				return nil, err
			}
			mqlFile := f.(*mqlFile)
			if exists := mqlFile.GetExists(); exists.Error == nil && exists.Data {
				return mqlFile, nil
			}
		}
	}

	// none of the candidates exist; return the primary path so callers can
	// still inspect the (missing) file rather than erroring out
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(chronyConfPaths[0]),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlChronyConf) content(file *mqlFile) (string, error) {
	return fileContentOrEmpty(file)
}

// load reads the configuration starting at file and follows its includes
// once per resource, so files and settings see the same snapshot.
func (s *mqlChronyConf) load(file *mqlFile) (*chronyConfig, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.loaded != nil {
		return s.loaded, nil
	}
	if file == nil {
		return nil, errors.New("cannot get file for chrony.conf")
	}

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("chrony.conf requires a connection with a file system")
	}
	cfg, err := loadChronyConfig(&afero.Afero{Fs: conn.FileSystem()}, file.Path.Data)
	if err != nil {
		return nil, err
	}
	s.loaded = cfg
	return cfg, nil
}

func (s *mqlChronyConf) files(file *mqlFile) ([]any, error) {
	cfg, err := s.load(file)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(cfg.files))
	for _, path := range cfg.files {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (s *mqlChronyConf) settings(file *mqlFile) ([]any, error) {
	cfg, err := s.load(file)
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(cfg.settings), nil
}

// chronyConfig is the configuration chronyd reads: the main file plus every
// file pulled in by include, confdir and sourcedir, in the order read.
type chronyConfig struct {
	files    []string
	settings []string
}

// loadChronyConfig reads the configuration file at path and follows its
// include, confdir and sourcedir directives the way chronyd does. A missing
// main file yields an empty configuration rather than an error.
func loadChronyConfig(afs *afero.Afero, path string) (*chronyConfig, error) {
	cfg := &chronyConfig{files: []string{}, settings: []string{}}
	if err := cfg.read(afs, path, 0); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *chronyConfig) read(afs *afero.Afero, path string, level int) error {
	if level > chronyMaxIncludeLevel {
		return fmt.Errorf("chrony.conf: maximum include level exceeded at %s", path)
	}

	data, err := afs.ReadFile(path)
	if err != nil {
		// chronyd skips an include glob that matches nothing; a missing file
		// here is the same case. The connection's virtual filesystem may not
		// return *os.PathError, so match the wrapped sentinel rather than using
		// os.IsNotExist.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	c.files = append(c.files, path)

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		// chrony discards lines starting with any of !;#% (CPS_NormalizeLine)
		if line == "" || strings.ContainsRune("!;#%", rune(line[0])) {
			continue
		}
		c.settings = append(c.settings, line)

		fields := strings.Fields(line)
		var included []string
		switch strings.ToLower(fields[0]) {
		case "include":
			if len(fields) < 2 {
				continue
			}
			included, err = chronyGlob(afs, fields[1])
		case "confdir":
			included, err = chronySearchDirs(afs, fields[1:], ".conf")
		case "sourcedir":
			included, err = chronySearchDirs(afs, fields[1:], ".sources")
		default:
			continue
		}
		if err != nil {
			return err
		}
		for _, inc := range included {
			if err := c.read(afs, inc, level+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// chronyGlob expands an include pattern. chrony runs glob(3) on it, which
// expands wildcards in any path component; a pattern without one is used as
// is. Like sshd Include handling (expandSshdGlob), only `*` is expanded. Matches are sorted, as glob(3) returns them, and directories are
// skipped since only files can be read.
func chronyGlob(afs *afero.Afero, pattern string) ([]string, error) {
	if !filepath.IsAbs(pattern) {
		pattern = "/" + pattern
	}
	if !reGlob.MatchString(pattern) {
		return []string{pattern}, nil
	}
	matches, err := expandSshdGlob(afs, pattern)
	if err != nil {
		return nil, err
	}
	res := make([]string, 0, len(matches))
	for _, m := range matches {
		if fi, err := afs.Stat(m); err == nil && fi.IsDir() {
			continue
		}
		res = append(res, m)
	}
	sort.Strings(res)
	return res, nil
}

// chronySearchDirs lists the files confdir and sourcedir read: every file
// with the suffix across dirs, ordered by file name, and for a name present
// in several dirs only the copy from the dir listed first
// (search_dirs in chrony's conf.c).
func chronySearchDirs(afs *afero.Afero, dirs []string, suffix string) ([]string, error) {
	byName := map[string]string{}
	for _, dir := range dirs {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, suffix) {
				continue
			}
			if _, ok := byName[name]; ok {
				continue
			}
			byName[name] = filepath.Join(dir, name)
		}
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	res := make([]string, 0, len(names))
	for _, name := range names {
		res = append(res, byName[name])
	}
	return res, nil
}

// directiveValues returns the argument portion of every setting whose
// first token matches the given directive (case-insensitive).
func directiveValues(settings []any, directive string) []any {
	res := []any{}
	for i := range settings {
		line, ok := settings[i].(string)
		if !ok {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !strings.EqualFold(fields[0], directive) {
			continue
		}
		res = append(res, strings.TrimSpace(strings.TrimPrefix(line, fields[0])))
	}
	return res
}

// lastDirectiveValue returns the argument portion of the last occurrence
// of a single-value directive (chrony uses the last setting for these),
// or "" when the directive is absent.
func lastDirectiveValue(settings []any, directive string) string {
	values := directiveValues(settings, directive)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1].(string)
}

func (s *mqlChronyConf) servers(settings []any) ([]any, error) {
	return directiveValues(settings, "server"), nil
}

func (s *mqlChronyConf) pools(settings []any) ([]any, error) {
	return directiveValues(settings, "pool"), nil
}

func (s *mqlChronyConf) peers(settings []any) ([]any, error) {
	return directiveValues(settings, "peer"), nil
}

func (s *mqlChronyConf) allow(settings []any) ([]any, error) {
	return directiveValues(settings, "allow"), nil
}

func (s *mqlChronyConf) deny(settings []any) ([]any, error) {
	return directiveValues(settings, "deny"), nil
}

func (s *mqlChronyConf) bindCmdAddresses(settings []any) ([]any, error) {
	return directiveValues(settings, "bindcmdaddress"), nil
}

func (s *mqlChronyConf) keyFile(settings []any) (string, error) {
	return lastDirectiveValue(settings, "keyfile"), nil
}

func (s *mqlChronyConf) makeStep(settings []any) (string, error) {
	return lastDirectiveValue(settings, "makestep"), nil
}

// rtcSync reports whether the bare `rtcsync` directive is present.
func (s *mqlChronyConf) rtcSync(settings []any) (bool, error) {
	for i := range settings {
		line, ok := settings[i].(string)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line), "rtcsync") {
			return true, nil
		}
	}
	return false, nil
}

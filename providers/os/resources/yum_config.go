// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

// yumConfigPaths lists the default global package-manager configuration
// file locations. Classic yum uses /etc/yum.conf; dnf-based systems use
// /etc/dnf/dnf.conf (on which /etc/yum.conf is often just a symlink).
// The first one that exists wins.
var yumConfigPaths = []string{
	"/etc/yum.conf",
	"/etc/dnf/dnf.conf",
}

func initYumConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in yum.config initialization, it must be a string")
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

func (y *mqlYumConfig) id() (string, error) {
	file := y.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "", errors.New("cannot get file for yum.config")
	}
	return file.Data.Path.Data, nil
}

func (y *mqlYumConfig) file() (*mqlFile, error) {
	for _, candidate := range yumConfigPaths {
		f, err := CreateResource(y.MqlRuntime, "file", map[string]*llx.RawData{
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

	// none exist; return the primary path so callers can still inspect it
	f, err := CreateResource(y.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(yumConfigPaths[0]),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// yumManagerBinaries are the package managers that read the global
// configuration. With one of them installed and no configuration file, its
// built-in defaults apply.
var yumManagerBinaries = []string{"/usr/bin/yum", "/usr/bin/dnf", dnf5Binary, "/usr/bin/microdnf"}

// noYumConfig reports that there is no yum or dnf configuration to read: the
// file does not exist, and either it was named with yum.config(path: ...) or
// no yum or dnf is installed whose defaults would apply. The fields are null
// then. An empty configuration would read as "signature checks disabled" on
// a host that has no yum at all, such as Debian.
func (y *mqlYumConfig) noYumConfig() (bool, error) {
	file := y.GetFile()
	if file.Error != nil {
		return false, file.Error
	}
	if file.Data == nil {
		return true, nil
	}
	exists := file.Data.GetExists()
	if exists.Error != nil {
		return false, exists.Error
	}
	if exists.Data {
		return false, nil
	}
	if !slices.Contains(yumConfigPaths, file.Data.Path.Data) {
		return true, nil
	}
	conn := y.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, bin := range yumManagerBinaries {
		if ok, _ := afs.Exists(bin); ok {
			return false, nil
		}
	}
	return true, nil
}

func (y *mqlYumConfig) content(file *mqlFile) (string, error) {
	if none, err := y.noYumConfig(); err != nil {
		return "", err
	} else if none {
		y.Content.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return fileContentOrEmpty(file)
}

// params returns every directive in the [main] section as a string map.
func (y *mqlYumConfig) params(content string) (map[string]any, error) {
	if none, err := y.noYumConfig(); err != nil {
		return nil, err
	} else if none {
		y.Params.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ini := parsers.ParseIni(content, "=")

	res := map[string]any{}
	main, ok := ini.Fields["main"].(map[string]any)
	if !ok {
		return res, nil
	}
	for k, v := range main {
		if s, ok := v.(string); ok {
			res[k] = s
		}
	}
	return res, nil
}

// parseYumBool interprets a yum/dnf boolean value. yum accepts 1/0,
// true/false, yes/no, on/off (case-insensitive). Unrecognized values are
// treated as false.
func parseYumBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// yumManager is the package manager that reads the configuration.
type yumManager int

const (
	yum3 yumManager = iota // RHEL 7 and older, Amazon Linux 2
	dnf4
	dnf5
)

func detectYumManager(afs *afero.Afero) yumManager {
	if ok, _ := afs.Exists(dnf5Binary); ok {
		return dnf5
	}
	if ok, _ := afs.Exists("/usr/bin/dnf"); ok {
		return dnf4
	}
	return yum3
}

// dnf5ConfDropInDirs are read before the main configuration file, distribution
// directory first; a file in the user directory masks the distribution file of
// the same name, and the files are applied in name order. See DROP-IN
// CONFIGURATION DIRECTORIES in dnf5.conf(5). Fedora sets pkg_gpgcheck=True in
// /usr/share/dnf5/libdnf.conf.d/20-fedora-defaults.conf and leaves dnf.conf
// empty.
var dnf5ConfDropInDirs = []string{"/usr/share/dnf5/libdnf.conf.d", "/etc/dnf/libdnf5.conf.d"}

// yumDirective is one key = value line of a [main] section.
type yumDirective struct{ key, value string }

// yumMainDirectives returns the [main] directives of an ini file in the order
// they appear, which decides between dnf5's gpgcheck and pkg_gpgcheck.
func yumMainDirectives(content string) []yumDirective {
	res := []yumDirective{}
	inMain := false
	for _, line := range strings.Split(content, "\n") {
		// an unquoted "#" starts a comment, as params reads it
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.Index(line, "]")
			inMain = end > 0 && strings.TrimSpace(line[1:end]) == "main"
			continue
		}
		if !inMain {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); k != "" {
			res = append(res, yumDirective{key: k, value: strings.TrimSpace(v)})
		}
	}
	return res
}

// readDnf5ConfDropIns returns the drop-in files in the order dnf5 applies them.
func readDnf5ConfDropIns(afs *afero.Afero) ([]string, error) {
	byName := map[string]string{}
	for _, dir := range dnf5ConfDropInDirs {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			// the later directory (/etc) masks the earlier one
			byName[e.Name()] = path.Join(dir, e.Name())
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	contents := make([]string, 0, len(names))
	for _, name := range names {
		data, err := afs.ReadFile(byName[name])
		if err != nil {
			return nil, err
		}
		contents = append(contents, string(data))
	}
	return contents, nil
}

// yumOptionDefaults holds the compiled-in defaults of the options the bool
// fields read; on dnf 5 gpgcheck is read as pkg_gpgcheck. yum 3 defaults
// clean_requirements_on_remove to false, dnf 4 and dnf 5 to true.
var yumOptionDefaults = map[yumManager]map[string]bool{
	yum3: {"gpgcheck": false, "localpkg_gpgcheck": false, "repo_gpgcheck": false, "clean_requirements_on_remove": false},
	dnf4: {"gpgcheck": false, "localpkg_gpgcheck": false, "repo_gpgcheck": false, "clean_requirements_on_remove": true},
	dnf5: {"pkg_gpgcheck": false, "localpkg_gpgcheck": false, "repo_gpgcheck": false, "clean_requirements_on_remove": true},
}

// effectiveBool returns a boolean option the way the package manager resolves
// it: its default, overridden on dnf 5 by the drop-in directories, overridden
// by the configuration file. On dnf 5 gpgcheck is another name for
// pkg_gpgcheck, and whichever of the two is set last wins. field is null when
// there is no configuration, see noYumConfig.
func (y *mqlYumConfig) effectiveBool(field *plugin.TValue[bool], key string) (bool, error) {
	if none, err := y.noYumConfig(); err != nil {
		return false, err
	} else if none {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	conn := y.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	manager := detectYumManager(afs)

	canonical := func(k string) string {
		if manager == dnf5 && k == "gpgcheck" {
			return "pkg_gpgcheck"
		}
		return k
	}
	key = canonical(key)

	sources := []string{}
	file := y.GetFile()
	if file.Error != nil {
		return false, file.Error
	}
	// drop-ins extend the system configuration, not a file named with
	// yum.config(path: ...)
	if manager == dnf5 && file.Data != nil && slices.Contains(yumConfigPaths, file.Data.Path.Data) {
		dropIns, err := readDnf5ConfDropIns(afs)
		if err != nil {
			if plugin.StructuredErrors() {
				return false, err
			}
			log.Debug().Err(err).Msg("yum.config> could not read the dnf5 drop-in configuration")
		}
		sources = append(sources, dropIns...)
	}
	content := y.GetContent()
	if content.Error != nil {
		return false, content.Error
	}
	sources = append(sources, content.Data)

	value := yumOptionDefaults[manager][key]
	for _, src := range sources {
		for _, d := range yumMainDirectives(src) {
			if canonical(d.key) == key {
				value = parseYumBool(d.value)
			}
		}
	}
	return value, nil
}

func (y *mqlYumConfig) gpgcheck(params map[string]any) (bool, error) {
	return y.effectiveBool(&y.Gpgcheck, "gpgcheck")
}

func (y *mqlYumConfig) localPkgGpgcheck(params map[string]any) (bool, error) {
	return y.effectiveBool(&y.LocalPkgGpgcheck, "localpkg_gpgcheck")
}

func (y *mqlYumConfig) repoGpgcheck(params map[string]any) (bool, error) {
	return y.effectiveBool(&y.RepoGpgcheck, "repo_gpgcheck")
}

func (y *mqlYumConfig) cleanRequirementsOnRemove(params map[string]any) (bool, error) {
	return y.effectiveBool(&y.CleanRequirementsOnRemove, "clean_requirements_on_remove")
}

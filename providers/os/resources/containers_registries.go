// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	containersRegistriesConf       = "/etc/containers/registries.conf"
	containersRegistriesConfVendor = "/usr/share/containers/registries.conf"
	// containersShortNameAliasesCache holds the aliases the tools record
	// after a short name pull. Its aliases take precedence over the
	// configuration's.
	containersShortNameAliasesCache = "/var/cache/containers/short-name-aliases.conf"
	containersDefaultShortNameMode  = "permissive"
)

// containersRegistriesDropInDirs are the drop-in directories root reads,
// highest priority first.
var containersRegistriesDropInDirs = []string{
	"/etc/containers/registries.rootful.conf.d",
	"/etc/containers/registries.conf.d",
	"/usr/share/containers/registries.rootful.conf.d",
	"/usr/share/containers/registries.conf.d",
}

// isRegistriesConfDFileName reports whether a drop-in is read. Unlike other
// *.d directories, hidden files are read too.
func isRegistriesConfDFileName(name string) bool {
	return strings.HasSuffix(name, ".conf")
}

// registriesConf is one containers-registries.conf(5) file. The global
// settings are pointers so that a file that leaves them out does not reset
// what an earlier file set.
type registriesConf struct {
	UnqualifiedSearchRegistries *[]string         `toml:"unqualified-search-registries"`
	ShortNameMode               string            `toml:"short-name-mode"`
	Registries                  []registryConf    `toml:"registry"`
	Aliases                     map[string]string `toml:"aliases"`
	// V1 is the version 1 format: [registries.search], [registries.insecure]
	// and [registries.block], each a list of registries.
	V1 struct {
		Search   registriesV1List `toml:"search"`
		Insecure registriesV1List `toml:"insecure"`
		Block    registriesV1List `toml:"block"`
	} `toml:"registries"`
}

type registriesV1List struct {
	Registries []string `toml:"registries"`
}

type registryConf struct {
	Prefix             string         `toml:"prefix"`
	Location           string         `toml:"location"`
	Insecure           bool           `toml:"insecure"`
	Blocked            bool           `toml:"blocked"`
	MirrorByDigestOnly bool           `toml:"mirror-by-digest-only"`
	Mirrors            []registryConf `toml:"mirror"`
	PullFromMirror     string         `toml:"pull-from-mirror"`
}

// parseRegistriesConf decodes one file and brings it into the version 2
// shape, as the tools do before merging it.
func parseRegistriesConf(content string) (registriesConf, error) {
	var c registriesConf
	if _, err := toml.Decode(content, &c); err != nil {
		return registriesConf{}, err
	}

	v1 := c.V1
	if len(v1.Search.Registries)+len(v1.Insecure.Registries)+len(v1.Block.Registries) > 0 {
		if c.UnqualifiedSearchRegistries != nil || len(c.Registries) > 0 {
			return registriesConf{}, fmt.Errorf("mixing registries.conf version 1 and 2 settings is not supported")
		}
		byLocation := map[string]*registryConf{}
		entry := func(location string) *registryConf {
			location = strings.TrimRight(location, "/")
			if r, ok := byLocation[location]; ok {
				return r
			}
			r := &registryConf{Location: location}
			byLocation[location] = r
			return r
		}
		for _, l := range v1.Insecure.Registries {
			entry(l).Insecure = true
		}
		for _, l := range v1.Block.Registries {
			entry(l).Blocked = true
		}
		for _, r := range byLocation {
			c.Registries = append(c.Registries, *r)
		}
		if len(v1.Search.Registries) > 0 {
			search := append([]string{}, v1.Search.Registries...)
			c.UnqualifiedSearchRegistries = &search
		}
	}

	for i := range c.Registries {
		r := &c.Registries[i]
		r.Location = strings.TrimRight(r.Location, "/")
		r.Prefix = strings.TrimRight(r.Prefix, "/")
		if r.Prefix == "" {
			r.Prefix = r.Location
		}
	}
	return c, nil
}

// mergeRegistriesConf applies a later file to the configuration so far: the
// settings it sets replace earlier ones, a registry entry replaces the one
// with the same prefix, and an alias set to "" is removed.
func mergeRegistriesConf(dst *registriesConf, src registriesConf) {
	byPrefix := map[string]registryConf{}
	for _, r := range dst.Registries {
		byPrefix[r.Prefix] = r
	}
	for _, r := range src.Registries {
		byPrefix[r.Prefix] = r
	}
	prefixes := make([]string, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	dst.Registries = make([]registryConf, 0, len(prefixes))
	for _, p := range prefixes {
		dst.Registries = append(dst.Registries, byPrefix[p])
	}

	if src.UnqualifiedSearchRegistries != nil {
		dst.UnqualifiedSearchRegistries = src.UnqualifiedSearchRegistries
	}
	if src.ShortNameMode != "" {
		dst.ShortNameMode = src.ShortNameMode
	}
	mergeRegistryAliases(dst, src.Aliases)
}

func mergeRegistryAliases(dst *registriesConf, aliases map[string]string) {
	for name, value := range aliases {
		if dst.Aliases == nil {
			dst.Aliases = map[string]string{}
		}
		if value == "" {
			delete(dst.Aliases, name)
			continue
		}
		dst.Aliases[name] = value
	}
}

type mqlContainersRegistriesInternal struct {
	lock   sync.Mutex
	loaded bool
	paths  []string
	conf   registriesConf
	err    error
}

// load reads and merges the configuration once for all fields.
func (r *mqlContainersRegistries) load() ([]string, registriesConf, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.loaded {
		return r.paths, r.conf, r.err
	}
	r.loaded = true

	paths, conf, err := r.read()
	if err != nil {
		r.err = err
		return nil, registriesConf{}, err
	}
	r.paths, r.conf = paths, conf
	return paths, conf, nil
}

// read finds and merges the configuration files. A file that exists but
// cannot be checked or read is an error, never an empty configuration, so
// that settings the tools apply are not silently left out.
func (r *mqlContainersRegistries) read() ([]string, registriesConf, error) {
	main := containersRegistriesConf
	ok, err := registriesFileExists(r.MqlRuntime, main)
	if err != nil {
		return nil, registriesConf{}, err
	}
	if !ok {
		main = containersRegistriesConfVendor
		if ok, err = registriesFileExists(r.MqlRuntime, main); err != nil {
			return nil, registriesConf{}, err
		}
	}
	paths := []string{}
	if ok {
		paths = append(paths, main)
	}
	dropIns, err := listConfDFilesWith(r.MqlRuntime, containersRegistriesDropInDirs, isRegistriesConfDFileName)
	if err != nil {
		return nil, registriesConf{}, err
	}
	paths = append(paths, dropIns...)

	conf := registriesConf{}
	for _, p := range paths {
		c, err := readRegistriesConf(r.MqlRuntime, p)
		if err != nil {
			return nil, registriesConf{}, err
		}
		mergeRegistriesConf(&conf, c)
	}

	ok, err = registriesFileExists(r.MqlRuntime, containersShortNameAliasesCache)
	if err != nil {
		return nil, registriesConf{}, err
	}
	if ok {
		c, err := readRegistriesConf(r.MqlRuntime, containersShortNameAliasesCache)
		if err != nil {
			return nil, registriesConf{}, err
		}
		mergeRegistryAliases(&conf, c.Aliases)
		paths = append(paths, containersShortNameAliasesCache)
	}
	return paths, conf, nil
}

func registriesFile(runtime *plugin.Runtime, p string) (*mqlFile, error) {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func registriesFileExists(runtime *plugin.Runtime, p string) (bool, error) {
	f, err := registriesFile(runtime, p)
	if err != nil {
		return false, err
	}
	exists := f.GetExists()
	return exists.Data, exists.Error
}

func readRegistriesConf(runtime *plugin.Runtime, p string) (registriesConf, error) {
	f, err := registriesFile(runtime, p)
	if err != nil {
		return registriesConf{}, err
	}
	content := f.GetContent()
	if content.Error != nil {
		return registriesConf{}, content.Error
	}
	c, err := parseRegistriesConf(content.Data)
	if err != nil {
		return registriesConf{}, fmt.Errorf("cannot parse %s: %w", p, err)
	}
	return c, nil
}

func (r *mqlContainersRegistries) files() ([]any, error) {
	paths, _, err := r.load()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, p := range paths {
		f, err := CreateResource(r.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (r *mqlContainersRegistries) unqualifiedSearchRegistries() ([]any, error) {
	_, conf, err := r.load()
	if err != nil {
		return nil, err
	}
	if conf.UnqualifiedSearchRegistries == nil {
		return []any{}, nil
	}
	return stringsToAny(*conf.UnqualifiedSearchRegistries), nil
}

func (r *mqlContainersRegistries) shortNameMode() (string, error) {
	_, conf, err := r.load()
	if err != nil {
		return "", err
	}
	if conf.ShortNameMode == "" {
		return containersDefaultShortNameMode, nil
	}
	return conf.ShortNameMode, nil
}

func (r *mqlContainersRegistries) aliases() (map[string]any, error) {
	_, conf, err := r.load()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	for k, v := range conf.Aliases {
		res[k] = v
	}
	return res, nil
}

func (r *mqlContainersRegistries) list() ([]any, error) {
	_, conf, err := r.load()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, reg := range conf.Registries {
		mirrors := []any{}
		for i, m := range reg.Mirrors {
			pull := m.PullFromMirror
			if pull == "" {
				pull = "all"
			}
			mirror, err := CreateResource(r.MqlRuntime, "containers.registry.mirror", map[string]*llx.RawData{
				"__id":           llx.StringData("containers.registry.mirror/" + reg.Prefix + "/" + strconv.Itoa(i)),
				"location":       llx.StringData(m.Location),
				"insecure":       llx.BoolData(m.Insecure),
				"pullFromMirror": llx.StringData(pull),
			})
			if err != nil {
				return nil, err
			}
			mirrors = append(mirrors, mirror)
		}
		registry, err := CreateResource(r.MqlRuntime, "containers.registry", map[string]*llx.RawData{
			"__id":               llx.StringData("containers.registry/" + reg.Prefix),
			"prefix":             llx.StringData(reg.Prefix),
			"location":           llx.StringData(reg.Location),
			"insecure":           llx.BoolData(reg.Insecure),
			"blocked":            llx.BoolData(reg.Blocked),
			"mirrorByDigestOnly": llx.BoolData(reg.MirrorByDigestOnly),
			"mirrors":            llx.ArrayData(mirrors, "containers.registry.mirror"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, registry)
	}
	return res, nil
}

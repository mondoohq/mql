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
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// Configuration shared by the containers tools (Podman, Buildah, Skopeo and,
// for storage.conf, CRI-O). Both formats are TOML, read from a system file and
// *.d drop-ins, each later file overriding what the earlier ones set.

const (
	containersConfEtc = "/etc/containers/containers.conf"
	containersConfUsr = "/usr/share/containers/containers.conf"
	storageConfEtc    = "/etc/containers/storage.conf"
	storageConfUsr    = "/usr/share/containers/storage.conf"

	containersDefaultPidsLimit = 2048
	storageDefaultGraphRoot    = "/var/lib/containers/storage"
	storageDefaultRunRoot      = "/run/containers/storage"
)

// containersDefaultCapabilities is the capability set containers get when
// containers.conf sets none (DefaultCapabilities in containers/common).
var containersDefaultCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_NET_BIND_SERVICE",
	"CAP_SETFCAP",
	"CAP_SETGID",
	"CAP_SETPCAP",
	"CAP_SETUID",
	"CAP_SYS_CHROOT",
}

// containersConfDropInDirs are the containers.conf drop-in directories root
// reads, highest priority first. Podman 6 (containers/common 0.68) moved to
// the shared config file loader, which added the rootful and /usr/share
// directories; earlier versions read only /etc/containers/containers.conf.d.
var (
	containersConfDropInDirs = []string{
		"/etc/containers/containers.rootful.conf.d",
		"/etc/containers/containers.conf.d",
		"/usr/share/containers/containers.rootful.conf.d",
		"/usr/share/containers/containers.conf.d",
	}
	containersConfLegacyDropInDirs = []string{
		"/etc/containers/containers.conf.d",
	}
	storageConfDropInDirs = []string{
		"/etc/containers/storage.rootful.conf.d",
		"/etc/containers/storage.conf.d",
		"/usr/share/containers/storage.rootful.conf.d",
		"/usr/share/containers/storage.conf.d",
	}
)

// containersConfStructTables and storageConfStructTables are the tables the
// library decodes into structs. BurntSushi/toml matches a struct field's name
// regardless of case when no key matches exactly, so `[Containers]` or
// `Log_Driver` are read like `[containers]` and `log_driver`. Tables decoded
// into maps, such as [storage.options.pull_options], keep their keys as
// written.
var (
	containersConfStructTables = map[string]bool{"": true, "containers": true, "engine": true, "network": true}
	storageConfStructTables    = map[string]bool{"": true, "storage": true, "storage.options": true, "storage.options.overlay": true}
)

// containersConfig is a merged containers.conf or storage.conf.
type containersConfig struct {
	paths []string
	// merged starts from the library's defaults for the lists a file can
	// append to, which is what the fields read.
	merged map[string]any
	// raw holds only what the files set.
	raw map[string]any
}

// containersConfDefaults returns the defaults containers.conf files are
// merged over: the one list with a non-empty default, which a file can extend
// with {append = true}.
func containersConfDefaults() map[string]any {
	caps := make([]any, len(containersDefaultCapabilities))
	for i, c := range containersDefaultCapabilities {
		caps[i] = c
	}
	return map[string]any{
		"containers": map[string]any{"default_capabilities": caps},
	}
}

// mergeContainersTOML applies a later file to the configuration so far, as the
// containers tools decode each file into the same structure: a table merges
// into the table before it, any other value replaces the earlier one. A list
// can carry an attribute table, `{append = true}`, which appends its values
// to the earlier ones instead. The attribute sticks to the setting, so a later
// list without one appends too, until a list sets `{append = false}`.
func mergeContainersTOML(dst, src map[string]any, prefix string, appendAttr map[string]bool) {
	for k, v := range src {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			if cur, ok := dst[k].(map[string]any); ok {
				mergeContainersTOML(cur, val, key, appendAttr)
				continue
			}
			fresh := map[string]any{}
			mergeContainersTOML(fresh, val, key, appendAttr)
			dst[k] = fresh
		case []any:
			values := make([]any, 0, len(val))
			for _, x := range val {
				attr, ok := x.(map[string]any)
				if !ok {
					values = append(values, x)
					continue
				}
				if b, ok := attr["append"].(bool); ok {
					appendAttr[key] = b
				}
			}
			if cur, ok := dst[k].([]any); ok && appendAttr[key] {
				dst[k] = append(append([]any{}, cur...), values...)
			} else {
				dst[k] = values
			}
		default:
			dst[k] = v
		}
	}
}

// parseContainersTOML decodes one file, with the keys of the tables in
// structTables in lower case.
func parseContainersTOML(content string, structTables map[string]bool) (map[string]any, error) {
	res := map[string]any{}
	if _, err := toml.Decode(content, &res); err != nil {
		return nil, err
	}
	return lowerStructKeys(res, "", structTables), nil
}

// lowerStructKeys folds the keys of struct tables to lower case. When a file
// holds a key in two spellings, the library assigns the exact one, so it wins
// here too; two spellings of one table are merged.
func lowerStructKeys(table map[string]any, path string, structTables map[string]bool) map[string]any {
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	// exact (already lower case) keys last, so they are assigned last
	sort.Slice(keys, func(i, j int) bool {
		ei, ej := keys[i] == strings.ToLower(keys[i]), keys[j] == strings.ToLower(keys[j])
		if ei != ej {
			return !ei
		}
		return keys[i] < keys[j]
	})
	res := make(map[string]any, len(table))
	for _, k := range keys {
		nk := k
		if structTables[path] {
			nk = strings.ToLower(k)
		}
		child := nk
		if path != "" {
			child = path + "." + nk
		}
		v := table[k]
		if t, ok := v.(map[string]any); ok {
			t = lowerStructKeys(t, child, structTables)
			if cur, ok := res[nk].(map[string]any); ok {
				mergeContainersTOML(cur, t, child, map[string]bool{})
				continue
			}
			v = t
		}
		res[nk] = v
	}
	return res
}

// mergeContainersFiles parses and merges file contents in order over the
// defaults, which may be nil.
func mergeContainersFiles(defaults map[string]any, structTables map[string]bool, paths []string, contents []string) (map[string]any, error) {
	merged := map[string]any{}
	appendAttr := map[string]bool{}
	if defaults != nil {
		mergeContainersTOML(merged, defaults, "", appendAttr)
	}
	for i, content := range contents {
		parsed, err := parseContainersTOML(content, structTables)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %s: %w", paths[i], err)
		}
		mergeContainersTOML(merged, parsed, "", appendAttr)
	}
	return merged, nil
}

// containersTable returns a table of the merged configuration.
func containersTable(cfg map[string]any, name string) map[string]any {
	t, _ := cfg[name].(map[string]any)
	return t
}

// containersString returns a string setting, false when it is unset.
func containersString(table map[string]any, key string) (string, bool) {
	v, ok := table[key].(string)
	return v, ok
}

// containersBool returns a boolean setting, false when it is unset.
func containersBool(table map[string]any, key string) (bool, bool) {
	v, ok := table[key].(bool)
	return v, ok
}

// containersStrings returns a list setting, false when it is unset.
func containersStrings(table map[string]any, key string) ([]string, bool) {
	raw, ok := table[key].([]any)
	if !ok {
		return nil, false
	}
	res := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			res = append(res, s)
		}
	}
	return res, true
}

// containersInt returns an integer setting, false when it is unset.
func containersInt(table map[string]any, key string) (int64, bool) {
	v, ok := table[key].(int64)
	return v, ok
}

// podmanPackageMajorVersion reads the major version of an installed podman
// package version such as "5.8.7-1.fc44", "5:5.4.0-1.el9" (with an epoch), or
// "5.4.2+ds1-2".
func podmanPackageMajorVersion(version string) (int, bool) {
	if _, rest, ok := strings.Cut(version, ":"); ok {
		version = rest
	}
	return podmanMajorVersion(version)
}

// containersSharedLoader reports whether the host's Podman reads
// containers.conf with the loader of Podman 6 and later. Without an installed
// podman package, or when packages cannot be listed, it reports the loader
// every earlier version used.
func containersSharedLoader(runtime *plugin.Runtime) bool {
	raw, err := NewResource(runtime, "package", map[string]*llx.RawData{"name": llx.StringData("podman")})
	if err != nil {
		log.Debug().Err(err).Msg("containers.conf> cannot look up the podman package")
		return false
	}
	pkg := raw.(*mqlPackage)
	if installed := pkg.GetInstalled(); installed.Error != nil || !installed.Data {
		return false
	}
	version := pkg.GetVersion()
	if version.Error != nil {
		return false
	}
	major, ok := podmanPackageMajorVersion(version.Data)
	return ok && major >= 6
}

// containersConfPaths lists the containers.conf files root reads, in the
// order they are applied. exists reports whether a main file is present.
func containersConfPaths(sharedLoader bool, exists func(string) (bool, error), dropIns func([]string) ([]string, error)) ([]string, error) {
	paths := []string{}
	if sharedLoader {
		// the first main file found, then every drop-in
		for _, p := range []string{containersConfEtc, containersConfUsr} {
			ok, err := exists(p)
			if err != nil {
				return nil, err
			}
			if ok {
				paths = append(paths, p)
				break
			}
		}
		d, err := dropIns(containersConfDropInDirs)
		if err != nil {
			return nil, err
		}
		return append(paths, d...), nil
	}

	// the vendor file, the admin's file on top, then /etc's drop-ins
	for _, p := range []string{containersConfUsr, containersConfEtc} {
		ok, err := exists(p)
		if err != nil {
			return nil, err
		}
		if ok {
			paths = append(paths, p)
		}
	}
	d, err := dropIns(containersConfLegacyDropInDirs)
	if err != nil {
		return nil, err
	}
	return append(paths, d...), nil
}

// storageConfPaths lists the storage.conf files root reads, in the order they
// are applied: the first main file found, then the drop-ins. Tools older than
// Podman 6 read no drop-ins, and nothing ships into those directories for
// them.
func storageConfPaths(exists func(string) (bool, error), dropIns func([]string) ([]string, error)) ([]string, error) {
	paths := []string{}
	for _, p := range []string{storageConfEtc, storageConfUsr} {
		ok, err := exists(p)
		if err != nil {
			return nil, err
		}
		if ok {
			paths = append(paths, p)
			break
		}
	}
	d, err := dropIns(storageConfDropInDirs)
	if err != nil {
		return nil, err
	}
	return append(paths, d...), nil
}

// loadContainersConfig reads and merges the files.
func loadContainersConfig(runtime *plugin.Runtime, defaults map[string]any, structTables map[string]bool, list func(exists func(string) (bool, error), dropIns func([]string) ([]string, error)) ([]string, error)) (*containersConfig, error) {
	exists := func(p string) (bool, error) { return registriesFileExists(runtime, p) }
	dropIns := func(dirs []string) ([]string, error) {
		return listConfDFilesWith(runtime, dirs, isRegistriesConfDFileName)
	}
	paths, err := list(exists, dropIns)
	if err != nil {
		return nil, err
	}
	contents := make([]string, len(paths))
	for i, p := range paths {
		f, err := registriesFile(runtime, p)
		if err != nil {
			return nil, err
		}
		content := f.GetContent()
		if content.Error != nil {
			return nil, content.Error
		}
		contents[i] = content.Data
	}
	raw, err := mergeContainersFiles(nil, structTables, paths, contents)
	if err != nil {
		return nil, err
	}
	merged := raw
	if defaults != nil {
		if merged, err = mergeContainersFiles(defaults, structTables, paths, contents); err != nil {
			return nil, err
		}
	}
	return &containersConfig{paths: paths, merged: merged, raw: raw}, nil
}

func containersConfigFiles(runtime *plugin.Runtime, cfg *containersConfig) ([]any, error) {
	res := make([]any, 0, len(cfg.paths))
	for _, p := range cfg.paths {
		f, err := registriesFile(runtime, p)
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

// =============================================================================
// containers.conf
// =============================================================================

type mqlContainersConfInternal struct {
	lock         sync.Mutex
	loaded       bool
	sharedLoader bool
	cfg          *containersConfig
	err          error
}

func (c *mqlContainersConf) load() (*containersConfig, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.loaded {
		return c.cfg, c.err
	}
	c.loaded = true
	c.sharedLoader = containersSharedLoader(c.MqlRuntime)
	c.cfg, c.err = loadContainersConfig(c.MqlRuntime, containersConfDefaults(), containersConfStructTables, func(exists func(string) (bool, error), dropIns func([]string) ([]string, error)) ([]string, error) {
		return containersConfPaths(c.sharedLoader, exists, dropIns)
	})
	return c.cfg, c.err
}

func (c *mqlContainersConf) table(name string) (map[string]any, error) {
	cfg, err := c.load()
	if err != nil {
		return nil, err
	}
	return containersTable(cfg.merged, name), nil
}

func (c *mqlContainersConf) files() ([]any, error) {
	cfg, err := c.load()
	if err != nil {
		return nil, err
	}
	return containersConfigFiles(c.MqlRuntime, cfg)
}

// stringOr reports a string setting of a table, or def when it is unset.
func (c *mqlContainersConf) stringOr(table, key, def string) (string, error) {
	t, err := c.table(table)
	if err != nil {
		return "", err
	}
	if v, ok := containersString(t, key); ok {
		return v, nil
	}
	return def, nil
}

// stringOrNull reports a string setting of a table, or null when it is unset.
func (c *mqlContainersConf) stringOrNull(field *plugin.TValue[string], table, key string) (string, error) {
	t, err := c.table(table)
	if err != nil {
		return "", err
	}
	if v, ok := containersString(t, key); ok {
		return v, nil
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (c *mqlContainersConf) boolOr(table, key string, def bool) (bool, error) {
	t, err := c.table(table)
	if err != nil {
		return false, err
	}
	if v, ok := containersBool(t, key); ok {
		return v, nil
	}
	return def, nil
}

func (c *mqlContainersConf) stringsOr(table, key string, def []string) ([]any, error) {
	t, err := c.table(table)
	if err != nil {
		return nil, err
	}
	if v, ok := containersStrings(t, key); ok {
		return convert.SliceAnyToInterface(v), nil
	}
	return convert.SliceAnyToInterface(def), nil
}

func (c *mqlContainersConf) privileged() (bool, error) {
	return c.boolOr("containers", "privileged", false)
}

func (c *mqlContainersConf) defaultCapabilities() ([]any, error) {
	t, err := c.table("containers")
	if err != nil {
		return nil, err
	}
	caps, ok := containersStrings(t, "default_capabilities")
	if !ok {
		caps = containersDefaultCapabilities
	}
	return convert.SliceAnyToInterface(normalizeCapabilityNames(caps)), nil
}

func (c *mqlContainersConf) defaultSysctls() ([]any, error) {
	return c.stringsOr("containers", "default_sysctls", nil)
}

func (c *mqlContainersConf) defaultUlimits() ([]any, error) {
	return c.stringsOr("containers", "default_ulimits", nil)
}

func (c *mqlContainersConf) devices() ([]any, error) {
	return c.stringsOr("containers", "devices", nil)
}

func (c *mqlContainersConf) mounts() ([]any, error) {
	return c.stringsOr("containers", "mounts", nil)
}

func (c *mqlContainersConf) volumes() ([]any, error) {
	return c.stringsOr("containers", "volumes", nil)
}

func (c *mqlContainersConf) envHost() (bool, error) {
	return c.boolOr("containers", "env_host", false)
}

func (c *mqlContainersConf) seccompProfile() (string, error) {
	return c.stringOrNull(&c.SeccompProfile, "containers", "seccomp_profile")
}

func (c *mqlContainersConf) apparmorProfile() (string, error) {
	return c.stringOrNull(&c.ApparmorProfile, "containers", "apparmor_profile")
}

func (c *mqlContainersConf) label() (bool, error) {
	t, err := c.table("containers")
	if err != nil {
		return false, err
	}
	if v, ok := containersBool(t, "label"); ok {
		return v, nil
	}
	c.Label.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (c *mqlContainersConf) readOnly() (bool, error) {
	return c.boolOr("containers", "read_only", false)
}

func (c *mqlContainersConf) pidsLimit() (int64, error) {
	t, err := c.table("containers")
	if err != nil {
		return 0, err
	}
	if v, ok := containersInt(t, "pids_limit"); ok {
		return v, nil
	}
	return containersDefaultPidsLimit, nil
}

func (c *mqlContainersConf) userns() (string, error) {
	v, err := c.stringOr("containers", "userns", "")
	if err != nil {
		return "", err
	}
	// the engine treats an empty mode as sharing the host's user namespace
	if v == "" {
		return "host", nil
	}
	return v, nil
}

func (c *mqlContainersConf) netns() (string, error) {
	return c.stringOr("containers", "netns", "private")
}

func (c *mqlContainersConf) pidns() (string, error) {
	return c.stringOr("containers", "pidns", "private")
}

func (c *mqlContainersConf) ipcns() (string, error) {
	return c.stringOr("containers", "ipcns", "shareable")
}

func (c *mqlContainersConf) utsns() (string, error) {
	return c.stringOr("containers", "utsns", "private")
}

func (c *mqlContainersConf) cgroupns() (string, error) {
	t, err := c.table("containers")
	if err != nil {
		return "", err
	}
	if v, ok := containersString(t, "cgroupns"); ok {
		return v, nil
	}
	if c.sharedLoader {
		return "private", nil
	}
	c.Cgroupns.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (c *mqlContainersConf) cgroups() (string, error) {
	return c.stringOr("containers", "cgroups", "enabled")
}

func (c *mqlContainersConf) logDriver() (string, error) {
	return c.stringOrNull(&c.LogDriver, "containers", "log_driver")
}

func (c *mqlContainersConf) runtime() (string, error) {
	return c.stringOrNull(&c.Runtime, "engine", "runtime")
}

func (c *mqlContainersConf) eventsLogger() (string, error) {
	return c.stringOrNull(&c.EventsLogger, "engine", "events_logger")
}

func (c *mqlContainersConf) cgroupManager() (string, error) {
	return c.stringOrNull(&c.CgroupManager, "engine", "cgroup_manager")
}

func (c *mqlContainersConf) networkBackend() (string, error) {
	return c.stringOrNull(&c.NetworkBackend, "network", "network_backend")
}

func (c *mqlContainersConf) defaultNetwork() (string, error) {
	return c.stringOr("network", "default_network", "podman")
}

// =============================================================================
// containers.storage
// =============================================================================

type mqlContainersStorageInternal struct {
	lock   sync.Mutex
	loaded bool
	cfg    *containersConfig
	err    error
}

func (s *mqlContainersStorage) load() (*containersConfig, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.loaded {
		return s.cfg, s.err
	}
	s.loaded = true
	s.cfg, s.err = loadContainersConfig(s.MqlRuntime, nil, storageConfStructTables, storageConfPaths)
	return s.cfg, s.err
}

// storageTables returns the [storage] table and its [storage.options] table.
func (s *mqlContainersStorage) storageTables() (map[string]any, map[string]any, error) {
	cfg, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	storage := containersTable(cfg.merged, "storage")
	return storage, containersTable(storage, "options"), nil
}

func (s *mqlContainersStorage) files() ([]any, error) {
	cfg, err := s.load()
	if err != nil {
		return nil, err
	}
	return containersConfigFiles(s.MqlRuntime, cfg)
}

func (s *mqlContainersStorage) configuration() (any, error) {
	cfg, err := s.load()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(cfg.raw)
}

func (s *mqlContainersStorage) driver() (string, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return "", err
	}
	if v, ok := containersString(storage, "driver"); ok && v != "" {
		// the library reads the overlay2 alias as overlay
		if v == "overlay2" {
			return "overlay", nil
		}
		return v, nil
	}
	s.Driver.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (s *mqlContainersStorage) driverPriority() ([]any, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return nil, err
	}
	v, _ := containersStrings(storage, "driver_priority")
	return convert.SliceAnyToInterface(v), nil
}

func (s *mqlContainersStorage) graphRoot() (string, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return "", err
	}
	if v, ok := containersString(storage, "graphroot"); ok && v != "" {
		return v, nil
	}
	return storageDefaultGraphRoot, nil
}

func (s *mqlContainersStorage) runRoot() (string, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return "", err
	}
	if v, ok := containersString(storage, "runroot"); ok && v != "" {
		return v, nil
	}
	return storageDefaultRunRoot, nil
}

func (s *mqlContainersStorage) imageStore() (string, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return "", err
	}
	v, _ := containersString(storage, "imagestore")
	return v, nil
}

func (s *mqlContainersStorage) additionalImageStores() ([]any, error) {
	_, options, err := s.storageTables()
	if err != nil {
		return nil, err
	}
	v, _ := containersStrings(options, "additionalimagestores")
	return convert.SliceAnyToInterface(v), nil
}

func (s *mqlContainersStorage) transientStore() (bool, error) {
	storage, _, err := s.storageTables()
	if err != nil {
		return false, err
	}
	v, _ := containersBool(storage, "transient_store")
	return v, nil
}

// storageOverlayOption reads an overlay driver option. The overlay table's
// setting is passed to the driver after the generic one in [storage.options],
// so it wins when both are set.
func storageOverlayOption(options map[string]any, key string) string {
	if v, ok := containersString(containersTable(options, "overlay"), key); ok && v != "" {
		return v
	}
	v, _ := containersString(options, key)
	return v
}

// splitMountOptions splits a comma separated mount option list.
func splitMountOptions(s string) []string {
	res := []string{}
	for _, o := range strings.Split(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			res = append(res, o)
		}
	}
	return res
}

func (s *mqlContainersStorage) overlayMountProgram() (string, error) {
	_, options, err := s.storageTables()
	if err != nil {
		return "", err
	}
	return storageOverlayOption(options, "mount_program"), nil
}

func (s *mqlContainersStorage) overlayMountOptions() ([]any, error) {
	_, options, err := s.storageTables()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(splitMountOptions(storageOverlayOption(options, "mountopt"))), nil
}

func (s *mqlContainersStorage) pullOptions() (map[string]any, error) {
	_, options, err := s.storageTables()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	for k, v := range containersTable(options, "pull_options") {
		switch val := v.(type) {
		case string:
			res[k] = val
		case bool:
			res[k] = strconv.FormatBool(val)
		}
	}
	return res, nil
}

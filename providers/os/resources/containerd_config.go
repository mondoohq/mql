// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/kballard/go-shellquote"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

const (
	// containerdConfigFile is where containerd reads its configuration from
	// unless --config names another file.
	containerdConfigFile = "/etc/containerd/config.toml"

	// The plugins that hold the CRI settings. Configuration version 2 keeps
	// them all in the CRI plugin; version 3 (containerd 2.x) splits them into
	// a runtime and an images plugin and leaves only the streaming server in
	// the CRI plugin.
	containerdCRIPlugin        = "io.containerd.grpc.v1.cri"
	containerdCRIRuntimePlugin = "io.containerd.cri.v1.runtime"
	containerdCRIImagesPlugin  = "io.containerd.cri.v1.images"

	// containerdDefaultRegistryConfigPath is where containerd 2.x looks for
	// hosts.toml files unless configured otherwise.
	containerdDefaultRegistryConfigPath = "/etc/containerd/certs.d:/etc/docker/certs.d"
)

// containerdConfigFiles are the main configuration files of the containerds
// that Kubernetes distributions run, after the standalone containerd's. K3s
// and k0s start containerd without a --config flag in its visible command
// line, so a running process does not always name its file.
var containerdConfigFiles = []string{
	containerdConfigFile,
	"/var/lib/rancher/k3s/agent/etc/containerd/config.toml",
	"/var/lib/rancher/rke2/agent/etc/containerd/config.toml",
	"/var/snap/microk8s/current/args/containerd.toml",
	"/run/k0s/containerd.toml",
	"/etc/k0s/containerd.toml",
}

// containerdInstallPaths are the containerd binaries the Kubernetes
// distributions ship on no PATH, in directories only root can write.
var containerdInstallPaths = []string{
	"/var/lib/rancher/rke2/bin/containerd",
	"/snap/microk8s/current/bin/containerd",
	"/snap/k8s/current/bin/containerd",
	"/var/lib/k0s/bin/containerd",
}

// containerdV1PluginNames maps the short plugin names of configuration
// version 1 to the ids containerd migrates them to.
var containerdV1PluginNames = map[string]string{
	"cri":       "io.containerd.grpc.v1.cri",
	"cgroups":   "io.containerd.monitor.v1.cgroups",
	"linux":     "io.containerd.runtime.v1.linux",
	"scheduler": "io.containerd.gc.v1.scheduler",
	"bolt":      "io.containerd.metadata.v1.bolt",
	"task":      "io.containerd.runtime.v2.task",
	"opt":       "io.containerd.internal.v1.opt",
	"restart":   "io.containerd.internal.v1.restart",
	"tracing":   "io.containerd.internal.v1.tracing",
	"otlp":      "io.containerd.tracing.processor.v1.otlp",
	"aufs":      "io.containerd.snapshotter.v1.aufs",
	"btrfs":     "io.containerd.snapshotter.v1.btrfs",
	"devmapper": "io.containerd.snapshotter.v1.devmapper",
	"native":    "io.containerd.snapshotter.v1.native",
	"overlayfs": "io.containerd.snapshotter.v1.overlayfs",
	"zfs":       "io.containerd.snapshotter.v1.zfs",
}

// containerdV1PluginID returns the id containerd migrates a plugin name of
// configuration version 1 to, as its v1MigratePluginName does: a name with a
// dot is an id already.
func containerdV1PluginID(name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	if id, ok := containerdV1PluginNames[name]; ok {
		return id
	}
	switch {
	case strings.HasSuffix(name, "-service"):
		return "io.containerd.service.v1." + name
	case name == "windows" || name == "windows-lcow":
		return "io.containerd.snapshotter.v1." + name
	default:
		return "io.containerd.grpc.v1." + name
	}
}

type mqlContainerdInternal struct {
	lock   sync.Mutex
	loaded bool
	// proc is the running containerd, nil when there is none
	proc *mqlProcess
	// flags are what its command line sets
	flags containerdFlags
	// ver is the containerd version, empty when unknown
	ver string
	// major is the major version of containerd, 0 when unknown
	major int

	cfgLock   sync.Mutex
	cfgLoaded bool
	cfg       *containerdConfig
	cfgErr    error
}

// containerdFlags are the command-line flags of containerd that change where
// it reads its configuration and what it overrides of it.
type containerdFlags struct {
	config  string
	address string
	root    string
	state   string
}

// parseContainerdCommandLine reads the flags of a containerd command line.
// containerd takes `--flag value`, `--flag=value`, and the one-dash forms of
// both.
func parseContainerdCommandLine(command string) containerdFlags {
	res := containerdFlags{}
	words := strings.Fields(command)
	if len(words) == 0 {
		return res
	}
	words = words[1:]
	for i := 0; i < len(words); i++ {
		word := words[i]
		// containerd's flags come before its subcommand
		if word == "--" || !strings.HasPrefix(word, "-") {
			break
		}
		name := strings.TrimLeft(word, "-")
		value, hasValue := "", false
		if n, v, ok := strings.Cut(name, "="); ok {
			name, value, hasValue = n, v, true
		}
		var dst *string
		switch name {
		case "config", "c":
			dst = &res.config
		case "address", "a":
			dst = &res.address
		case "root":
			dst = &res.root
		case "state":
			dst = &res.state
		default:
			continue
		}
		if !hasValue {
			if i+1 >= len(words) {
				break
			}
			i++
			value = words[i]
		}
		*dst = value
	}
	return res
}

// load finds the running containerd, parses its command line, and determines
// the containerd version, once.
func (c *mqlContainerd) load() {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.loaded {
		return
	}
	c.loaded = true

	c.proc = findContainerdProcess(c.MqlRuntime)
	if c.proc != nil {
		if command := c.proc.GetCommand(); command.Error == nil {
			c.flags = parseContainerdCommandLine(command.Data)
		}
	}
	c.ver = c.containerdVersion(containerdVersionBinaries(c.proc != nil, newBinaryProbe(c.MqlRuntime, c.proc)))
	c.major = containerdMajor(c.ver)
}

// isContainerdProcess reports whether a process is a containerd daemon: its
// executable is containerd, or it calls itself containerd, as the containerd
// that K3s runs inside its own binary does.
func isContainerdProcess(executable, command string) bool {
	if path.Base(executable) == "containerd" {
		return true
	}
	words := strings.Fields(command)
	return len(words) > 0 && path.Base(words[0]) == "containerd"
}

// findContainerdProcess returns the running containerd, or nil when there is
// none or the process list cannot be read, as on an image or a mounted
// filesystem.
func findContainerdProcess(runtime *plugin.Runtime) *mqlProcess {
	obj, err := CreateResource(runtime, "processes", nil)
	if err != nil {
		return nil
	}
	list := obj.(*mqlProcesses).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("containerd> cannot list processes")
		return nil
	}
	for _, p := range list.Data {
		proc := p.(*mqlProcess)
		exe := proc.GetExecutable()
		command := proc.GetCommand()
		if exe.Error != nil || command.Error != nil || !isContainerdProcess(exe.Data, command.Data) {
			continue
		}
		// any user can start a process named containerd, with a --config of
		// their choosing, so the same admission rules as for the kubelet apply
		if kubeletProcessAllowed(runtime, proc) {
			return proc
		}
	}
	return nil
}

// containerdVersionBinaries returns the containerd binaries to ask for the
// version, in order. The containerd process is matched by name, and any user
// can start a process named containerd, so its binary is run only when root
// runs that very file in the system's own mount namespace, as for the
// kubelet. Then the containerd on the PATH, then the install paths that only
// root can change.
func containerdVersionBinaries(hasProcess bool, probe kubeletBinaryProbe) []string {
	res := []string{}
	if hasProcess {
		if p := resolveRootExecutable("", nil, probe); path.IsAbs(p) {
			res = append(res, p)
		}
	}
	res = append(res, "containerd")
	for _, p := range containerdInstallPaths {
		if probe.trustedBinary(p) {
			res = append(res, p)
		}
	}
	return res
}

// containerdVersion asks containerd binaries for the version, and returns the
// first answer.
func (c *mqlContainerd) containerdVersion(bins []string) string {
	for _, bin := range bins {
		out, ok := runCommandQuiet(c.MqlRuntime, shellquote.Join(bin, "--version"))
		if !ok {
			continue
		}
		if v := parseContainerdVersion(out); v != "" {
			return v
		}
	}
	return ""
}

// parseContainerdVersion reads the version from `containerd --version`, for
// example "containerd github.com/containerd/containerd/v2 v2.2.0 1c4457e0",
// and returns it without the leading v ("2.2.0").
func parseContainerdVersion(out string) string {
	fields := strings.Fields(out)
	if len(fields) < 3 || fields[0] != "containerd" {
		return ""
	}
	v := strings.TrimPrefix(fields[2], "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}

// containerdMajor returns the major version of a containerd version, 0 when
// it is not known.
func containerdMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}

// containerdMinor returns the major.minor of a containerd version.
func containerdMinor(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func (c *mqlContainerd) version() (string, error) {
	c.load()
	v := c.ver
	if v == "" {
		c.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return v, nil
}

func (c *mqlContainerd) process() (*mqlProcess, error) {
	c.load()
	if c.proc == nil {
		c.Process.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return c.proc, nil
}

// configFilePath returns the main configuration file: the one the running
// containerd names, else the first of containerdConfigFiles that exists, else
// the default.
func (c *mqlContainerd) configFilePath() string {
	c.load()
	if c.flags.config != "" {
		return c.flags.config
	}
	fs := c.MqlRuntime.Connection.(shared.Connection).FileSystem()
	for _, p := range containerdConfigFiles {
		if _, err := fs.Stat(p); err == nil {
			return p
		}
	}
	return containerdConfigFile
}

func (c *mqlContainerd) configFile() (*mqlFile, error) {
	f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(c.configFilePath()),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// containerdConfig is the configuration containerd loads from its files.
type containerdConfig struct {
	// files are the files it was merged from, in the order applied
	files []string
	// merged holds what the files set
	merged map[string]any
	// version is the configuration version the files set, 0 when none
	version int64
}

// loadConfig reads and merges the configuration files, once.
func (c *mqlContainerd) loadConfig() (*containerdConfig, error) {
	c.load()
	c.cfgLock.Lock()
	defer c.cfgLock.Unlock()
	if c.cfgLoaded {
		return c.cfg, c.cfgErr
	}
	c.cfgLoaded = true
	fs := c.MqlRuntime.Connection.(shared.Connection).FileSystem()
	c.cfg, c.cfgErr = loadContainerdConfig(fs, c.configFilePath(), c.major)
	return c.cfg, c.cfgErr
}

// loadContainerdConfig loads the configuration the way containerd's
// LoadConfig does: the main file first, then the files each file imports,
// breadth first, every file merged over the ones before. A missing main file
// is no configuration, as containerd then runs with its defaults.
func loadContainerdConfig(fs afero.Fs, main string, major int) (*containerdConfig, error) {
	res := &containerdConfig{files: []string{}, merged: map[string]any{}}
	if _, err := fs.Stat(main); err != nil {
		return res, nil
	}

	loaded := map[string]bool{}
	pending := []string{main}
	for len(pending) > 0 {
		p := pending[0]
		pending = pending[1:]
		if loaded[p] {
			continue
		}
		data, err := afero.ReadFile(fs, p)
		if err != nil {
			if p == main {
				return nil, err
			}
			// containerd refuses to start with an import it cannot read
			log.Debug().Err(err).Str("file", p).Msg("containerd> cannot read an imported configuration file")
			loaded[p] = true
			continue
		}
		cfg, err := parseContainerdConfig(string(data))
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", p, err))
		}
		mergeContainerdConfig(res.merged, cfg, major)
		res.files = append(res.files, p)
		loaded[p] = true

		imports := resolveContainerdImports(fs, p, containerdStrings(cfg["imports"]))
		pending = append(pending, imports...)
	}
	res.version, _ = res.merged["version"].(int64)
	return res, nil
}

// parseContainerdConfig decodes a containerd configuration file. A file of
// version 1 (or none) has its plugins, and the plugins it disables or
// requires, renamed to the ids of version 2, as containerd migrates it.
func parseContainerdConfig(content string) (map[string]any, error) {
	cfg := map[string]any{}
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, err
	}
	if v, _ := cfg["version"].(int64); v < 2 {
		if plugins, ok := cfg["plugins"].(map[string]any); ok {
			renamed := make(map[string]any, len(plugins))
			for name, v := range plugins {
				renamed[containerdV1PluginID(name)] = v
			}
			cfg["plugins"] = renamed
		}
		for _, key := range []string{"disabled_plugins", "required_plugins"} {
			list, ok := cfg[key].([]any)
			if !ok {
				continue
			}
			renamed := make([]any, len(list))
			for i, item := range list {
				if name, ok := item.(string); ok {
					item = containerdV1PluginID(name)
				}
				renamed[i] = item
			}
			cfg[key] = renamed
		}
	}
	return cfg, nil
}

// resolveContainerdImports returns the files an import list names, relative
// paths taken from the importing file's directory and globs expanded in name
// order, as containerd's resolveImports does.
func resolveContainerdImports(fs afero.Fs, parent string, imports []string) []string {
	res := []string{}
	for _, p := range imports {
		p = path.Clean(p)
		if !path.IsAbs(p) {
			p = path.Join(path.Dir(parent), p)
		}
		if strings.Contains(p, "*") {
			res = append(res, globContainerdImport(fs, p)...)
			continue
		}
		res = append(res, p)
	}
	return res
}

// globContainerdImport expands a glob the way filepath.Glob does, in name
// order. It lists directories with ReadDir rather than afero.Glob, which
// relies on Readdirnames that not every connection's filesystem implements.
func globContainerdImport(fs afero.Fs, pattern string) []string {
	dir, file := path.Split(pattern)
	dir = path.Clean(dir)
	dirs := []string{dir}
	if strings.ContainsAny(dir, "*?[") {
		dirs = globContainerdImport(fs, dir)
	}
	res := []string{}
	for _, d := range dirs {
		entries, err := afero.ReadDir(fs, d)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			if ok, err := path.Match(file, name); err == nil && ok {
				res = append(res, path.Join(d, name))
			}
		}
	}
	return res
}

// containerdReplacedSections are the tables of which a later file replaces
// every entry it sets as a whole.
var containerdReplacedSections = map[string]bool{
	"proxy_plugins":     true,
	"stream_processors": true,
	"timeouts":          true,
}

// mergeContainerdConfig merges a configuration file over the configuration so
// far, as containerd's mergeConfig does. A file's own settings override the
// earlier ones only when they are set to something other than an empty value,
// and lists are joined. Plugin sections are merged key by key on containerd
// 2.x; containerd 1.x replaces a plugin's whole section with the later file's.
func mergeContainerdConfig(dst, src map[string]any, major int) {
	for k, v := range src {
		switch {
		case k == "plugins":
			plugins, _ := v.(map[string]any)
			dstPlugins, ok := dst[k].(map[string]any)
			if !ok {
				dstPlugins = map[string]any{}
				dst[k] = dstPlugins
			}
			for id, section := range plugins {
				srcSection, srcIsTable := section.(map[string]any)
				dstSection, dstIsTable := dstPlugins[id].(map[string]any)
				if major != 1 && srcIsTable && dstIsTable {
					mergeContainerdTables(dstSection, srcSection)
					continue
				}
				dstPlugins[id] = section
			}
		case containerdReplacedSections[k]:
			table, _ := v.(map[string]any)
			dstTable, ok := dst[k].(map[string]any)
			if !ok {
				dstTable = map[string]any{}
				dst[k] = dstTable
			}
			for name, entry := range table {
				dstTable[name] = entry
			}
		default:
			dst[k] = mergeContainerdValue(dst[k], v)
		}
	}
}

// mergeContainerdValue merges a setting outside the plugins: a table key by
// key, a list joined without duplicates, anything else replaced unless the
// later value is empty.
func mergeContainerdValue(dst, src any) any {
	switch s := src.(type) {
	case map[string]any:
		d, ok := dst.(map[string]any)
		if !ok {
			d = map[string]any{}
		}
		for k, v := range s {
			d[k] = mergeContainerdValue(d[k], v)
		}
		return d
	case []any:
		d, _ := dst.([]any)
		res := append([]any{}, d...)
		for _, item := range s {
			found := false
			for _, existing := range res {
				if reflect.DeepEqual(existing, item) {
					found = true
					break
				}
			}
			if !found {
				res = append(res, item)
			}
		}
		return res
	default:
		if dst != nil && isZeroContainerdValue(src) {
			return dst
		}
		return src
	}
}

func isZeroContainerdValue(v any) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case int64:
		return x == 0
	case float64:
		return x == 0
	case bool:
		return !x
	default:
		return v == nil
	}
}

// mergeContainerdTables merges a plugin section over another, as containerd
// 2.x does: tables merge key by key and every other value the later file sets
// replaces the earlier one.
func mergeContainerdTables(dst, src map[string]any) {
	for k, v := range src {
		srcTable, srcIsTable := v.(map[string]any)
		dstTable, dstIsTable := dst[k].(map[string]any)
		if srcIsTable && dstIsTable {
			mergeContainerdTables(dstTable, srcTable)
			continue
		}
		dst[k] = v
	}
}

func containerdStrings(v any) []string {
	res := []string{}
	list, _ := v.([]any)
	for _, item := range list {
		if s, ok := item.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

func (c *mqlContainerd) files() ([]any, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, p := range cfg.files {
		f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (c *mqlContainerd) configuration() (map[string]any, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(withoutContainerdSecrets(cfg.merged))
}

// containerdSecretKeys are the settings that hold registry credentials or
// headers (which carry tokens): the CRI registry's auths, headers, and each
// registry's auth with its username, password, auth and identitytoken.
var containerdSecretKeys = []string{"auth", "auths", "headers", "header", "username", "password", "identitytoken"}

func isContainerdSecretKey(k string) bool {
	for _, s := range containerdSecretKeys {
		if strings.EqualFold(k, s) {
			return true
		}
	}
	return false
}

// withoutContainerdSecrets returns a copy of a configuration without the
// registry credentials and headers it may hold, wherever they are. containerd
// matches setting names regardless of case (`Auth`, `AUTHS`, `Headers`), so
// they are matched the same way.
func withoutContainerdSecrets(cfg map[string]any) map[string]any {
	res := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if isContainerdSecretKey(k) {
			continue
		}
		res[k] = withoutContainerdSecretsValue(v)
	}
	return res
}

func withoutContainerdSecretsValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return withoutContainerdSecrets(x)
	case []any:
		res := make([]any, len(x))
		for i, item := range x {
			res[i] = withoutContainerdSecretsValue(item)
		}
		return res
	default:
		return v
	}
}

// containerdSetting is a CRI setting: where configuration version 2 and
// version 3 keep it, and containerd's built-in default on 1.x and 2.x (nil
// when there is none).
type containerdSetting struct {
	v2, v3   []string
	default1 any
	default2 any
}

var (
	containerdSandboxImage = containerdSetting{
		v2: []string{containerdCRIPlugin, "sandbox_image"},
		v3: []string{containerdCRIImagesPlugin, "pinned_images", "sandbox"},
	}
	containerdSnapshotter = containerdSetting{
		v2:       []string{containerdCRIPlugin, "containerd", "snapshotter"},
		v3:       []string{containerdCRIImagesPlugin, "snapshotter"},
		default1: "overlayfs", default2: "overlayfs",
	}
	containerdDefaultRuntime = containerdSetting{
		v2:       []string{containerdCRIPlugin, "containerd", "default_runtime_name"},
		v3:       []string{containerdCRIRuntimePlugin, "containerd", "default_runtime_name"},
		default1: "runc", default2: "runc",
	}
	containerdRuntimes = containerdSetting{
		v2: []string{containerdCRIPlugin, "containerd", "runtimes"},
		v3: []string{containerdCRIRuntimePlugin, "containerd", "runtimes"},
	}
	containerdRegistry = containerdSetting{
		v2: []string{containerdCRIPlugin, "registry"},
		v3: []string{containerdCRIImagesPlugin, "registry"},
	}
	containerdRegistryConfigPath = containerdSetting{
		v2: []string{containerdCRIPlugin, "registry", "config_path"},
		v3: []string{containerdCRIImagesPlugin, "registry", "config_path"},
	}
	containerdStreamAddress = containerdSetting{
		v2:       []string{containerdCRIPlugin, "stream_server_address"},
		v3:       []string{containerdCRIPlugin, "stream_server_address"},
		default1: "127.0.0.1", default2: "127.0.0.1",
	}
	containerdStreamPort = containerdSetting{
		v2:       []string{containerdCRIPlugin, "stream_server_port"},
		v3:       []string{containerdCRIPlugin, "stream_server_port"},
		default1: "0", default2: "0",
	}
	containerdStreamTLS = containerdSetting{
		v2:       []string{containerdCRIPlugin, "enable_tls_streaming"},
		v3:       []string{containerdCRIPlugin, "enable_tls_streaming"},
		default1: false, default2: false,
	}
)

// containerdRuntimeSetting is a setting of the CRI runtime: in the CRI plugin
// in version 2, in the runtime plugin in version 3.
func containerdRuntimeSetting(key string, default1, default2 any) containerdSetting {
	return containerdSetting{
		v2:       []string{containerdCRIPlugin, key},
		v3:       []string{containerdCRIRuntimePlugin, key},
		default1: default1,
		default2: default2,
	}
}

// containerdSandboxImages are the built-in pod sandbox images of containerd
// releases.
var containerdSandboxImages = map[string]string{
	"1.7": "registry.k8s.io/pause:3.8",
	"2.0": "registry.k8s.io/pause:3.10",
	"2.1": "registry.k8s.io/pause:3.10",
	"2.2": "registry.k8s.io/pause:3.10.1",
	"2.3": "registry.k8s.io/pause:3.10.2",
}

// containerdLookup returns the value at a path of nested tables. With fold,
// keys past the first (a plugin id or top-level setting) also match
// regardless of case when none matches exactly, as containerd 2.x decodes
// settings into its structs; containerd 1.x does not.
func containerdLookup(cfg map[string]any, keys []string, fold bool) (any, bool) {
	var cur any = cfg
	for i, k := range keys {
		table, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = containerdGet(table, k, fold && i > 0)
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// containerdGet returns a setting of a table: the key that matches exactly,
// else, with fold, one that matches regardless of case.
func containerdGet(table map[string]any, key string, fold bool) (any, bool) {
	if v, ok := table[key]; ok {
		return v, true
	}
	if !fold {
		return nil, false
	}
	for k, v := range table {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// effectiveMajor is the containerd major version the settings are read for:
// the known one, or 2 for a configuration of version 3, which only containerd
// 2.x loads. 0 means either.
func effectiveContainerdMajor(major int, version int64) int {
	if major != 0 {
		return major
	}
	if version >= 3 {
		return 2
	}
	return 0
}

// containerdSettingValue returns what the configuration sets for a setting,
// and whether it sets it. containerd 1.x reads version 2 locations only.
// containerd 2.x reads the version 3 locations of a version 3 configuration,
// and migrates the version 2 locations of an older one to version 3.
func containerdSettingValue(cfg map[string]any, version int64, major int, s containerdSetting) (any, bool) {
	plugins, _ := cfg["plugins"].(map[string]any)
	fold := major == 2
	switch {
	case major == 1:
		return containerdLookup(plugins, s.v2, false)
	case version >= 3:
		return containerdLookup(plugins, s.v3, fold)
	default:
		if v, ok := containerdLookup(plugins, s.v2, fold); ok {
			return v, true
		}
		return containerdLookup(plugins, s.v3, fold)
	}
}

// containerdDefault returns containerd's built-in value of a setting, and
// whether it is known: when the containerd major version is unknown, only a
// default that 1.x and 2.x share is.
func containerdDefault(major int, s containerdSetting) (any, bool) {
	switch major {
	case 1:
		return s.default1, s.default1 != nil
	case 2:
		return s.default2, s.default2 != nil
	default:
		if s.default1 != nil && reflect.DeepEqual(s.default1, s.default2) {
			return s.default1, true
		}
		return nil, false
	}
}

// setting returns the effective value of a CRI setting: what the files set,
// else containerd's default. ok is false when neither is known.
func (c *mqlContainerd) setting(s containerdSetting) (any, bool, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, false, err
	}
	v, ok := cfg.effective(c.major, s)
	return v, ok, nil
}

// effective returns the value of a CRI setting containerd runs with: what the
// files set, else containerd's default. ok is false when neither is known.
func (cfg *containerdConfig) effective(major int, s containerdSetting) (any, bool) {
	major = effectiveContainerdMajor(major, cfg.version)
	if v, ok := containerdSettingValue(cfg.merged, cfg.version, major, s); ok {
		return v, true
	}
	return containerdDefault(major, s)
}

func (c *mqlContainerd) stringSetting(field *plugin.TValue[string], s containerdSetting) (string, error) {
	v, ok, err := c.setting(s)
	if err != nil {
		return "", err
	}
	str, isString := v.(string)
	if !ok || !isString {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return str, nil
}

func (c *mqlContainerd) boolSetting(field *plugin.TValue[bool], s containerdSetting) (bool, error) {
	v, ok, err := c.setting(s)
	if err != nil {
		return false, err
	}
	b, isBool := v.(bool)
	if !ok || !isBool {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return b, nil
}

func (c *mqlContainerd) configVersion() (int64, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return 0, err
	}
	if cfg.version != 0 {
		return cfg.version, nil
	}
	// a file without a version is version 1; no file is the defaults'
	if len(cfg.files) > 0 {
		return 1, nil
	}
	if v := containerdDefaultConfigVersion(c.ver); v != 0 {
		return v, nil
	}
	c.ConfigVersion.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

// containerdDefaultConfigVersion returns the configuration version of a
// containerd release's built-in defaults, 0 when the release is unknown:
// 2 on 1.x, 3 on 2.0 to 2.2, and 4 from 2.3, which moved the API server
// settings into plugins.
func containerdDefaultConfigVersion(version string) int64 {
	switch major, minor := containerdMajor(version), containerdMinorNumber(version); {
	case major == 1:
		return 2
	case major == 2 && minor >= 3:
		return 4
	case major == 2:
		return 3
	case major > 2:
		return 4
	default:
		return 0
	}
}

// containerdMinorNumber returns the minor version of a containerd version, 0
// when it has none.
func containerdMinorNumber(version string) int {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

// containerdPatchNumber returns the patch version of a containerd version,
// without a distribution suffix ("1.6.20~ds1" is 20), -1 when it has none.
func containerdPatchNumber(version string) int {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 3 {
		return -1
	}
	digits := parts[2]
	for i, r := range digits {
		if r < '0' || r > '9' {
			digits = digits[:i]
			break
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return -1
	}
	return n
}

// topLevel returns a setting outside the plugins, the value of a command-line
// flag first.
func (c *mqlContainerd) topLevel(flag string, keys []string) (any, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	if flag != "" {
		return flag, nil
	}
	v, _ := containerdLookup(cfg.merged, keys, effectiveContainerdMajor(c.major, cfg.version) == 2)
	return v, nil
}

func (c *mqlContainerd) topLevelString(flag string, keys []string, def string) (string, error) {
	v, err := c.topLevel(flag, keys)
	if err != nil {
		return "", err
	}
	if s, ok := v.(string); ok && s != "" {
		return s, nil
	}
	return def, nil
}

func (c *mqlContainerd) root() (string, error) {
	c.load()
	return c.topLevelString(c.flags.root, []string{"root"}, "/var/lib/containerd")
}

func (c *mqlContainerd) state() (string, error) {
	c.load()
	return c.topLevelString(c.flags.state, []string{"state"}, "/run/containerd")
}

// The plugins that hold the API server settings from configuration version 4
// (containerd 2.3) on, which earlier versions keep in the [grpc] table.
const (
	containerdGRPCPlugin    = "io.containerd.server.v1.grpc"
	containerdGRPCTCPPlugin = "io.containerd.server.v1.grpc-tcp"
)

// serverSetting returns an API server setting: from its plugin's section when
// the files have one, as containerd 2.3 only migrates the [grpc] table to a
// plugin that has none, else from the [grpc] table.
func (cfg *containerdConfig) serverSetting(plugin, key string, legacy []string, fold bool) any {
	plugins, _ := cfg.merged["plugins"].(map[string]any)
	if section, ok := plugins[plugin].(map[string]any); ok {
		v, _ := containerdGet(section, key, fold)
		return v
	}
	v, _ := containerdLookup(cfg.merged, legacy, fold)
	return v
}

func (c *mqlContainerd) server(plugin, key string, legacy []string) (any, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	return cfg.serverSetting(plugin, key, legacy, effectiveContainerdMajor(c.major, cfg.version) == 2), nil
}

func (c *mqlContainerd) grpcAddress() (string, error) {
	c.load()
	if c.flags.address != "" {
		return c.flags.address, nil
	}
	v, err := c.server(containerdGRPCPlugin, "address", []string{"grpc", "address"})
	if err != nil {
		return "", err
	}
	if s, ok := v.(string); ok && s != "" {
		return s, nil
	}
	return containerdSocket, nil
}

func (c *mqlContainerd) grpcUid() (int64, error) {
	v, err := c.server(containerdGRPCPlugin, "uid", []string{"grpc", "uid"})
	n, _ := v.(int64)
	return n, err
}

func (c *mqlContainerd) grpcGid() (int64, error) {
	v, err := c.server(containerdGRPCPlugin, "gid", []string{"grpc", "gid"})
	n, _ := v.(int64)
	return n, err
}

func (c *mqlContainerd) grpcTcpAddress() (string, error) {
	v, err := c.server(containerdGRPCTCPPlugin, "address", []string{"grpc", "tcp_address"})
	s, _ := v.(string)
	return s, err
}

func (c *mqlContainerd) disabledPlugins() ([]any, error) {
	v, err := c.topLevel("", []string{"disabled_plugins"})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, s := range containerdStrings(v) {
		res = append(res, s)
	}
	return res, nil
}

func (c *mqlContainerd) sandboxImage() (string, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return "", err
	}
	img, ok := cfg.sandboxImage(c.ver)
	if !ok {
		c.SandboxImage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return img, nil
}

// sandboxImage returns the pod sandbox image of a containerd release: the one
// the files set, else the release's built-in one.
func (cfg *containerdConfig) sandboxImage(version string) (string, bool) {
	v, ok := cfg.effective(containerdMajor(version), containerdSandboxImage)
	if s, isString := v.(string); ok && isString {
		return s, true
	}
	if containerdMinor(version) == "1.6" {
		// 1.6.9 moved the image to registry.k8s.io
		switch patch := containerdPatchNumber(version); {
		case patch >= 9:
			return "registry.k8s.io/pause:3.6", true
		case patch >= 0:
			return "k8s.gcr.io/pause:3.6", true
		}
	}
	img, ok := containerdSandboxImages[containerdMinor(version)]
	return img, ok
}

func (c *mqlContainerd) snapshotter() (string, error) {
	return c.stringSetting(&c.Snapshotter, containerdSnapshotter)
}

func (c *mqlContainerd) defaultRuntime() (string, error) {
	return c.stringSetting(&c.DefaultRuntime, containerdDefaultRuntime)
}

func (c *mqlContainerd) enableUnprivilegedPorts() (bool, error) {
	return c.boolSetting(&c.EnableUnprivilegedPorts, containerdRuntimeSetting("enable_unprivileged_ports", false, true))
}

func (c *mqlContainerd) enableUnprivilegedIcmp() (bool, error) {
	return c.boolSetting(&c.EnableUnprivilegedIcmp, containerdRuntimeSetting("enable_unprivileged_icmp", false, true))
}

func (c *mqlContainerd) selinuxEnabled() (bool, error) {
	return c.boolSetting(&c.SelinuxEnabled, containerdRuntimeSetting("enable_selinux", false, false))
}

func (c *mqlContainerd) restrictOomScoreAdj() (bool, error) {
	return c.boolSetting(&c.RestrictOomScoreAdj, containerdRuntimeSetting("restrict_oom_score_adj", false, false))
}

func (c *mqlContainerd) deviceOwnershipFromSecurityContext() (bool, error) {
	return c.boolSetting(&c.DeviceOwnershipFromSecurityContext, containerdRuntimeSetting("device_ownership_from_security_context", false, false))
}

func (c *mqlContainerd) disableApparmor() (bool, error) {
	return c.boolSetting(&c.DisableApparmor, containerdRuntimeSetting("disable_apparmor", false, false))
}

func (c *mqlContainerd) tolerateMissingHugetlbController() (bool, error) {
	return c.boolSetting(&c.TolerateMissingHugetlbController, containerdRuntimeSetting("tolerate_missing_hugetlb_controller", true, true))
}

func (c *mqlContainerd) streamAddress() (string, error) {
	return c.stringSetting(&c.StreamAddress, containerdStreamAddress)
}

func (c *mqlContainerd) streamPort() (int64, error) {
	v, ok, err := c.setting(containerdStreamPort)
	if err != nil {
		return 0, err
	}
	port, isPort := crioPort(v)
	if !ok || !isPort {
		c.StreamPort.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return port, nil
}

func (c *mqlContainerd) streamTlsEnabled() (bool, error) {
	return c.boolSetting(&c.StreamTlsEnabled, containerdStreamTLS)
}

// registryConfigPathList returns the hosts.toml directories, and whether
// they are known.
func (c *mqlContainerd) registryConfigPathList() ([]string, bool, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, false, err
	}
	paths, ok := cfg.registryConfigPaths(c.major)
	return paths, ok, nil
}

// registryConfigPaths returns the hosts.toml directories, and whether they
// are known. containerd 2.x reads its default directories whenever no
// config_path is set and no deprecated registry mirrors are configured.
func (cfg *containerdConfig) registryConfigPaths(major int) ([]string, bool) {
	major = effectiveContainerdMajor(major, cfg.version)
	v, _ := containerdSettingValue(cfg.merged, cfg.version, major, containerdRegistryConfigPath)
	if s, _ := v.(string); s != "" {
		return splitContainerdConfigPath(s), true
	}
	switch major {
	case 1:
		return []string{}, true
	case 2:
		registry, _ := containerdSettingValue(cfg.merged, cfg.version, major, containerdRegistry)
		table, _ := registry.(map[string]any)
		v, _ := containerdGet(table, "mirrors", true)
		if mirrors, _ := v.(map[string]any); len(mirrors) > 0 {
			return []string{}, true
		}
		return splitContainerdConfigPath(containerdDefaultRegistryConfigPath), true
	default:
		return nil, false
	}
}

// splitContainerdConfigPath splits a config_path into its directories.
func splitContainerdConfigPath(s string) []string {
	res := []string{}
	for _, p := range strings.Split(s, ":") {
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func (c *mqlContainerd) registryConfigPaths() ([]any, error) {
	paths, ok, err := c.registryConfigPathList()
	if err != nil {
		return nil, err
	}
	if !ok {
		c.RegistryConfigPaths.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, p := range paths {
		res = append(res, p)
	}
	return res, nil
}

// containerdRuntime is a runtime handler of the CRI configuration.
type containerdRuntime struct {
	Name                         string
	Type                         string
	ShimPath                     string
	Path                         string
	Root                         string
	SystemdCgroup                bool
	PrivilegedWithoutHostDevices bool
	PodAnnotations               []string
	BaseRuntimeSpec              string
}

// containerdRuntimesFrom reads the runtime handlers of a runtimes table, in
// name order.
func containerdRuntimesFrom(table map[string]any, fold bool) []containerdRuntime {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	res := make([]containerdRuntime, 0, len(names))
	for _, name := range names {
		rt, _ := table[name].(map[string]any)
		get := func(m map[string]any, key string) any {
			v, _ := containerdGet(m, key, fold)
			return v
		}
		options, _ := get(rt, "options").(map[string]any)
		r := containerdRuntime{Name: name, PodAnnotations: containerdStrings(get(rt, "pod_annotations"))}
		r.Type, _ = get(rt, "runtime_type").(string)
		r.ShimPath, _ = get(rt, "runtime_path").(string)
		r.BaseRuntimeSpec, _ = get(rt, "base_runtime_spec").(string)
		r.PrivilegedWithoutHostDevices, _ = get(rt, "privileged_without_host_devices").(bool)
		// the options go to the runtime as they are written
		r.Path, _ = options["BinaryName"].(string)
		r.Root, _ = options["Root"].(string)
		r.SystemdCgroup, _ = options["SystemdCgroup"].(bool)
		res = append(res, r)
	}
	return res
}

// effectiveContainerdRuntimes returns the runtime handlers containerd runs
// with. containerd 2.x keeps its built-in runc handler next to the ones the
// files add, with the files' runc settings applied over it, and migrates the handlers of a version 2 configuration to the
// ones of version 3 that do not exist yet. containerd 1.x has only the
// handlers of the files once they set any.
func effectiveContainerdRuntimes(cfg map[string]any, version int64, major int) map[string]any {
	plugins, _ := cfg["plugins"].(map[string]any)
	v2, _ := containerdLookup(plugins, containerdRuntimes.v2, major == 2)
	v3, _ := containerdLookup(plugins, containerdRuntimes.v3, major == 2)
	v2Table, _ := v2.(map[string]any)
	v3Table, _ := v3.(map[string]any)

	res := map[string]any{}
	switch {
	case major == 1:
		for k, v := range v2Table {
			res[k] = v
		}
	case version >= 3:
		for k, v := range v3Table {
			res[k] = v
		}
	default:
		for k, v := range v3Table {
			res[k] = v
		}
		for k, v := range v2Table {
			if _, ok := res[k]; !ok {
				res[k] = v
			}
		}
	}

	builtin := map[string]any{"runtime_type": "io.containerd.runc.v2"}
	switch {
	case major != 1:
		// the files' runc settings apply over the built-in runc handler
		if rt, ok := res["runc"].(map[string]any); ok {
			merged := map[string]any{}
			mergeContainerdTables(merged, builtin)
			mergeContainerdTables(merged, rt)
			builtin = merged
		}
		res["runc"] = builtin
	case len(res) == 0:
		res["runc"] = builtin
	}
	return res
}

func (c *mqlContainerd) runtimes() ([]any, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	def := c.GetDefaultRuntime()
	major := effectiveContainerdMajor(c.major, cfg.version)
	res := []any{}
	for _, rt := range containerdRuntimesFrom(effectiveContainerdRuntimes(cfg.merged, cfg.version, major), major == 2) {
		annotations := make([]any, 0, len(rt.PodAnnotations))
		for _, a := range rt.PodAnnotations {
			annotations = append(annotations, a)
		}
		r, err := CreateResource(c.MqlRuntime, "containerd.runtime", map[string]*llx.RawData{
			"__id":                         llx.StringData("containerd.runtime/" + rt.Name),
			"name":                         llx.StringData(rt.Name),
			"type":                         llx.StringData(rt.Type),
			"shimPath":                     llx.StringData(rt.ShimPath),
			"path":                         llx.StringData(rt.Path),
			"root":                         llx.StringData(rt.Root),
			"systemdCgroup":                llx.BoolData(rt.SystemdCgroup),
			"privilegedWithoutHostDevices": llx.BoolData(rt.PrivilegedWithoutHostDevices),
			"podAnnotations":               llx.ArrayData(annotations, types.String),
			"baseRuntimeSpec":              llx.StringData(rt.BaseRuntimeSpec),
			"isDefault":                    llx.BoolData(def.Error == nil && def.Data == rt.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

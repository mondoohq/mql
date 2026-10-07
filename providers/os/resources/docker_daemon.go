// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	// dockerDaemonConfigFile is where dockerd reads its configuration from
	// unless --config-file names another file.
	dockerDaemonConfigFile = "/etc/docker/daemon.json"
	// dockerDefaultHost is the address dockerd listens on when no host is
	// configured.
	dockerDefaultHost = "unix:///var/run/docker.sock"
)

type mqlDockerDaemonInternal struct {
	lock   sync.Mutex
	loaded bool
	// proc is the running dockerd, nil when there is none
	proc *mqlProcess
	// cmdline is what its command line sets
	cmdline dockerdCommandLine
}

// initDockerDaemon makes `docker.daemon` the same resource whether it is
// reached through the docker field or by its own name: every field reads the
// target on demand, so neither needs anything from the other.
func initDockerDaemon(_ *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return args, nil, nil
}

func (d *mqlDocker) daemon() (*mqlDockerDaemon, error) {
	r, err := NewResource(d.MqlRuntime, "docker.daemon", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return r.(*mqlDockerDaemon), nil
}

// load finds the running dockerd and parses its command line, once.
func (d *mqlDockerDaemon) load() {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.loaded {
		return
	}
	d.loaded = true
	d.cmdline = dockerdCommandLine{settings: map[string]any{}}

	proc := findDockerdProcess(d.MqlRuntime)
	if proc == nil {
		return
	}
	command := proc.GetCommand()
	if command.Error != nil {
		log.Debug().Err(command.Error).Msg("docker.daemon> cannot read the dockerd command line")
		return
	}
	d.proc = proc
	d.cmdline = parseDockerdCommandLine(command.Data)
}

// findDockerdProcess returns the running dockerd, or nil when there is none or
// the process list cannot be read, as on an image or a mounted filesystem.
func findDockerdProcess(runtime *plugin.Runtime) *mqlProcess {
	obj, err := CreateResource(runtime, "processes", nil)
	if err != nil {
		return nil
	}
	list := obj.(*mqlProcesses).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("docker.daemon> cannot list processes")
		return nil
	}
	for _, p := range list.Data {
		proc := p.(*mqlProcess)
		exe := proc.GetExecutable()
		if exe.Error != nil || path.Base(exe.Data) != "dockerd" {
			continue
		}
		// any user can start a process named dockerd, with a --config-file of
		// their choosing, so the same admission rules as for the kubelet apply
		if kubeletProcessAllowed(runtime, proc) {
			return proc
		}
	}
	return nil
}

func (d *mqlDockerDaemon) process() (*mqlProcess, error) {
	d.load()
	if d.proc == nil {
		d.Process.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return d.proc, nil
}

func (d *mqlDockerDaemon) configFile() (*mqlFile, error) {
	d.load()
	p := d.cmdline.configFile
	if p == "" {
		p = dockerDaemonConfigFile
	}
	f, err := CreateResource(d.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(p),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (d *mqlDockerDaemon) configuration() (map[string]any, error) {
	d.load()
	f := d.GetConfigFile()
	if f.Error != nil {
		return nil, f.Error
	}
	content := f.Data.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	file, err := parseDockerDaemonJSON(content.Data)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", f.Data.Path.Data, err))
	}
	return mergeDockerDaemonConfig(file, d.cmdline.settings), nil
}

// parseDockerDaemonJSON decodes a daemon.json. An empty file sets nothing.
func parseDockerDaemonJSON(content string) (map[string]any, error) {
	res := map[string]any{}
	if strings.TrimSpace(content) == "" {
		return res, nil
	}
	if err := json.Unmarshal([]byte(content), &res); err != nil {
		return nil, err
	}
	return res, nil
}

// mergeDockerDaemonConfig fills in what the configuration file leaves out
// with what the command line sets. dockerd refuses to start when both set the
// same setting, so the two never disagree on a running daemon.
func mergeDockerDaemonConfig(file map[string]any, flags map[string]any) map[string]any {
	res := make(map[string]any, len(file)+len(flags))
	for k, v := range flags {
		res[k] = v
	}
	for k, v := range file {
		res[k] = v
	}
	return res
}

func (d *mqlDockerDaemon) settings() (map[string]any, error) {
	cfg := d.GetConfiguration()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	m, _ := cfg.Data.(map[string]any)
	return m, nil
}

func (d *mqlDockerDaemon) boolSetting(key string, def bool) (bool, error) {
	cfg, err := d.settings()
	if err != nil {
		return false, err
	}
	return dockerBool(cfg, key, def), nil
}

func (d *mqlDockerDaemon) stringSetting(key string, def string) (string, error) {
	cfg, err := d.settings()
	if err != nil {
		return "", err
	}
	return dockerString(cfg, key, def), nil
}

func (d *mqlDockerDaemon) listSetting(key string) ([]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	return dockerStringList(cfg[key]), nil
}

// dockerBool returns a boolean setting, or def when it is not set.
func dockerBool(cfg map[string]any, key string, def bool) bool {
	if b, ok := cfg[key].(bool); ok {
		return b
	}
	return def
}

// dockerString returns a string setting, or def when it is not set or empty,
// which dockerd treats as not set.
func dockerString(cfg map[string]any, key string, def string) string {
	if s, ok := cfg[key].(string); ok && s != "" {
		return s
	}
	return def
}

func dockerStringList(v any) []any {
	res := []any{}
	list, _ := v.([]any)
	for _, e := range list {
		if s, ok := e.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

func (d *mqlDockerDaemon) icc() (bool, error) {
	return d.boolSetting("icc", true)
}

func (d *mqlDockerDaemon) usernsRemap() (string, error) {
	return d.stringSetting("userns-remap", "")
}

func (d *mqlDockerDaemon) liveRestore() (bool, error) {
	return d.boolSetting("live-restore", false)
}

func (d *mqlDockerDaemon) noNewPrivileges() (bool, error) {
	return d.boolSetting("no-new-privileges", false)
}

func (d *mqlDockerDaemon) userlandProxy() (bool, error) {
	return d.boolSetting("userland-proxy", true)
}

func (d *mqlDockerDaemon) logDriver() (string, error) {
	return d.stringSetting("log-driver", "json-file")
}

func (d *mqlDockerDaemon) logLevel() (string, error) {
	return d.stringSetting("log-level", "info")
}

func (d *mqlDockerDaemon) logOpts() (map[string]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	opts, _ := cfg["log-opts"].(map[string]any)
	for k, v := range opts {
		if s, ok := v.(string); ok {
			res[k] = s
		}
	}
	return res, nil
}

func (d *mqlDockerDaemon) insecureRegistries() ([]any, error) {
	return d.listSetting("insecure-registries")
}

func (d *mqlDockerDaemon) registryMirrors() ([]any, error) {
	return d.listSetting("registry-mirrors")
}

func (d *mqlDockerDaemon) authorizationPlugins() ([]any, error) {
	return d.listSetting("authorization-plugins")
}

func (d *mqlDockerDaemon) hosts() ([]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	return dockerHosts(cfg), nil
}

// dockerHosts returns the addresses dockerd listens on: the configured ones,
// or the default socket when none is configured.
func dockerHosts(cfg map[string]any) []any {
	hosts := dockerStringList(cfg["hosts"])
	if len(hosts) == 0 {
		return []any{dockerDefaultHost}
	}
	return hosts
}

// dockerTLS returns whether the Engine API serves TLS and whether it verifies
// client certificates, the way dockerd decides them: any tlsverify setting,
// true or false, turns TLS on; without one, verification follows tls.
func dockerTLS(cfg map[string]any) (bool, bool) {
	verify, verifySet := cfg["tlsverify"].(bool)
	tls, tlsSet := cfg["tls"].(bool)
	if verifySet {
		return true, verify
	}
	if tlsSet && tls {
		return true, true
	}
	return false, false
}

func (d *mqlDockerDaemon) tls() (bool, error) {
	cfg, err := d.settings()
	if err != nil {
		return false, err
	}
	tls, _ := dockerTLS(cfg)
	return tls, nil
}

func (d *mqlDockerDaemon) tlsVerify() (bool, error) {
	cfg, err := d.settings()
	if err != nil {
		return false, err
	}
	_, verify := dockerTLS(cfg)
	return verify, nil
}

func (d *mqlDockerDaemon) settingFile(field *plugin.TValue[*mqlFile], key string) (*mqlFile, error) {
	p, err := d.stringSetting(key, "")
	if err != nil {
		return nil, err
	}
	if p == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(d.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(p),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (d *mqlDockerDaemon) tlsCaCert() (*mqlFile, error) {
	return d.settingFile(&d.TlsCaCert, "tlscacert")
}

func (d *mqlDockerDaemon) tlsCert() (*mqlFile, error) {
	return d.settingFile(&d.TlsCert, "tlscert")
}

func (d *mqlDockerDaemon) tlsKey() (*mqlFile, error) {
	return d.settingFile(&d.TlsKey, "tlskey")
}

func (d *mqlDockerDaemon) seccompProfile() (string, error) {
	return d.stringSetting("seccomp-profile", "builtin")
}

func (d *mqlDockerDaemon) selinuxEnabled() (bool, error) {
	return d.boolSetting("selinux-enabled", false)
}

func (d *mqlDockerDaemon) cgroupParent() (string, error) {
	return d.stringSetting("cgroup-parent", "")
}

func (d *mqlDockerDaemon) dataRoot() (string, error) {
	return d.stringSetting("data-root", "/var/lib/docker")
}

func (d *mqlDockerDaemon) storageDriver() (string, error) {
	return d.stringSetting("storage-driver", "")
}

func (d *mqlDockerDaemon) experimental() (bool, error) {
	return d.boolSetting("experimental", false)
}

func (d *mqlDockerDaemon) iptables() (bool, error) {
	return d.boolSetting("iptables", true)
}

func (d *mqlDockerDaemon) ipForward() (bool, error) {
	return d.boolSetting("ip-forward", true)
}

func (d *mqlDockerDaemon) defaultRuntime() (string, error) {
	return d.stringSetting("default-runtime", "runc")
}

func (d *mqlDockerDaemon) runtimes() (map[string]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	return dockerRuntimes(cfg), nil
}

// dockerRuntimes maps each registered runtime to its binary, or to its
// runtimeType when it has a containerd shim of its own.
func dockerRuntimes(cfg map[string]any) map[string]any {
	res := map[string]any{}
	runtimes, _ := cfg["runtimes"].(map[string]any)
	for name, v := range runtimes {
		rt, _ := v.(map[string]any)
		target := dockerJSONString(rt, "path")
		if target == "" {
			target = dockerJSONString(rt, "runtimeType")
		}
		res[name] = target
	}
	return res
}

func (d *mqlDockerDaemon) features() (map[string]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	features, _ := cfg["features"].(map[string]any)
	for k, v := range features {
		if b, ok := v.(bool); ok {
			res[k] = b
		}
	}
	return res, nil
}

type dockerUlimit struct {
	name       string
	soft, hard int64
}

// dockerUlimits returns the default-ulimits setting in name order. dockerd
// decodes it with Go's encoding/json, which matches keys regardless of case,
// so "soft" works as well as the documented "Soft".
func dockerUlimits(cfg map[string]any) []dockerUlimit {
	ulimits, _ := cfg["default-ulimits"].(map[string]any)
	res := make([]dockerUlimit, 0, len(ulimits))
	for name, v := range ulimits {
		u, _ := v.(map[string]any)
		res = append(res, dockerUlimit{
			name: name,
			soft: dockerJSONInt(u, "soft"),
			hard: dockerJSONInt(u, "hard"),
		})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].name < res[j].name })
	return res
}

func (d *mqlDockerDaemon) defaultUlimits() ([]any, error) {
	cfg, err := d.settings()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, u := range dockerUlimits(cfg) {
		r, err := CreateResource(d.MqlRuntime, "docker.daemon.ulimit", map[string]*llx.RawData{
			"__id": llx.StringData(u.name),
			"name": llx.StringData(u.name),
			"soft": llx.IntData(u.soft),
			"hard": llx.IntData(u.hard),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// dockerJSONValue looks a key up the way Go's encoding/json does: an exact
// match first, then one that differs only in case.
func dockerJSONValue(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

func dockerJSONString(m map[string]any, key string) string {
	s, _ := dockerJSONValue(m, key).(string)
	return s
}

func dockerJSONInt(m map[string]any, key string) int64 {
	switch v := dockerJSONValue(m, key).(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

// dockerdCommandLine is what a dockerd command line sets: the configuration
// file it names, and its settings keyed as in daemon.json.
type dockerdCommandLine struct {
	configFile string
	settings   map[string]any
}

type dockerdFlagKind int

const (
	dockerdString dockerdFlagKind = iota
	dockerdBool
	dockerdInt
	// a flag that may repeat, collected in a list
	dockerdList
	// a flag that may repeat and holds a comma-separated list
	dockerdCommaList
	// key=value, collected in a map
	dockerdMap
	// name=soft[:hard]
	dockerdUlimitFlag
	// name=path
	dockerdRuntimeFlag
	// name or name=bool
	dockerdFeatureFlag
	// driver=key=value
	dockerdNetworkOptFlag
	// not a daemon setting
	dockerdIgnored
)

type dockerdFlag struct {
	// key is the setting's key in daemon.json
	key  string
	kind dockerdFlagKind
}

// dockerdShortFlags maps dockerd's one-letter flags to their long names.
var dockerdShortFlags = map[byte]string{
	'b': "bridge",
	'D': "debug",
	'G': "group",
	'H': "host",
	'h': "help",
	'l': "log-level",
	'p': "pidfile",
	'r': "restart",
	's': "storage-driver",
	'v': "version",
}

// dockerdFlags lists the dockerd flags whose daemon.json key differs from the
// flag's name, or whose value is not a single string. Any other flag is a
// string setting under its own name.
var dockerdFlags = map[string]dockerdFlag{
	"host":                             {"hosts", dockerdList},
	"registry-mirror":                  {"registry-mirrors", dockerdList},
	"insecure-registry":                {"insecure-registries", dockerdList},
	"authorization-plugin":             {"authorization-plugins", dockerdList},
	"storage-opt":                      {"storage-opts", dockerdList},
	"exec-opt":                         {"exec-opts", dockerdList},
	"label":                            {"labels", dockerdList},
	"dns":                              {"dns", dockerdCommaList},
	"dns-opt":                          {"dns-opts", dockerdList},
	"dns-search":                       {"dns-search", dockerdList},
	"cdi-spec-dir":                     {"cdi-spec-dirs", dockerdList},
	"host-gateway-ip":                  {"host-gateway-ips", dockerdList},
	"node-generic-resource":            {"node-generic-resources", dockerdList},
	"default-address-pool":             {"default-address-pools", dockerdList},
	"log-opt":                          {"log-opts", dockerdMap},
	"default-ulimit":                   {"default-ulimits", dockerdUlimitFlag},
	"add-runtime":                      {"runtimes", dockerdRuntimeFlag},
	"feature":                          {"features", dockerdFeatureFlag},
	"default-network-opt":              {"default-network-opts", dockerdNetworkOptFlag},
	"allow-nondistributable-artifacts": {"allow-nondistributable-artifacts", dockerdList},
	"debug":                            {"debug", dockerdBool},
	"tls":                              {"tls", dockerdBool},
	"tlsverify":                        {"tlsverify", dockerdBool},
	"raw-logs":                         {"raw-logs", dockerdBool},
	"experimental":                     {"experimental", dockerdBool},
	"cri-containerd":                   {"cri-containerd", dockerdBool},
	"selinux-enabled":                  {"selinux-enabled", dockerdBool},
	"iptables":                         {"iptables", dockerdBool},
	"ip6tables":                        {"ip6tables", dockerdBool},
	"ip-forward":                       {"ip-forward", dockerdBool},
	"ip-forward-no-drop":               {"ip-forward-no-drop", dockerdBool},
	"ip-masq":                          {"ip-masq", dockerdBool},
	"ipv6":                             {"ipv6", dockerdBool},
	"icc":                              {"icc", dockerdBool},
	"userland-proxy":                   {"userland-proxy", dockerdBool},
	"allow-direct-routing":             {"allow-direct-routing", dockerdBool},
	"live-restore":                     {"live-restore", dockerdBool},
	"init":                             {"init", dockerdBool},
	"no-new-privileges":                {"no-new-privileges", dockerdBool},
	"rootless":                         {"rootless", dockerdBool},
	"mtu":                              {"mtu", dockerdInt},
	"network-control-plane-mtu":        {"network-control-plane-mtu", dockerdInt},
	"network-diagnostic-port":          {"network-diagnostic-port", dockerdInt},
	"max-concurrent-downloads":         {"max-concurrent-downloads", dockerdInt},
	"max-concurrent-uploads":           {"max-concurrent-uploads", dockerdInt},
	"max-download-attempts":            {"max-download-attempts", dockerdInt},
	"shutdown-timeout":                 {"shutdown-timeout", dockerdInt},
	"cpu-rt-period":                    {"cpu-rt-period", dockerdInt},
	"cpu-rt-runtime":                   {"cpu-rt-runtime", dockerdInt},
	"restart":                          {"", dockerdIgnored},
	"validate":                         {"", dockerdIgnored},
	"version":                          {"", dockerdIgnored},
	"help":                             {"", dockerdIgnored},
}

// dockerdIsBool reports whether a flag takes no value of its own: dockerd's
// boolean flags accept only --flag or --flag=value.
func dockerdIsBool(name string) bool {
	switch name {
	case "restart", "validate", "version", "help":
		return true
	}
	return dockerdFlags[name].kind == dockerdBool
}

// parseDockerdCommandLine reads the flags of a dockerd command line, as the
// process list reports it, with the arguments separated by spaces. dockerd
// takes no arguments besides flags, so a word that is not a flag is the value
// of the flag before it.
func parseDockerdCommandLine(command string) dockerdCommandLine {
	res := dockerdCommandLine{settings: map[string]any{}}
	words := strings.Fields(command)
	if len(words) == 0 {
		return res
	}
	words = words[1:]
	for i := 0; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			break
		}
		var names []string
		value, hasValue := "", false
		switch {
		case strings.HasPrefix(word, "--"):
			name := word[2:]
			if n, v, ok := strings.Cut(name, "="); ok {
				name, value, hasValue = n, v, true
			}
			names = []string{name}
		case strings.HasPrefix(word, "-") && len(word) > 1:
			// one-letter flags may be combined (-Dr); the first that takes
			// a value takes the rest of the word, or the next word
			short := word[1:]
			for j := 0; j < len(short); j++ {
				name, ok := dockerdShortFlags[short[j]]
				if !ok {
					break
				}
				names = append(names, name)
				if dockerdIsBool(name) {
					continue
				}
				if rest := short[j+1:]; rest != "" {
					value, hasValue = strings.TrimPrefix(rest, "="), true
				}
				break
			}
		default:
			continue
		}
		for k, name := range names {
			last := k == len(names)-1
			if dockerdIsBool(name) {
				b := true
				if last && hasValue {
					parsed, err := strconv.ParseBool(value)
					if err != nil {
						continue
					}
					b = parsed
				}
				res.set(name, strconv.FormatBool(b))
				continue
			}
			if !hasValue {
				if i+1 >= len(words) || strings.HasPrefix(words[i+1], "-") {
					continue
				}
				i++
				value = words[i]
			}
			res.set(name, value)
		}
	}
	return res
}

func (c *dockerdCommandLine) set(name string, value string) {
	if name == "config-file" {
		c.configFile = value
		return
	}
	flag, ok := dockerdFlags[name]
	if !ok {
		flag = dockerdFlag{key: name, kind: dockerdString}
	}
	switch flag.kind {
	case dockerdIgnored:
	case dockerdString:
		c.settings[flag.key] = value
	case dockerdBool:
		c.settings[flag.key] = value == "true"
	case dockerdInt:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			c.settings[flag.key] = value
			return
		}
		c.settings[flag.key] = float64(n)
	case dockerdList:
		list, _ := c.settings[flag.key].([]any)
		c.settings[flag.key] = append(list, value)
	case dockerdCommaList:
		list, _ := c.settings[flag.key].([]any)
		for _, v := range strings.Split(value, ",") {
			if v != "" {
				list = append(list, v)
			}
		}
		c.settings[flag.key] = list
	case dockerdMap:
		k, v, _ := strings.Cut(value, "=")
		c.subMap(flag.key)[k] = v
	case dockerdUlimitFlag:
		name, limits, ok := strings.Cut(value, "=")
		if !ok {
			return
		}
		softStr, hardStr, hasHard := strings.Cut(limits, ":")
		soft, err := strconv.ParseInt(softStr, 10, 64)
		if err != nil {
			return
		}
		hard := soft
		if hasHard {
			if hard, err = strconv.ParseInt(hardStr, 10, 64); err != nil {
				return
			}
		}
		c.subMap(flag.key)[name] = map[string]any{
			"Name": name,
			"Soft": float64(soft),
			"Hard": float64(hard),
		}
	case dockerdRuntimeFlag:
		name, p, ok := strings.Cut(value, "=")
		if !ok {
			return
		}
		c.subMap(flag.key)[name] = map[string]any{"path": p}
	case dockerdFeatureFlag:
		name, v, hasValue := strings.Cut(value, "=")
		enabled := true
		if hasValue {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return
			}
			enabled = b
		}
		c.subMap(flag.key)[name] = enabled
	case dockerdNetworkOptFlag:
		driver, opt, ok := strings.Cut(value, "=")
		if !ok {
			return
		}
		k, v, _ := strings.Cut(opt, "=")
		opts := c.subMap(flag.key)
		driverOpts, _ := opts[driver].(map[string]any)
		if driverOpts == nil {
			driverOpts = map[string]any{}
			opts[driver] = driverOpts
		}
		driverOpts[k] = v
	}
}

func (c *dockerdCommandLine) subMap(key string) map[string]any {
	m, _ := c.settings[key].(map[string]any)
	if m == nil {
		m = map[string]any{}
		c.settings[key] = m
	}
	return m
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/aimodel"
	"go.mondoo.com/mql/providers/os/resources/ollama"
	"go.mondoo.com/mql/providers/os/resources/systemd"
	"go.mondoo.com/mql/types"
)

// ollamaBinaryPaths are the locations an Ollama server is installed to when the
// unit does not name one: the path the official install script uses, the one
// distribution packages use, the Homebrew prefixes, and the macOS application
// bundle. The unit's ExecStart= is preferred over all of them, because it is the
// host stating where its own binary is rather than us guessing.
var ollamaBinaryPaths = []string{
	"/usr/local/bin/ollama",
	"/usr/bin/ollama",
	"/bin/ollama",
	"/opt/homebrew/bin/ollama",
	"/usr/local/opt/ollama/bin/ollama",
	"/Applications/Ollama.app/Contents/Resources/ollama",
}

type mqlOllamaConfigInternal struct {
	lock     sync.Mutex
	resolved bool

	// cfg is the effective configuration, nil when no Ollama server is present.
	cfg *ollama.Config
	// unit is the resolved systemd unit, nil when the host has none.
	unit *systemd.UnitEnv

	isInstalled  bool
	serverBinary string
	// ollamaDir is the server account's Ollama directory, the location of
	// server.json and of the default model store.
	ollamaDir string
}

func (c *mqlOllamaConfig) id() (string, error) {
	return "ollama.config", nil
}

// resolve reads the host once and caches the result. Every field goes through
// it, so a query touching twenty settings still walks the filesystem once.
func (c *mqlOllamaConfig) resolve() (*ollama.Config, error) {
	if c.resolved {
		return c.cfg, nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.resolved {
		return c.cfg, nil
	}

	afs := connectionAfs(c.MqlRuntime)

	unit, hasUnit := systemd.ResolveUnitEnv(afs, ollama.UnitName)
	if hasUnit {
		c.unit = unit
	}

	c.serverBinary = c.findBinary(unit)
	c.isInstalled = hasUnit || c.serverBinary != ""

	// The daemon's home decides where the default model store and server.json
	// sit. The unit states it outright on most packaged installations; failing
	// that it is the home of the account named by User=, and failing that the
	// home of the user being scanned.
	home := unit.Vars["HOME"]
	if home == "" && unit.User != "" {
		home = c.homeOfUser(unit.User)
	}
	if home == "" {
		if h, err := targetHomeDir(c.MqlRuntime); err == nil {
			home = h
		}
	}
	if home != "" {
		c.ollamaDir = path.Join(home, ".ollama")
	}

	if !c.isInstalled {
		c.resolved = true
		return nil, nil
	}

	var settings *ollama.ServerSettings
	if c.ollamaDir != "" {
		if data, err := afs.ReadFile(path.Join(c.ollamaDir, "server.json")); err == nil {
			s, err := ollama.ParseServerSettings(data)
			if err != nil {
				log.Debug().Err(err).Str("path", path.Join(c.ollamaDir, "server.json")).
					Msg("mql[ollama.config]> cannot parse server.json")
			} else {
				settings = s
			}
		}
	}

	c.cfg = ollama.Resolve(unit.Vars, home, settings)
	c.cfg.Sources = unit.Sources
	c.cfg.Files = unit.Files()
	c.resolved = true
	return c.cfg, nil
}

// findBinary locates the server binary, preferring the path the unit itself
// names over the well-known installation paths.
func (c *mqlOllamaConfig) findBinary(unit *systemd.UnitEnv) string {
	afs := connectionAfs(c.MqlRuntime)

	if unit != nil && unit.ExecStart != "" {
		candidate := strings.Fields(unit.ExecStart)[0]
		if ok, err := afs.Exists(candidate); err == nil && ok {
			return candidate
		}
	}

	for _, p := range ollamaBinaryPaths {
		if ok, err := afs.Exists(p); err == nil && ok {
			return p
		}
	}
	return ""
}

// homeOfUser resolves a system account's home directory. targetUserHomes filters
// system accounts out by design, and the Ollama daemon runs as one, so the user
// list is consulted directly here.
func (c *mqlOllamaConfig) homeOfUser(name string) string {
	res, err := CreateResource(c.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return ""
	}
	list := res.(*mqlUsers).GetList()
	if list.Error != nil {
		return ""
	}
	for _, u := range list.Data {
		user, ok := u.(*mqlUser)
		if !ok {
			continue
		}
		if user.GetName().Data == name {
			return user.GetHome().Data
		}
	}
	return ""
}

// --- shared accessor plumbing ---
//
// Every setting is null when no Ollama server is installed. Reporting Ollama's
// defaults on a host that does not run it would let a check like
// `listensOnAllInterfaces == false` pass everywhere, which is worse than not
// answering: the check would look satisfied without anything having been read.

func (c *mqlOllamaConfig) str(f *plugin.TValue[string], pick func(*ollama.Config) string) (string, error) {
	cfg, err := c.resolve()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		f.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return pick(cfg), nil
}

func (c *mqlOllamaConfig) bl(f *plugin.TValue[bool], pick func(*ollama.Config) bool) (bool, error) {
	cfg, err := c.resolve()
	if err != nil {
		return false, err
	}
	if cfg == nil {
		f.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return pick(cfg), nil
}

func (c *mqlOllamaConfig) num(f *plugin.TValue[int64], pick func(*ollama.Config) int64) (int64, error) {
	cfg, err := c.resolve()
	if err != nil {
		return 0, err
	}
	if cfg == nil {
		f.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return pick(cfg), nil
}

func (c *mqlOllamaConfig) strList(f *plugin.TValue[[]any], pick func(*ollama.Config) []string) ([]any, error) {
	cfg, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		f.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toAnySlice(pick(cfg)), nil
}

// --- install and provenance ---

func (c *mqlOllamaConfig) installed() (bool, error) {
	if _, err := c.resolve(); err != nil {
		return false, err
	}
	return c.isInstalled, nil
}

func (c *mqlOllamaConfig) binaryPath() (string, error) {
	if _, err := c.resolve(); err != nil {
		return "", err
	}
	if c.serverBinary == "" {
		c.BinaryPath.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return c.serverBinary, nil
}

func (c *mqlOllamaConfig) user() (string, error) {
	if _, err := c.resolve(); err != nil {
		return "", err
	}
	if c.unit == nil || c.unit.User == "" {
		c.User.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return c.unit.User, nil
}

func (c *mqlOllamaConfig) files() ([]any, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}
	if c.unit == nil {
		return []any{}, nil
	}
	return toAnySlice(c.unit.Files()), nil
}

// variables reports the declared Ollama settings. The filter is a reduction
// pending secret flagging in MQL; see the TODO on ollama.IsConfigVar.
func (c *mqlOllamaConfig) variables() (map[string]any, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}
	if c.unit == nil {
		return map[string]any{}, nil
	}
	return toAnyMap(ollama.ConfigVars(c.unit.Vars)), nil
}

func (c *mqlOllamaConfig) variableSources() (map[string]any, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}
	if c.unit == nil {
		return map[string]any{}, nil
	}
	return toAnyMap(ollama.ConfigVars(c.unit.Sources)), nil
}

func (c *mqlOllamaConfig) service() (*mqlService, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}
	if c.unit == nil {
		// Nothing on this host declares a service for the server, so there is
		// no unit to report the state of.
		c.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	name := strings.TrimSuffix(ollama.UnitName, ".service")
	res, err := NewResource(c.MqlRuntime, "service", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlService), nil
}

func (c *mqlOllamaConfig) compute_package() (*mqlPackage, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}
	return resolveToolPackage(c.MqlRuntime, c.ollamaDir, toolPackageSpecs["ollama"])
}

func (c *mqlOllamaConfig) version() (string, error) {
	pkg := c.GetPackage()
	if pkg.Error != nil {
		return "", pkg.Error
	}
	if pkg.Data == nil {
		c.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	v := pkg.Data.GetVersion()
	if v.Error != nil || v.Data == "" {
		c.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return v.Data, nil
}

// --- exposure ---

func (c *mqlOllamaConfig) host() (string, error) {
	return c.str(&c.Host, func(cfg *ollama.Config) string { return cfg.Host })
}

func (c *mqlOllamaConfig) bindAddress() (string, error) {
	return c.str(&c.BindAddress, func(cfg *ollama.Config) string { return cfg.BindAddress })
}

func (c *mqlOllamaConfig) port() (int64, error) {
	return c.num(&c.Port, func(cfg *ollama.Config) int64 { return cfg.Port })
}

func (c *mqlOllamaConfig) listensOnAllInterfaces() (bool, error) {
	return c.bl(&c.ListensOnAllInterfaces, func(cfg *ollama.Config) bool { return cfg.ListensOnAllInterfaces })
}

func (c *mqlOllamaConfig) tls() (bool, error) {
	return c.bl(&c.Tls, func(cfg *ollama.Config) bool { return cfg.TLS })
}

func (c *mqlOllamaConfig) origins() ([]any, error) {
	return c.strList(&c.Origins, func(cfg *ollama.Config) []string { return cfg.Origins })
}

func (c *mqlOllamaConfig) allowsAnyOrigin() (bool, error) {
	return c.bl(&c.AllowsAnyOrigin, func(cfg *ollama.Config) bool { return cfg.AllowsAnyOrigin })
}

func (c *mqlOllamaConfig) authEnabled() (bool, error) {
	return c.bl(&c.AuthEnabled, func(cfg *ollama.Config) bool { return cfg.AuthEnabled })
}

// --- egress ---

func (c *mqlOllamaConfig) cloudEnabled() (bool, error) {
	return c.bl(&c.CloudEnabled, func(cfg *ollama.Config) bool { return cfg.CloudEnabled })
}

func (c *mqlOllamaConfig) cloudDisabledSource() (string, error) {
	return c.str(&c.CloudDisabledSource, func(cfg *ollama.Config) string { return cfg.CloudDisabledSource })
}

func (c *mqlOllamaConfig) remotes() ([]any, error) {
	return c.strList(&c.Remotes, func(cfg *ollama.Config) []string { return cfg.Remotes })
}

func (c *mqlOllamaConfig) httpProxy() (string, error) {
	return c.str(&c.HttpProxy, func(cfg *ollama.Config) string { return cfg.HTTPProxy })
}

func (c *mqlOllamaConfig) httpsProxy() (string, error) {
	return c.str(&c.HttpsProxy, func(cfg *ollama.Config) string { return cfg.HTTPSProxy })
}

func (c *mqlOllamaConfig) noProxy() (string, error) {
	return c.str(&c.NoProxy, func(cfg *ollama.Config) string { return cfg.NoProxy })
}

// --- data handling ---

func (c *mqlOllamaConfig) debugLogRequests() (bool, error) {
	return c.bl(&c.DebugLogRequests, func(cfg *ollama.Config) bool { return cfg.DebugLogRequests })
}

func (c *mqlOllamaConfig) historyEnabled() (bool, error) {
	return c.bl(&c.HistoryEnabled, func(cfg *ollama.Config) bool { return cfg.HistoryEnabled })
}

func (c *mqlOllamaConfig) logLevel() (string, error) {
	return c.str(&c.LogLevel, func(cfg *ollama.Config) string { return cfg.LogLevel })
}

func (c *mqlOllamaConfig) noPrune() (bool, error) {
	return c.bl(&c.NoPrune, func(cfg *ollama.Config) bool { return cfg.NoPrune })
}

// --- capacity and tuning ---

func (c *mqlOllamaConfig) keepAliveSeconds() (int64, error) {
	return c.num(&c.KeepAliveSeconds, func(cfg *ollama.Config) int64 { return cfg.KeepAliveSeconds })
}

func (c *mqlOllamaConfig) loadTimeoutSeconds() (int64, error) {
	return c.num(&c.LoadTimeoutSeconds, func(cfg *ollama.Config) int64 { return cfg.LoadTimeoutSeconds })
}

func (c *mqlOllamaConfig) contextLength() (int64, error) {
	return c.num(&c.ContextLength, func(cfg *ollama.Config) int64 { return cfg.ContextLength })
}

func (c *mqlOllamaConfig) numParallel() (int64, error) {
	return c.num(&c.NumParallel, func(cfg *ollama.Config) int64 { return cfg.NumParallel })
}

func (c *mqlOllamaConfig) maxLoadedModels() (int64, error) {
	return c.num(&c.MaxLoadedModels, func(cfg *ollama.Config) int64 { return cfg.MaxLoadedModels })
}

func (c *mqlOllamaConfig) maxQueue() (int64, error) {
	return c.num(&c.MaxQueue, func(cfg *ollama.Config) int64 { return cfg.MaxQueue })
}

func (c *mqlOllamaConfig) gpuOverhead() (int64, error) {
	return c.num(&c.GpuOverhead, func(cfg *ollama.Config) int64 { return cfg.GpuOverhead })
}

func (c *mqlOllamaConfig) flashAttention() (bool, error) {
	return c.bl(&c.FlashAttention, func(cfg *ollama.Config) bool { return cfg.FlashAttention })
}

func (c *mqlOllamaConfig) schedSpread() (bool, error) {
	return c.bl(&c.SchedSpread, func(cfg *ollama.Config) bool { return cfg.SchedSpread })
}

func (c *mqlOllamaConfig) kvCacheType() (string, error) {
	return c.str(&c.KvCacheType, func(cfg *ollama.Config) string { return cfg.KvCacheType })
}

func (c *mqlOllamaConfig) llmLibrary() (string, error) {
	return c.str(&c.LlmLibrary, func(cfg *ollama.Config) string { return cfg.LlmLibrary })
}

// --- model store ---

func (c *mqlOllamaConfig) modelsPath() (string, error) {
	return c.str(&c.ModelsPath, func(cfg *ollama.Config) string { return cfg.ModelsPath })
}

func (c *mqlOllamaConfig) models() ([]any, error) {
	cfg, err := c.resolve()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.ModelsPath == "" {
		c.Models.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	afs := connectionAfs(c.MqlRuntime)
	var out []any
	for _, m := range aimodel.DetectOllamaModels(afs, cfg.ModelsPath) {
		res, err := newAiModelResource(c.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- integrations ---

func (c *mqlOllamaConfig) integrations() ([]any, error) {
	if _, err := c.resolve(); err != nil {
		return nil, err
	}

	users, err := targetUserHomes(c.MqlRuntime)
	if err != nil {
		log.Debug().Err(err).Msg("mql[ollama.config]> cannot enumerate users for Ollama integrations")
		return []any{}, nil
	}

	afs := connectionAfs(c.MqlRuntime)
	var out []any
	for _, u := range users {
		configPath := path.Join(u.home, ".ollama", "config.json")
		data, err := afs.ReadFile(configPath)
		if err != nil {
			continue
		}

		entries, err := ollama.ParseIntegrations(data)
		if err != nil {
			// One user's unreadable file must not take the other users' entries
			// down with it.
			log.Debug().Err(err).Str("path", configPath).
				Msg("mql[ollama.config]> cannot parse Ollama integration config")
			continue
		}

		for _, e := range entries {
			res, err := CreateResource(c.MqlRuntime, "ollama.config.integration", map[string]*llx.RawData{
				"name":       llx.StringData(e.Name),
				"user":       llx.StringData(u.name),
				"modelNames": llx.ArrayData(toAnySlice(e.Models), types.String),
				"aliases":    llx.MapData(toAnyMap(e.Aliases), types.String),
				"onboarded":  llx.BoolData(e.Onboarded),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func (i *mqlOllamaConfigIntegration) models() ([]any, error) {
	names := i.GetModelNames()
	if names.Error != nil {
		return nil, names.Error
	}
	if len(names.Data) == 0 {
		return []any{}, nil
	}

	res, err := CreateResource(i.MqlRuntime, "ollama.config", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	cfg, ok := res.(*mqlOllamaConfig)
	if !ok {
		return nil, errors.New("cannot resolve ollama.config for integration models")
	}

	store := cfg.GetModels()
	if store.Error != nil {
		return nil, store.Error
	}

	// Resolve against the store that is already fetched rather than creating a
	// model resource per name: the store is one walk, and a name the host does
	// not have must resolve to nothing rather than to an empty model.
	byName := map[string]any{}
	for _, m := range store.Data {
		model, ok := m.(*mqlAiModel)
		if !ok {
			continue
		}
		byName[model.GetName().Data] = m
	}

	var out []any
	for _, n := range names.Data {
		name, ok := n.(string)
		if !ok {
			continue
		}
		if m, ok := matchOllamaModel(byName, name); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// matchOllamaModel resolves a configured model name against the model store.
//
// Ollama treats an untagged name as implicitly :latest - `ollama run qwen3.5`
// and `ollama run qwen3.5:latest` are the same model - but the store reports
// the fully qualified name. An integration that records the bare name found
// nothing, so `models` came back empty on a host that had the model pulled.
func matchOllamaModel(byName map[string]any, name string) (any, bool) {
	if m, ok := byName[name]; ok {
		return m, true
	}
	if !strings.Contains(name, ":") {
		if m, ok := byName[name+":latest"]; ok {
			return m, true
		}
	}
	// The reverse also happens: a config pinned to :latest against a store
	// entry that reports the bare name.
	if base, tag, found := strings.Cut(name, ":"); found && tag == "latest" {
		if m, ok := byName[base]; ok {
			return m, true
		}
	}
	return nil, false
}

// id carries the user as well as the tool name: the integrations are per-user,
// so two accounts may both configure "claude", and keying on the name alone
// would cache the first one and report it again for the second.
func (i *mqlOllamaConfigIntegration) id() (string, error) {
	return "ollama.config.integration/" + i.User.Data + "/" + i.Name.Data, nil
}

// ollamaModelDirs returns every Ollama model store on the host: the one the
// server is configured with, plus each user's own. A user who runs `ollama
// serve` themselves keeps models under their home, while the packaged service
// keeps them wherever its unit says, so neither location alone is enough.
func ollamaModelDirs(runtime *plugin.Runtime) []string {
	seen := map[string]struct{}{}
	var dirs []string
	add := func(d string) {
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		dirs = append(dirs, d)
	}

	if res, err := CreateResource(runtime, "ollama.config", map[string]*llx.RawData{}); err == nil {
		if cfg, ok := res.(*mqlOllamaConfig); ok {
			if p := cfg.GetModelsPath(); p.Error == nil {
				add(p.Data)
			}
		}
	}

	users, err := targetUserHomes(runtime)
	if err != nil {
		log.Debug().Err(err).Msg("mql[ollama]> cannot enumerate users for Ollama model stores")
		return dirs
	}
	for _, u := range users {
		add(path.Join(u.home, ".ollama", "models"))
	}
	return dirs
}

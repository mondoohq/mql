// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/pwquality"
	"go.mondoo.com/mql/types"
)

// libpwqualityPackages are the package names libpwquality ships as: the RPM
// distributions, then Debian, Ubuntu and SUSE.
var libpwqualityPackages = []string{"libpwquality", "libpwquality1"}

type mqlPwqualityInternal struct {
	lock        sync.Mutex
	legacy      *bool
	configCache map[string]pwqualityConfig
}

// pwqualityConfig is one configuration file read with its drop-ins.
type pwqualityConfig struct {
	settings pwquality.Settings
	paths    []string
}

func (s *mqlPwquality) id() (string, error) {
	return "pwquality", nil
}

// isLegacy reports whether the installed libpwquality is older than 1.3.0,
// which read no drop-ins and had other defaults. Without the package, or when
// packages cannot be listed, it assumes a current one.
func (s *mqlPwquality) isLegacy() bool {
	if s.legacy != nil {
		return *s.legacy
	}
	res := false
	for _, name := range libpwqualityPackages {
		raw, err := NewResource(s.MqlRuntime, "package", map[string]*llx.RawData{"name": llx.StringData(name)})
		if err != nil {
			log.Debug().Err(err).Str("package", name).Msg("pwquality> cannot look up the libpwquality package")
			continue
		}
		pkg := raw.(*mqlPackage)
		if installed := pkg.GetInstalled(); installed.Error != nil || !installed.Data {
			continue
		}
		if version := pkg.GetVersion(); version.Error == nil {
			res = pwquality.IsLegacy(version.Data)
		}
		break
	}
	s.legacy = &res
	return res
}

// configPaths lists the files libpwquality reads for the configuration file
// cfg, in order, keeping those that exist.
func (s *mqlPwquality) configPaths(fs afero.Fs, cfg string) ([]string, error) {
	mainExists, err := pwqualityExists(fs, cfg)
	if err != nil {
		return nil, err
	}
	dropIns := !s.isLegacy()
	var etcNames, baseNames []string
	if dropIns {
		if etcNames, err = pwqualityDropIns(fs, cfg+".d"); err != nil {
			return nil, err
		}
		if cfg == pwquality.DefaultFile {
			if baseNames, err = pwqualityDropIns(fs, pwquality.BaseFile+".d"); err != nil {
				return nil, err
			}
		}
	}

	var res []string
	for _, p := range pwquality.Files(cfg, mainExists, etcNames, baseNames, dropIns) {
		ok, err := pwqualityExists(fs, p)
		if err != nil {
			return nil, err
		}
		if ok {
			res = append(res, p)
		}
	}
	return res, nil
}

func pwqualityExists(fs afero.Fs, p string) (bool, error) {
	st, err := fs.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return isRegularTarget(st), nil
}

// pwqualityDropIns lists the names in dir; pwquality.Files keeps the ones
// libpwquality reads. A missing directory has none.
func pwqualityDropIns(fs afero.Fs, dir string) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	var res []string
	for _, e := range entries {
		res = append(res, e.Name())
	}
	sort.Strings(res)
	return res, nil
}

// readConfig reads the settings of the configuration file cfg and its
// drop-ins. Reading stops at the first line libpwquality rejects, as the
// library does.
func (s *mqlPwquality) readConfig(cfg string) (pwquality.Settings, []string, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, nil, errors.New("pwquality requires a connection with a file system")
	}
	fs := conn.FileSystem()
	paths, err := s.configPaths(fs, cfg)
	if err != nil {
		return nil, nil, err
	}

	settings := pwquality.Settings{}
	for _, p := range paths {
		f, err := fs.Open(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %w", p, err)
		}
		err = settings.Apply(p, f)
		f.Close()
		var perr *pwquality.Error
		if errors.As(err, &perr) {
			log.Debug().Err(err).Msg("pwquality> libpwquality stops reading its configuration here")
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %w", p, err)
		}
	}
	return settings, paths, nil
}

// config reads the configuration file cfg and its drop-ins once.
func (s *mqlPwquality) config(cfg string) (pwqualityConfig, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if c, ok := s.configCache[cfg]; ok {
		return c, nil
	}
	settings, paths, err := s.readConfig(cfg)
	if err != nil {
		return pwqualityConfig{}, err
	}
	if s.configCache == nil {
		s.configCache = map[string]pwqualityConfig{}
	}
	c := pwqualityConfig{settings: settings, paths: paths}
	s.configCache[cfg] = c
	return c, nil
}

func (s *mqlPwquality) files() ([]any, error) {
	c, err := s.config(pwquality.DefaultFile)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(c.paths))
	for _, p := range c.paths {
		f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

func (s *mqlPwquality) settings(files []any) (*mqlPwqualitySettings, error) {
	c, err := s.config(pwquality.DefaultFile)
	if err != nil {
		return nil, err
	}
	return newPwqualitySettings(s.MqlRuntime, "pwquality.settings", c.settings, s.isLegacy())
}

func (s *mqlPwquality) pam() ([]any, error) {
	obj, err := CreateResource(s.MqlRuntime, "pam.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	// without any PAM configuration (Photon OS containers, for one) no
	// service checks passwords with pam_pwquality
	exists := obj.(*mqlPamConf).GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return []any{}, nil
	}
	entries := obj.(*mqlPamConf).GetEntries()
	if entries.Error != nil {
		return nil, entries.Error
	}

	services := make([]string, 0, len(entries.Data))
	for service := range entries.Data {
		services = append(services, service)
	}
	sort.Strings(services)

	res := []any{}
	for _, service := range services {
		list, _ := entries.Data[service].([]any)
		for _, raw := range list {
			entry, ok := raw.(*mqlPamConfServiceEntry)
			if !ok || entry.PamType.Data != "password" || !isPwqualityModule(entry.Module.Data) {
				continue
			}
			args := make([]string, 0, len(entry.Options.Data))
			for _, o := range entry.Options.Data {
				if str, ok := o.(string); ok {
					args = append(args, str)
				}
			}

			cfg := pwquality.DefaultFile
			for _, a := range args {
				if c, ok := strings.CutPrefix(a, "conf="); ok {
					cfg = c
				}
			}
			base, err := s.config(cfg)
			if err != nil {
				return nil, err
			}
			settings := base.settings.Clone()
			for _, a := range args {
				settings.ApplyOption(a)
			}

			id := "pwquality.pamModule/" + service + "/" + strconv.FormatInt(entry.LineNumber.Data, 10)
			ps, err := newPwqualitySettings(s.MqlRuntime, id, settings, s.isLegacy())
			if err != nil {
				return nil, err
			}
			mod, err := CreateResource(s.MqlRuntime, "pwquality.pamModule", map[string]*llx.RawData{
				"__id":       llx.StringData(id),
				"service":    llx.StringData(service),
				"lineNumber": llx.IntData(entry.LineNumber.Data),
				"control":    llx.StringData(entry.Control.Data),
				"arguments":  llx.ArrayData(llx.TArr2Raw(args), types.String),
				"settings":   llx.ResourceData(ps, "pwquality.settings"),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mod)
		}
	}
	return res, nil
}

// isPwqualityModule reports whether a PAM module path names pam_pwquality,
// with or without a directory.
func isPwqualityModule(module string) bool {
	return path.Base(module) == "pam_pwquality.so"
}

func newPwqualitySettings(runtime *plugin.Runtime, id string, s pwquality.Settings, legacy bool) (*mqlPwqualitySettings, error) {
	value := func(name string) int64 { return s.Int(name, legacy) }
	params := make(map[string]any, len(s))
	for k, v := range s {
		params[k] = v
	}
	var badwords []any
	for _, w := range strings.Fields(s["badwords"]) {
		badwords = append(badwords, w)
	}

	res, err := CreateResource(runtime, "pwquality.settings", map[string]*llx.RawData{
		"__id":           llx.StringData(id),
		"params":         llx.MapData(params, types.String),
		"difok":          llx.IntData(value("difok")),
		"minlen":         llx.IntData(value("minlen")),
		"dcredit":        llx.IntData(value("dcredit")),
		"ucredit":        llx.IntData(value("ucredit")),
		"lcredit":        llx.IntData(value("lcredit")),
		"ocredit":        llx.IntData(value("ocredit")),
		"minclass":       llx.IntData(value("minclass")),
		"maxrepeat":      llx.IntData(value("maxrepeat")),
		"maxclassrepeat": llx.IntData(value("maxclassrepeat")),
		"maxsequence":    llx.IntData(value("maxsequence")),
		"gecoscheck":     llx.BoolData(value("gecoscheck") != 0),
		"dictcheck":      llx.BoolData(value("dictcheck") != 0),
		"usercheck":      llx.BoolData(value("usercheck") != 0),
		"usersubstr":     llx.IntData(value("usersubstr")),
		"enforcing":      llx.BoolData(value("enforcing") != 0),
		"retry":          llx.IntData(value("retry")),
		"enforceForRoot": llx.BoolData(value("enforce_for_root") != 0),
		"localUsersOnly": llx.BoolData(value("local_users_only") != 0),
		"badwords":       llx.ArrayData(badwords, types.String),
		"dictpath":       llx.StringData(s["dictpath"]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPwqualitySettings), nil
}

// initPwqualitySettings makes `pwquality.settings` queried by its own path the
// settings of the configuration files, which the field of the same name
// returns.
func initPwqualitySettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "pwquality", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	settings := obj.(*mqlPwquality).GetSettings()
	if settings.Error != nil {
		return nil, nil, settings.Error
	}
	return nil, settings.Data, nil
}

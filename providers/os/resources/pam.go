// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/pam"
	"go.mondoo.com/mql/types"
)

const (
	defaultPamConf = "/etc/pam.conf"
	defaultPamDir  = "/etc/pam.d"
)

// pamServiceDirs lists the directories Linux-PAM reads a service's
// configuration from, in lookup order: the admin's /etc/pam.d, then the
// distribution defaults in /usr/lib/pam.d, then the vendor directory
// (/usr/etc/pam.d on distributions built with --enable-vendordir=/usr/etc).
// The first file named after the service wins, so a file in /etc/pam.d
// shadows the vendor copy. see libpam/pam_handlers.c: _pam_open_config_file
var pamServiceDirs = []string{defaultPamDir, "/usr/lib/pam.d", "/usr/etc/pam.d"}

// isPamServiceDir reports whether the file lives directly in one of the
// per-service PAM directories, where the file name is the service name.
func isPamServiceDir(filePath string) bool {
	dir := filepath.Dir(filePath)
	for _, d := range pamServiceDirs {
		if dir == d {
			return true
		}
	}
	return false
}

// pamPathExists reports whether path exists on the target.
func pamPathExists(runtime *plugin.Runtime, path string) (bool, error) {
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return false, err
	}
	exist := raw.(*mqlFile).GetExists()
	return exist.Data, exist.Error
}

func initPamConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["files"] = llx.ArrayData([]any{f}, types.Resource("file"))
		delete(args, "path")
	}

	return args, nil, nil
}

func (s *mqlPamConf) id() (string, error) {
	checksum := checksums.New
	for i := range s.Files.Data {
		path := s.Files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}

	return checksum.String(), nil
}

func (se *mqlPamConfServiceEntry) id() (string, error) {
	ptype := se.PamType.Data
	mod := se.Module.Data
	s := se.Service.Data
	ln := se.LineNumber.Data
	lnstr := strconv.FormatInt(ln, 10)

	id := s + "/" + lnstr + "/" + ptype

	// for include mod is empty
	if mod != "" {
		id += "/" + mod
	}

	return id, nil
}

// exists reports whether any PAM configuration is present, checking the
// pam.d directories and the single-file pam.conf the same way files() selects
// between them. Unlike files() it never errors when nothing is found, so
// audits can guard PAM checks on hosts that ship no PAM configuration.
func (s *mqlPamConf) exists() (bool, error) {
	for _, path := range append(append([]string{}, pamServiceDirs...), defaultPamConf) {
		exist, err := pamPathExists(s.MqlRuntime, path)
		if err != nil {
			return false, err
		}
		if exist {
			return true, nil
		}
	}
	return false, nil
}

// GetFiles is called when the user has not provided a custom path. Otherwise files are set in the init
// method and this function is never called then since the data is already cached.
func (s *mqlPamConf) files() ([]any, error) {
	// Linux-PAM uses the per-service directories when any of them exists and
	// ignores the legacy single-file /etc/pam.conf entirely; only when none
	// exists does it fall back to /etc/pam.conf. Within the directories it
	// loads the first file named after the service, in pamServiceDirs order.
	// We parse the same files PAM itself loads so audits reflect the
	// effective configuration rather than shadowed or dead files.
	// see http://www.linux-pam.org/Linux-PAM-html/sag-configuration.html
	var res []any
	seen := map[string]struct{}{}
	anyDir := false
	for _, dir := range pamServiceDirs {
		exist, err := pamPathExists(s.MqlRuntime, dir)
		if err != nil {
			return nil, err
		}
		if !exist {
			continue
		}
		anyDir = true

		files, err := getSortedPathFiles(s.MqlRuntime, dir)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			service := strings.TrimPrefix(f.(*mqlFile).Path.Data, dir+"/")
			if _, ok := seen[service]; ok {
				continue
			}
			seen[service] = struct{}{}
			res = append(res, f)
		}
	}

	if !anyDir {
		return getSortedPathFiles(s.MqlRuntime, defaultPamConf)
	}
	return res, nil
}

func (s *mqlPamConf) content(files []any) (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	var res strings.Builder
	var notReadyError error = nil

	for i := range files {
		file := files[i].(*mqlFile)

		f, err := conn.FileSystem().Open(file.Path.Data)
		if err != nil {
			return "", err
		}

		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return "", err
		}

		res.WriteString(string(raw))
		res.WriteString("\n")
	}

	if notReadyError != nil {
		return "", notReadyError
	}

	return res.String(), nil
}

func (s *mqlPamConf) services(files []any) (map[string]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	contents := map[string]string{}
	var notReadyError error = nil

	for i := range files {
		file := files[i].(*mqlFile)

		f, err := conn.FileSystem().Open(file.Path.Data)
		if err != nil {
			return nil, err
		}

		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}

		contents[file.Path.Data] = string(raw)
	}

	if notReadyError != nil {
		return nil, notReadyError
	}

	services := map[string]any{}
	for basename, content := range contents {
		lines := strings.Split(content, "\n")
		settings := []any{}
		var line string
		for i := range lines {
			line = lines[i]

			if idx := strings.Index(line, "#"); idx >= 0 {
				line = line[0:idx]
			}
			line = strings.Trim(line, " \t\r")

			if line != "" {
				settings = append(settings, line)
			}
		}
		services[basename] = settings
	}

	return services, nil
}

// canonicalizePamModuleName strips a leading path and `.so` suffix from a PAM
// module reference so callers can look modules up by short name. Case is
// preserved — PAM module names are conventionally lowercase, but we don't
// fold them.
func canonicalizePamModuleName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.TrimSuffix(name, ".so")
	return name
}

// aggregatePamParams merges `key=value` options from one or more service
// entries into a single dict. Bare options without `=` are stored with an
// empty string value so `params["use_authtok"] != null` works as an
// existence check. Later occurrences of the same key overwrite earlier
// ones, matching how PAM itself evaluates duplicate flags.
func aggregatePamParams(optionLists ...[]any) map[string]any {
	params := map[string]any{}
	for _, opts := range optionLists {
		for _, raw := range opts {
			token, ok := raw.(string)
			if !ok {
				continue
			}
			if token == "" {
				continue
			}
			if idx := strings.Index(token, "="); idx >= 0 {
				key := strings.ToLower(token[:idx])
				value := token[idx+1:]
				params[key] = value
			} else {
				params[strings.ToLower(token)] = ""
			}
		}
	}
	return params
}

// params parses this entry's raw options into key/value pairs, applying the
// same rules as the aggregated pam.module.params (see aggregatePamParams).
func (se *mqlPamConfServiceEntry) params(options []any) (map[string]any, error) {
	return aggregatePamParams(options), nil
}

// isPamControlEnabled reports whether a PAM control directive counts as
// "the module is loaded". Bracketed controls that explicitly route the
// module to ignore/skip don't count.
func isPamControlEnabled(control string) bool {
	c := strings.TrimSpace(control)
	if c == "" {
		return false
	}
	// Bracketed controls: `[default=ignore]` / `[default=skip]` mean the
	// module is referenced but its result is discarded — treat as not
	// enabled. Any other bracketed form (e.g. `[success=1 default=bad]`,
	// `[default=die]`) is a real load.
	if strings.HasPrefix(c, "[") {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "default=ignore") || strings.Contains(lower, "default=skip") {
			return false
		}
		return true
	}
	// Bare controls: required, requisite, sufficient, optional,
	// substack, include — all count as loaded.
	return true
}

func initPamModule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'name', it must be a string")
	}
	name = canonicalizePamModuleName(name)

	conf, err := CreateResource(runtime, "pam.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	pamConf := conf.(*mqlPamConf)

	modules := pamConf.GetModules()
	if modules.Error != nil {
		return nil, nil, modules.Error
	}

	for _, m := range modules.Data {
		mod, ok := m.(*mqlPamModule)
		if !ok {
			continue
		}
		if mod.Name.Data == name {
			return nil, mod, nil
		}
	}

	// Module is not referenced by any service — return an empty husk.
	res, err := CreateResource(runtime, "pam.module", map[string]*llx.RawData{
		"name":    llx.StringData(name),
		"params":  llx.MapData(map[string]any{}, types.String),
		"enabled": llx.BoolData(false),
		"entries": llx.ArrayData([]any{}, types.Resource("pam.conf.serviceEntry")),
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (m *mqlPamModule) id() (string, error) {
	return "pam.module/" + m.Name.Data, nil
}

// buildPamModules aggregates the given service entries by canonical module
// name and returns one pam.module resource per distinct module, in first-seen
// order. idScope namespaces the cache key: pass "" for the global view across
// all services, or a service name so a per-service module
// (e.g. pam.module/su/pam_wheel) does not collide with the global aggregation
// (pam.module/pam_wheel), which can have different enabled/params values.
func buildPamModules(runtime *plugin.Runtime, entries map[string]any, idScope string) ([]any, error) {
	// Collect entries grouped by canonical module name, preserving source
	// order across files for last-write-wins option aggregation.
	type moduleAgg struct {
		name       string
		entries    []any
		optionSets [][]any
		anyEnabled bool
	}

	byName := map[string]*moduleAgg{}
	order := []string{}

	// Iterate services in a stable order so the resulting []pam.module
	// list is deterministic across calls.
	serviceNames := make([]string, 0, len(entries))
	for svc := range entries {
		serviceNames = append(serviceNames, svc)
	}
	sort.Strings(serviceNames)

	for _, svc := range serviceNames {
		raw := entries[svc]
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, e := range list {
			entry, ok := e.(*mqlPamConfServiceEntry)
			if !ok {
				continue
			}
			rawModule := entry.Module.Data
			if rawModule == "" {
				// Skip @include lines and anything that doesn't reference
				// a real module.
				continue
			}
			name := canonicalizePamModuleName(rawModule)
			agg, ok := byName[name]
			if !ok {
				agg = &moduleAgg{name: name}
				byName[name] = agg
				order = append(order, name)
			}
			agg.entries = append(agg.entries, entry)
			agg.optionSets = append(agg.optionSets, entry.Options.Data)
			if isPamControlEnabled(entry.Control.Data) {
				agg.anyEnabled = true
			}
		}
	}

	out := make([]any, 0, len(order))
	for _, name := range order {
		agg := byName[name]
		params := aggregatePamParams(agg.optionSets...)
		modArgs := map[string]*llx.RawData{
			"name":    llx.StringData(agg.name),
			"params":  llx.MapData(params, types.String),
			"enabled": llx.BoolData(agg.anyEnabled),
			"entries": llx.ArrayData(agg.entries, types.Resource("pam.conf.serviceEntry")),
		}
		if idScope != "" {
			modArgs["__id"] = llx.StringData("pam.module/" + idScope + "/" + agg.name)
		}
		res, err := CreateResource(runtime, "pam.module", modArgs)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *mqlPamConf) modules(entries map[string]any) ([]any, error) {
	return buildPamModules(s.MqlRuntime, entries, "")
}

// initPamConfService selects a single PAM service by name and caches its
// parsed entries. The name matches the file PAM loads for the service (e.g.
// "su" -> /etc/pam.d/su, or /usr/lib/pam.d/su when only the distribution
// default exists) or the service column in the single-file /etc/pam.conf. When
// no such service is configured the resource is returned with an empty path
// and no entries rather than an error, so audits can branch on it cleanly.
func initPamConfService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("pam.conf.service requires a 'name'")
	}
	name, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'name', it must be a string")
	}

	conf, err := CreateResource(runtime, "pam.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	pamConf := conf.(*mqlPamConf)

	// No PAM configuration on this host: return an empty service rather than
	// erroring, mirroring pam.conf.exists, so audits don't blow up.
	exists := pamConf.GetExists()
	if exists.Error != nil {
		return nil, nil, exists.Error
	}
	if !exists.Data {
		args["name"] = llx.StringData(name)
		args["path"] = llx.StringData("")
		args["entries"] = llx.ArrayData([]any{}, types.Resource("pam.conf.serviceEntry"))
		return args, nil, nil
	}

	entries := pamConf.GetEntries()
	if entries.Error != nil {
		return nil, nil, entries.Error
	}

	// entries is keyed by the <pam.d dir>/<name> file path, or by the bare
	// service name for single-file /etc/pam.conf. filepath.Base matches both.
	path := ""
	serviceEntries := []any{}
	for key, raw := range entries.Data {
		if filepath.Base(key) != name {
			continue
		}
		if list, ok := raw.([]any); ok {
			serviceEntries = list
		}
		if strings.Contains(key, "/") {
			path = key
		} else {
			path = defaultPamConf
		}
		break
	}

	args["name"] = llx.StringData(name)
	args["path"] = llx.StringData(path)
	args["entries"] = llx.ArrayData(serviceEntries, types.Resource("pam.conf.serviceEntry"))
	return args, nil, nil
}

func (s *mqlPamConfService) id() (string, error) {
	return "pam.conf.service/" + s.Name.Data, nil
}

func (s *mqlPamConfService) modules() (map[string]any, error) {
	entries := s.GetEntries()
	if entries.Error != nil {
		return nil, entries.Error
	}

	// Scope the shared aggregator to this single service and key the result
	// by canonical module name so callers can write modules["pam_wheel"].
	scoped := map[string]any{s.Name.Data: entries.Data}
	mods, err := buildPamModules(s.MqlRuntime, scoped, s.Name.Data)
	if err != nil {
		return nil, err
	}

	out := make(map[string]any, len(mods))
	for _, m := range mods {
		mod := m.(*mqlPamModule)
		out[mod.Name.Data] = mod
	}
	return out, nil
}

func (s *mqlPamConf) entries(files []any) (map[string]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	contents := map[string]string{}
	var notReadyError error = nil

	for i := range files {
		file := files[i].(*mqlFile)

		f, err := conn.FileSystem().Open(file.Path.Data)
		if err != nil {
			return nil, err
		}

		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil, err
		}

		contents[file.Path.Data] = string(raw)
	}

	if notReadyError != nil {
		return nil, notReadyError
	}

	services := map[string]any{}
	for filePath, content := range contents {
		// Files directly under a pam.d directory carry one service each (the
		// file name is the service). The legacy single-file /etc/pam.conf instead
		// prefixes every line with the service name, so its lines have one
		// extra leading column. Detect the layout by whether the file lives
		// in the pam.d directory and group single-file lines by that column.
		singleFile := !isPamServiceDir(filePath)
		if !singleFile {
			// Preserve the empty-service key so e.g.
			// pam.conf.entries["/etc/pam.d/su"] stays an empty list rather
			// than null when the file has no parsable entries.
			if _, ok := services[filePath]; !ok {
				services[filePath] = []any{}
			}
		}

		lines := strings.Split(content, "\n")
		for i := range lines {
			line := lines[i]
			service := filePath

			if singleFile {
				fields := strings.Fields(pam.StripComments(line))
				if len(fields) < 2 {
					// Blank/comment line or one with no module reference.
					continue
				}
				service = fields[0]
				line = strings.Join(fields[1:], " ")
			}

			entry, err := pam.ParseLine(line)
			if err != nil {
				// A single malformed line must not abort parsing of the whole
				// PAM configuration. Log it and continue with the rest, like
				// the other config parsers in this package do.
				log.Warn().Err(err).Str("path", filePath).Int("line", i+1).Msg("skipping malformed PAM line")
				continue
			}

			// empty lines parse as empty object
			if entry == nil {
				continue
			}

			pamEntry, err := CreateResource(s.MqlRuntime, "pam.conf.serviceEntry", map[string]*llx.RawData{
				"service":    llx.StringData(service),
				"lineNumber": llx.IntData(int64(i)), // Used for ID
				"pamType":    llx.StringData(entry.PamType),
				"control":    llx.StringData(entry.Control),
				"module":     llx.StringData(entry.Module),
				"options":    llx.ArrayData(entry.Options, types.String),
			})
			if err != nil {
				return nil, err
			}

			list, _ := services[service].([]any)
			services[service] = append(list, pamEntry.(*mqlPamConfServiceEntry))
		}
	}

	return services, nil
}

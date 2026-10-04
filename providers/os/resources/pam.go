// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// isPamControlEnabled reports whether a PAM control acts on the module's
// result. A bracketed control does not only when every return value is
// ignored: `[default=ignore]` or `[success=ignore default=ignore]`. One
// value that jumps (`success=2`), returns (`ok`, `done`, `bad`, `die`) or
// resets is enough, so pam-auth-update's `[success=2 default=ignore]
// pam_unix.so` runs pam_unix on every authentication. A value the control
// does not name, with no `default=`, counts as `bad` in Linux-PAM.
// see libpam/pam_handlers.c: _pam_parse_control
func isPamControlEnabled(control string) bool {
	c := strings.TrimSpace(control)
	if c == "" {
		return false
	}
	if !strings.HasPrefix(c, "[") {
		// Bare controls: required, requisite, sufficient, optional,
		// substack, include all count as loaded.
		return true
	}
	hasDefault := false
	for _, tok := range strings.Fields(strings.Trim(c, "[]")) {
		value, action, ok := strings.Cut(strings.ToLower(tok), "=")
		if !ok {
			continue
		}
		if value == "default" {
			hasDefault = true
		}
		// `skip` is not a Linux-PAM action; it is kept as "ignore" as it
		// always was here.
		if action != "ignore" && action != "skip" {
			return true
		}
	}
	return !hasDefault
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
			if rawModule == "" || isPamIncludeEntry(entry) {
				// An include line names a file, not a module: skip it like
				// anything else that doesn't reference a real module.
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

// isPamIncludeEntry reports whether the entry is an `@include`, `include` or
// `substack` line, whose module column names a PAM file.
func isPamIncludeEntry(e *mqlPamConfServiceEntry) bool {
	return e.PamType.Data == "@include" ||
		strings.EqualFold(e.Control.Data, "include") ||
		strings.EqualFold(e.Control.Data, "substack")
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
	entries := s.GetStack()
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
		if err := parsePamFile(s.MqlRuntime, filePath, content, isPamSingleFileFormat(filePath, content), services); err != nil {
			return nil, err
		}
	}

	return services, nil
}

// isPamSingleFileFormat reports whether a PAM file uses the legacy
// /etc/pam.conf layout, where every line starts with the service name, rather
// than the pam.d layout, where it starts with the type. A file in a pam.d
// directory is always pam.d format. Any other file, such as one passed to
// pam.conf("<path>") or an authselect profile template, is judged by where
// its lines put the type: first means pam.d format, second the single file.
// Lines with neither, such as authselect's `{imply ...}` directives, do not
// count.
func isPamSingleFileFormat(filePath, content string) bool {
	if isPamServiceDir(filePath) {
		return false
	}
	typeFirst, typeSecond := 0, 0
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(pam.StripComments(line))
		switch {
		case len(fields) == 0:
		case fields[0] == "@include" || pam.IsType(fields[0]):
			typeFirst++
		case len(fields) > 1 && pam.IsType(fields[1]):
			typeSecond++
		}
	}
	return typeFirst <= typeSecond
}

// parsePamFile parses one PAM file into service entries, appended to
// services. A pam.d-format file is one service keyed by its path; a
// single-file /etc/pam.conf groups lines by the service in its first column.
func parsePamFile(runtime *plugin.Runtime, filePath, content string, singleFile bool, services map[string]any) error {
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

		pamEntry, err := CreateResource(runtime, "pam.conf.serviceEntry", map[string]*llx.RawData{
			"service":       llx.StringData(service),
			"lineNumber":    llx.IntData(int64(i)), // Used for ID
			"pamType":       llx.StringData(entry.PamType),
			"ignoreMissing": llx.BoolData(entry.IgnoreMissing),
			"control":       llx.StringData(entry.Control),
			"module":        llx.StringData(entry.Module),
			"options":       llx.ArrayData(entry.Options, types.String),
		})
		if err != nil {
			return err
		}

		list, _ := services[service].([]any)
		services[service] = append(list, pamEntry.(*mqlPamConfServiceEntry))
	}
	return nil
}

const (
	// pamMaxIncludeLevel is Linux-PAM's PAM_SUBSTACK_MAX_LEVEL: a service
	// whose includes nest this deep fails to load.
	pamMaxIncludeLevel = 16
	// pamMaxIncludes caps the include lines one stack expands. Nesting is
	// capped, fan-out is not: a file including another twice per level would
	// expand 2^16 times. Stock configurations expand around ten.
	pamMaxIncludes = 1000
	// pamMaxIncludedFileSize caps an included file read outside the files
	// pam.conf lists.
	pamMaxIncludedFileSize = 1 << 20
)

// pamStack expands the include lines of one service into the entries PAM
// runs. see libpam/pam_handlers.c: _pam_parse_conf_file, _pam_load_conf_file
type pamStack struct {
	runtime *plugin.Runtime
	// entries is pam.conf.entries keyed by file path, plus the files load
	// read itself; nil until the first include needs it
	entries map[string]any
	// includes counts the include lines expanded so far
	includes int
}

// files returns the parsed files known so far, reading pam.conf.entries on
// first use.
func (p *pamStack) files() (map[string]any, error) {
	if p.entries != nil {
		return p.entries, nil
	}
	conf, err := CreateResource(p.runtime, "pam.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := conf.(*mqlPamConf).GetEntries()
	if all.Error != nil {
		return nil, all.Error
	}
	// a copy, so the files load reads do not show up in pam.conf.entries
	p.entries = make(map[string]any, len(all.Data))
	for k, v := range all.Data {
		p.entries[k] = v
	}
	return p.entries, nil
}

// expand returns the entries PAM runs for list, read from file path. filter
// is the type an `include` or `substack` line restricts the included file to
// ("" for every type). An `@include` line keeps the filter it is read under,
// so an `@include` inside an `auth include` still brings in only auth lines.
func (p *pamStack) expand(path string, list []any, filter string, level int) ([]any, error) {
	out := []any{}
	for _, raw := range list {
		e, ok := raw.(*mqlPamConfServiceEntry)
		if !ok {
			continue
		}
		var target, subFilter string
		switch {
		case e.PamType.Data == "@include":
			target, subFilter = e.Control.Data, filter
		case filter != "" && !strings.EqualFold(e.PamType.Data, filter):
			continue
		case strings.EqualFold(e.Control.Data, "include") || strings.EqualFold(e.Control.Data, "substack"):
			target, subFilter = e.Module.Data, strings.ToLower(e.PamType.Data)
		default:
			out = append(out, e)
			continue
		}

		if level+1 >= pamMaxIncludeLevel {
			return nil, fmt.Errorf("%s: PAM includes nest more than %d levels deep", path, pamMaxIncludeLevel)
		}
		p.includes++
		if p.includes > pamMaxIncludes {
			return nil, fmt.Errorf("%s: more than %d PAM include lines to expand", path, pamMaxIncludes)
		}
		includedPath, included, err := p.load(target)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, e.LineNumber.Data+1, err)
		}
		expanded, err := p.expand(includedPath, included, subFilter, level+1)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}
	return out, nil
}

// load returns the path and parsed entries of an included file. An absolute
// name is that file; a relative one is looked up in the pam.d directories in
// the order PAM uses (see _pam_open_config_file). Files pam.conf already
// parsed are reused; any other, such as one outside the pam.d directories, is
// read here.
func (p *pamStack) load(name string) (string, []any, error) {
	candidates := []string{name}
	if !strings.HasPrefix(name, "/") {
		candidates = candidates[:0]
		for _, dir := range pamServiceDirs {
			candidates = append(candidates, dir+"/"+name)
		}
	}

	known, err := p.files()
	if err != nil {
		return "", nil, err
	}
	conn := p.runtime.Connection.(shared.Connection)
	for _, path := range candidates {
		if list, ok := known[path].([]any); ok {
			return path, list, nil
		}
		// Only a regular file is read, and only up to a size: an include
		// naming /dev/zero or a FIFO would otherwise never finish reading.
		st, err := conn.FileSystem().Stat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", nil, err
		}
		if !st.Mode().IsRegular() {
			return "", nil, fmt.Errorf("included PAM file %s is not a regular file", path)
		}
		f, err := conn.FileSystem().Open(path)
		if err != nil {
			return "", nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(f, pamMaxIncludedFileSize+1))
		f.Close()
		if err != nil {
			return "", nil, err
		}
		if len(raw) > pamMaxIncludedFileSize {
			return "", nil, fmt.Errorf("included PAM file %s is larger than %d bytes", path, pamMaxIncludedFileSize)
		}
		parsed := map[string]any{}
		if err := parsePamFile(p.runtime, path, string(raw), false, parsed); err != nil {
			return "", nil, err
		}
		list, _ := parsed[path].([]any)
		known[path] = list
		return path, list, nil
	}
	return "", nil, llx.NotFound(fmt.Errorf("included PAM file %s not found", name))
}

func (s *mqlPamConfService) stack() ([]any, error) {
	entries := s.GetEntries()
	if entries.Error != nil {
		return nil, entries.Error
	}
	p := &pamStack{runtime: s.MqlRuntime}
	return p.expand(s.Path.Data, entries.Data, "", 0)
}

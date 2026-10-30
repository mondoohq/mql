// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/coreos/go-systemd/unit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// systemdConfigUnitPaths are the directories of the search path that hold the
// administrator's configuration. Only an enablement link in one of these
// enables a unit: a link a package ships in /usr/lib/systemd/system/*.wants
// pulls the unit in, but `systemctl list-unit-files` still reports it as
// disabled (systemd-pcrextend.socket on Ubuntu 24.04).
var systemdConfigUnitPaths = []string{
	"/etc/systemd/system.control",
	"/etc/systemd/system",
}

// systemdUnitFile is one unit as `systemctl list-unit-files` reports it,
// read from the unit files on disk.
type systemdUnitFile struct {
	// Name is the unit name with its type, ssh.service or getty@tty1.service.
	Name string
	// State is the unit-file state list-unit-files prints: enabled,
	// disabled, static, indirect, masked, alias or linked.
	State string
	// Target is the unit an alias names, empty for every other state.
	Target string
	// Path is the file systemd loads for the unit: the file a link resolves
	// to, and for an instance the file of its template. Empty when masked.
	Path string
	// Description is the Description= of the unit, with the specifiers of
	// an instance expanded, or the unit name when the file sets none, as
	// systemd reports it.
	Description string

	// rawDescription is Description= as the file sets it, which a
	// template's instances expand
	rawDescription string
	// file is where the unit is on the search path, the link itself for a
	// masked or aliased unit
	file string
}

// unitInstall is what the [Install] section of a unit file says.
type unitInstall struct {
	wantedBy        []string
	alias           []string
	also            []string
	defaultInstance string
}

// enables reports whether the section names anything to link the unit
// from. A unit without it is static.
func (i unitInstall) enables() bool {
	return len(i.wantedBy) > 0 || len(i.alias) > 0
}

// readSystemdUnitFiles returns the units of one type (".service",
// ".socket", ".timer") the way `systemctl list-unit-files` sees them, plus
// the instances of templates that are enabled, which list-unit-files leaves
// out but `systemctl is-enabled` reports. Runtime directories (/run) are not
// read: a filesystem scan does not represent a running system.
func readSystemdUnitFiles(fsys afero.Fs, suffix string) ([]*systemdUnitFile, error) {
	// the first file of a name on the search path is the one systemd uses
	found := map[string]string{}
	// whether the directory listing reported the entry as a symlink, which
	// every file system here does (an lstat): the docker-container file
	// system has no lstat of its own
	linked := map[string]bool{}
	var names []string
	for _, dir := range systemdUnitSearchPath {
		entries, err := afero.ReadDir(fsys, dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, suffix) || len(name) == len(suffix) {
				continue
			}
			if _, ok := found[name]; ok {
				continue
			}
			found[name] = dir
			linked[name] = e.Mode()&fs.ModeSymlink != 0
			names = append(names, name)
		}
	}

	links := systemdEnablementLinks(fsys)

	units := make(map[string]*systemdUnitFile, len(names))
	installs := map[string]unitInstall{}
	for _, name := range names {
		u, install := readSystemdUnitFile(fsys, path.Join(found[name], name), name, linked[name])
		units[name] = u
		installs[name] = install
	}

	for _, name := range names {
		u := units[name]
		if u.State != "" {
			continue
		}
		install := installs[name]
		switch {
		case isSystemdTemplateUnit(name) && install.enables():
			u.State = templateState(name, install, links.wants)
		case links.wants[name] || anyLinked(install.alias, links.aliases):
			// linked from a .wants directory, or under a name its Alias=
			// declares; a unit without an [Install] section is enabled
			// this way too
			u.State = "enabled"
		case links.aliasedTo[name]:
			// linked under a name its Alias= does not declare
			u.State = "indirect"
		case install.enables():
			u.State = "disabled"
		case len(install.also) > 0:
			u.State = "indirect"
		default:
			u.State = "static"
		}
	}

	res := make([]*systemdUnitFile, 0, len(names))
	for _, name := range names {
		res = append(res, units[name])
	}

	// enabled instances of templates, getty@tty1.service from
	// getty.target.wants/getty@tty1.service
	var instances []string
	for link := range links.wants {
		if !strings.HasSuffix(link, suffix) || isSystemdTemplateUnit(link) || !isSystemdInstanceUnit(link) {
			continue
		}
		if _, ok := units[link]; ok {
			continue
		}
		instances = append(instances, link)
	}
	sort.Strings(instances)
	for _, instance := range instances {
		template, ok := units[systemdTemplateOf(instance)]
		if !ok || template.State == "masked" || template.Path == "" {
			continue
		}
		res = append(res, &systemdUnitFile{
			Name:        instance,
			State:       "enabled",
			Path:        template.Path,
			Description: unitDescription(instance, template.rawDescription),
		})
	}
	return res, nil
}

// readSystemdUnitFile reads the unit file at unitPath. The returned unit has
// its State set when the file alone decides it (masked, alias, linked).
func readSystemdUnitFile(fsys afero.Fs, unitPath string, name string, listedAsLink bool) (*systemdUnitFile, unitInstall) {
	u := &systemdUnitFile{Name: name, file: unitPath}
	resolved := unitPath
	if target, isLink := readUnitLink(fsys, unitPath, listedAsLink); isLink {
		if target == "/dev/null" {
			u.State = "masked"
			u.Description = name
			return u, unitInstall{}
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(unitPath), target)
		}
		resolved = target
		if base := path.Base(target); base != name {
			u.State = "alias"
			u.Target = base
		} else if isSystemdConfigUnitPath(path.Dir(unitPath)) && !isOnSystemdSearchPath(target) {
			// a unit file linked into the configuration from outside the
			// search path (`systemctl link`)
			u.State = "linked"
		}
	}
	u.Path = resolved

	f, err := fsys.Open(resolved)
	if err != nil {
		log.Debug().Err(err).Str("unit", unitPath).Msg("mql[systemd]> could not open unit file")
		u.Description = name
		return u, unitInstall{}
	}
	defer f.Close()
	opts, err := unit.Deserialize(f)
	if err != nil {
		log.Debug().Err(err).Str("unit", unitPath).Msg("mql[systemd]> could not parse unit file")
		u.Description = name
		return u, unitInstall{}
	}

	var install unitInstall
	var description string
	for _, o := range opts {
		switch o.Section {
		case "Unit":
			if o.Name == "Description" {
				description = o.Value
			}
		case "Install":
			switch o.Name {
			case "WantedBy", "RequiredBy", "UpheldBy":
				install.wantedBy = append(install.wantedBy, strings.Fields(o.Value)...)
			case "Alias":
				install.alias = append(install.alias, strings.Fields(o.Value)...)
			case "Also":
				install.also = append(install.also, strings.Fields(o.Value)...)
			case "DefaultInstance":
				install.defaultInstance = o.Value
			}
		}
	}
	u.rawDescription = description
	if isSystemdTemplateUnit(name) {
		// a template has no description of its own: systemd reports none
		// until it is instantiated
		u.Description = ""
	} else {
		u.Description = unitDescription(name, description)
	}
	return u, install
}

func isSystemdConfigUnitPath(dir string) bool {
	for _, d := range systemdConfigUnitPaths {
		if d == dir {
			return true
		}
	}
	return false
}

func isOnSystemdSearchPath(p string) bool {
	dir := path.Dir(p)
	for _, d := range systemdUnitSearchPath {
		if d == dir {
			return true
		}
	}
	return false
}

// readUnitLink returns the target of the unit file at p when it is a
// symlink. listedAsLink is what the directory listing said; without it the
// file is lstat'ed where the file system can.
func readUnitLink(fsys afero.Fs, p string, listedAsLink bool) (string, bool) {
	if !listedAsLink {
		lstater, ok := fsys.(afero.Lstater)
		if !ok {
			return "", false
		}
		info, _, err := lstater.LstatIfPossible(p)
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			return "", false
		}
	}
	lr, ok := fsys.(afero.LinkReader)
	if !ok {
		return "", false
	}
	target, err := lr.ReadlinkIfPossible(p)
	if err != nil {
		return "", false
	}
	return target, true
}

// enablementLinks are the links `systemctl enable` creates in the
// configuration directories.
type enablementLinks struct {
	// wants holds the names linked from a .wants, .requires or .upholds
	// directory, and the units those links point at under another name.
	wants map[string]bool
	// aliases holds the names of top-level links to a unit of another name.
	aliases map[string]bool
	// aliasedTo holds the units such a link points at.
	aliasedTo map[string]bool
}

// systemdEnablementLinks reads the enablement links of the configuration
// directories.
func systemdEnablementLinks(fsys afero.Fs) enablementLinks {
	links := enablementLinks{wants: map[string]bool{}, aliases: map[string]bool{}, aliasedTo: map[string]bool{}}
	for _, dir := range systemdConfigUnitPaths {
		entries, err := afero.ReadDir(fsys, dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() {
				target, isLink := readUnitLink(fsys, path.Join(dir, name), e.Mode()&fs.ModeSymlink != 0)
				if !isLink || target == "/dev/null" {
					continue
				}
				if base := path.Base(target); base != name {
					links.aliases[name] = true
					links.aliasedTo[base] = true
				}
				continue
			}
			if !strings.HasSuffix(name, ".wants") && !strings.HasSuffix(name, ".requires") && !strings.HasSuffix(name, ".upholds") {
				continue
			}
			wanted, err := afero.ReadDir(fsys, path.Join(dir, name))
			if err != nil {
				continue
			}
			for _, w := range wanted {
				links.wants[w.Name()] = true
				// a link named after an alias of the unit it points at
				target, isLink := readUnitLink(fsys, path.Join(dir, name, w.Name()), w.Mode()&fs.ModeSymlink != 0)
				if !isLink {
					continue
				}
				base := path.Base(target)
				if base != w.Name() && (!isSystemdInstanceUnit(w.Name()) || systemdTemplateOf(w.Name()) != base) {
					links.wants[base] = true
				}
			}
		}
	}
	return links
}

// templateState is the state of a template unit with an [Install] section:
// enabled when its default instance is linked, indirect when only other
// instances are.
func templateState(name string, install unitInstall, links map[string]bool) string {
	if install.defaultInstance != "" && links[systemdInstanceName(name, install.defaultInstance)] {
		return "enabled"
	}
	prefix, suffix := splitSystemdTemplate(name)
	for link := range links {
		if strings.HasPrefix(link, prefix) && strings.HasSuffix(link, suffix) && len(link) > len(prefix)+len(suffix) {
			return "indirect"
		}
	}
	return "disabled"
}

func anyLinked(names []string, links map[string]bool) bool {
	for _, n := range names {
		if links[n] {
			return true
		}
	}
	return false
}

// splitSystemdTemplate splits foo@.service into "foo@" and ".service".
func splitSystemdTemplate(name string) (string, string) {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return name, ""
	}
	return name[:dot], name[dot:]
}

// systemdInstanceName returns the instance of template foo@.service named
// by instance: foo@instance.service.
func systemdInstanceName(template string, instance string) string {
	prefix, suffix := splitSystemdTemplate(template)
	return prefix + instance + suffix
}

// isSystemdInstanceUnit reports whether name is an instance of a template,
// foo@bar.service.
func isSystemdInstanceUnit(name string) bool {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return false
	}
	at := strings.IndexByte(name[:dot], '@')
	return at > 0 && at < dot-1
}

// systemdTemplateOf returns the template of instance foo@bar.service:
// foo@.service.
func systemdTemplateOf(instance string) string {
	dot := strings.LastIndexByte(instance, '.')
	at := strings.IndexByte(instance, '@')
	return instance[:at+1] + instance[dot:]
}

// unitDescription expands the specifiers systemd expands in Description=
// and falls back to the unit name, as systemd does for a unit that sets no
// description.
func unitDescription(name string, raw string) string {
	if raw == "" {
		return name
	}
	if !strings.Contains(raw, "%") {
		return raw
	}
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		dot = len(name)
	}
	prefix, instance := name[:dot], ""
	if at := strings.IndexByte(prefix, '@'); at >= 0 {
		prefix, instance = name[:at], name[at+1:dot]
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' || i+1 == len(raw) {
			b.WriteByte(raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'n':
			b.WriteString(name)
		case 'N':
			b.WriteString(name[:dot])
		case 'p':
			b.WriteString(prefix)
		case 'P':
			b.WriteString(unescapeSystemdName(prefix))
		case 'i':
			b.WriteString(instance)
		case 'I':
			b.WriteString(unescapeSystemdName(instance))
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

// unescapeSystemdName undoes the \xNN escaping of a unit name. A "-" stays a
// "-": only path specifiers turn it into "/".
func unescapeSystemdName(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

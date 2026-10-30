// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

const (
	managedPreferencesDir = "/Library/Managed Preferences"
	systemPreferencesDir  = "/Library/Preferences"
	globalPreferences     = ".GlobalPreferences"

	prefSourceManaged     = "managed"
	prefSourceByHost      = "byHost"
	prefSourcePreferences = "preferences"
	prefSourceSystem      = "system"
)

// normalizePreferenceDomain maps the names `defaults` accepts for the global
// domain to its file name and rejects anything that is not a domain name, so
// a domain can never name a file outside the preference directories.
func normalizePreferenceDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	switch domain {
	case "NSGlobalDomain", "-g", "-globalDomain":
		return globalPreferences, nil
	case "":
		return "", errors.New("macos.preferences requires a domain")
	}
	if strings.ContainsAny(domain, `/\`) || domain == "." || domain == ".." {
		return "", fmt.Errorf("macos.preferences: %q is not a preference domain", domain)
	}
	return strings.TrimSuffix(domain, ".plist"), nil
}

// asPreferenceDict reads a dict field's value as the map it holds. A null
// dict has no values.
func asPreferenceDict(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// prefLayer is one source of preference values, in the order macOS applies
// them (first wins).
type prefLayer struct {
	source string
	values map[string]any
}

// mergePreferences merges preference layers key by key, the first layer that
// sets a key winning, as CFPreferences does: it merges the top-level keys of
// a domain and never the contents of a dictionary value.
func mergePreferences(layers []prefLayer) (map[string]any, map[string]any) {
	values := map[string]any{}
	sources := map[string]any{}
	for _, l := range layers {
		for k, v := range l.values {
			if _, ok := values[k]; ok {
				continue
			}
			values[k] = v
			sources[k] = l.source
		}
	}
	return values, sources
}

// mcxAlwaysValues returns the values of domain that complete.plist marks as
// always enforced. complete.plist holds each key as
// {mcxdomain: "always" | "once" | "often", source: [...], value: ...}; a value
// set once or often is applied as a default the user may change, so it is
// not enforced.
func mcxAlwaysValues(complete map[string]any, domain string) map[string]any {
	keys, ok := complete[domain].(map[string]any)
	if !ok {
		return nil
	}
	res := map[string]any{}
	for k, raw := range keys {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if state, _ := entry["mcxdomain"].(string); state != "always" {
			continue
		}
		v, ok := entry["value"]
		if !ok {
			continue
		}
		res[k] = v
	}
	return res
}

// byHostSuffix matches the host part of a ByHost file name: the hardware UUID
// on current releases, the primary MAC address (12 hex digits) on old ones.
var byHostSuffix = regexp.MustCompile(`^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|[0-9A-Fa-f]{12})$`)

// byHostCandidates returns the hosts that have a ByHost file for domain among
// the file names of a ByHost directory.
func byHostCandidates(names []string, domain string) []string {
	var hosts []string
	prefix := domain + "."
	for _, n := range names {
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".plist") {
			continue
		}
		host := strings.TrimSuffix(strings.TrimPrefix(n, prefix), ".plist")
		if byHostSuffix.MatchString(host) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// macosPrefReader reads preference files from the target. One reader serves
// a macos.preferences resource and its users, so the hardware UUID is read at
// most once.
type macosPrefReader struct {
	fs  afero.Fs
	run func(command string) (string, error)

	lock        sync.Mutex
	uuidFetched bool
	uuid        string
	uuidErr     error
}

func newMacosPrefReader(conn shared.Connection) *macosPrefReader {
	return &macosPrefReader{
		fs: conn.FileSystem(),
		run: func(command string) (string, error) {
			cmd, err := conn.RunCommand(command)
			if err != nil {
				return "", err
			}
			stdout, err := io.ReadAll(cmd.Stdout)
			if err != nil {
				return "", err
			}
			if cmd.ExitStatus != 0 {
				stderr, _ := io.ReadAll(cmd.Stderr)
				return "", fmt.Errorf("%s failed (exit %d): %s", command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
			}
			return string(stdout), nil
		},
	}
}

// readPlist decodes a binary or XML property list. A file that does not
// exist has no values; any other failure, such as a file the scan may not
// read, is an error.
func (r *macosPrefReader) readPlist(file string) (map[string]any, error) {
	f, err := r.fs.Open(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read %s: %w", file, err)
	}
	defer f.Close()
	data, err := plist.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", file, err)
	}
	return data, nil
}

func (r *macosPrefReader) exists(file string) (bool, error) {
	_, err := r.fs.Stat(file)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// hardwareUUID returns the IOPlatformUUID, which names the ByHost files of
// the scanned Mac.
func (r *macosPrefReader) hardwareUUID() (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.uuidFetched {
		return r.uuid, r.uuidErr
	}
	r.uuidFetched = true
	stdout, err := r.run(hardwareUUIDCmd)
	if err != nil {
		r.uuidErr = err
		return "", err
	}
	m := hardwareUUIDRegex.FindStringSubmatch(stdout)
	if m == nil {
		r.uuidErr = errors.New("ioreg did not report an IOPlatformUUID")
		return "", r.uuidErr
	}
	r.uuid = m[1]
	return r.uuid, nil
}

// byHostFile returns the ByHost file of domain for the scanned Mac, or "" when
// there is none. A home holding the ByHost file of a single host uses it
// without asking ioreg, so file system scans read it too; with several hosts
// (a home migrated from another Mac) the hardware UUID picks the file.
func (r *macosPrefReader) byHostFile(home, domain string) (string, error) {
	dir := path.Join(home, "Library/Preferences/ByHost")
	entries, err := afero.ReadDir(r.fs, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("cannot list %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	hosts := byHostCandidates(names, domain)
	switch len(hosts) {
	case 0:
		return "", nil
	case 1:
		return path.Join(dir, domain+"."+hosts[0]+".plist"), nil
	}
	uuid, err := r.hardwareUUID()
	if err != nil {
		return "", err
	}
	for _, h := range hosts {
		if strings.EqualFold(h, uuid) {
			return path.Join(dir, domain+"."+h+".plist"), nil
		}
	}
	return "", nil
}

// userPreferencesFile returns the file holding a user's own values of
// domain: the sandbox container's when the application is sandboxed and has
// written it, otherwise the one in ~/Library/Preferences.
func (r *macosPrefReader) userPreferencesFile(home, domain string) (string, error) {
	container := path.Join(home, "Library/Containers", domain, "Data/Library/Preferences", domain+".plist")
	ok, err := r.exists(container)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", container, err)
	}
	if ok {
		return container, nil
	}
	return path.Join(home, "Library/Preferences", domain+".plist"), nil
}

// managedFor returns the values profiles enforce in a managed preferences
// directory: the domain's plist, then the always-enforced entries of
// complete.plist for keys the plist does not set.
func (r *macosPrefReader) managedFor(dir, domain string) (map[string]any, error) {
	values, err := r.readPlist(path.Join(dir, domain+".plist"))
	if err != nil {
		return nil, err
	}
	complete, err := r.readPlist(path.Join(dir, "complete.plist"))
	if err != nil {
		return nil, err
	}
	merged, _ := mergePreferences([]prefLayer{
		{source: prefSourceManaged, values: values},
		{source: prefSourceManaged, values: mcxAlwaysValues(complete, domain)},
	})
	return merged, nil
}

type mqlMacosPreferencesInternal struct {
	lock   sync.Mutex
	reader *macosPrefReader
}

func initMacosPreferences(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	raw, ok := args["domain"]
	if !ok || raw == nil {
		return nil, nil, errors.New("macos.preferences requires a domain")
	}
	domain, _ := raw.Value.(string)
	normalized, err := normalizePreferenceDomain(domain)
	if err != nil {
		return nil, nil, err
	}
	args["domain"] = llx.StringData(normalized)
	return args, nil, nil
}

func (p *mqlMacosPreferences) id() (string, error) {
	return "macos.preferences/" + p.Domain.Data, nil
}

func (p *mqlMacosPreferences) prefReader() *macosPrefReader {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.reader == nil {
		p.reader = newMacosPrefReader(p.MqlRuntime.Connection.(shared.Connection))
	}
	return p.reader
}

func (p *mqlMacosPreferences) managed() (map[string]any, error) {
	return p.prefReader().managedFor(managedPreferencesDir, p.Domain.Data)
}

func (p *mqlMacosPreferences) system() (map[string]any, error) {
	values, err := p.prefReader().readPlist(path.Join(systemPreferencesDir, p.Domain.Data+".plist"))
	if values == nil && err == nil {
		values = map[string]any{}
	}
	return values, err
}

func (p *mqlMacosPreferences) layers() ([]prefLayer, error) {
	managed := p.GetManaged()
	if managed.Error != nil {
		return nil, managed.Error
	}
	system := p.GetSystem()
	if system.Error != nil {
		return nil, system.Error
	}
	return []prefLayer{
		{source: prefSourceManaged, values: asPreferenceDict(managed.Data)},
		{source: prefSourceSystem, values: asPreferenceDict(system.Data)},
	}, nil
}

func (p *mqlMacosPreferences) values() (map[string]any, error) {
	layers, err := p.layers()
	if err != nil {
		return nil, err
	}
	values, _ := mergePreferences(layers)
	return values, nil
}

func (p *mqlMacosPreferences) sources() (map[string]any, error) {
	layers, err := p.layers()
	if err != nil {
		return nil, err
	}
	_, sources := mergePreferences(layers)
	return sources, nil
}

func (p *mqlMacosPreferences) users() ([]any, error) {
	usersResource, err := CreateResource(p.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := usersResource.(*mqlUsers).GetList()
	if list.Error != nil {
		return nil, fmt.Errorf("cannot list users: %w", list.Error)
	}

	res := []any{}
	seen := map[string]struct{}{}
	for _, u := range list.Data {
		user := u.(*mqlUser)
		home := user.GetHome().Data
		if !strings.HasPrefix(home, "/Users/") || !isRealUserHome(home) {
			continue
		}
		name := user.GetName().Data
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		r, err := CreateResource(p.MqlRuntime, "macos.preferences.user", map[string]*llx.RawData{
			"__id":   llx.StringData("macos.preferences/" + p.Domain.Data + "/" + name),
			"domain": llx.StringData(p.Domain.Data),
		})
		if err != nil {
			return nil, err
		}
		pu := r.(*mqlMacosPreferencesUser)
		pu.parent = p
		pu.account = user
		pu.name = name
		pu.home = home
		res = append(res, pu)
	}
	return res, nil
}

type mqlMacosPreferencesUserInternal struct {
	parent  *mqlMacosPreferences
	account *mqlUser
	name    string
	home    string
}

// errPreferencesUserDetached reports a macos.preferences.user that was not
// created through macos.preferences.users.
var errPreferencesUserDetached = errors.New("macos.preferences.user is only available through macos.preferences.users")

func (u *mqlMacosPreferencesUser) user() (*mqlUser, error) {
	if u.account == nil {
		return nil, errPreferencesUserDetached
	}
	return u.account, nil
}

func (u *mqlMacosPreferencesUser) managed() (map[string]any, error) {
	if u.parent == nil {
		return nil, errPreferencesUserDetached
	}
	reader := u.parent.prefReader()
	values, err := reader.managedFor(path.Join(managedPreferencesDir, u.name), u.Domain.Data)
	if err != nil {
		return nil, err
	}
	computer := u.parent.GetManaged()
	if computer.Error != nil {
		return nil, computer.Error
	}
	merged, _ := mergePreferences([]prefLayer{
		{source: prefSourceManaged, values: values},
		{source: prefSourceManaged, values: asPreferenceDict(computer.Data)},
	})
	return merged, nil
}

func (u *mqlMacosPreferencesUser) byHost() (map[string]any, error) {
	if u.parent == nil {
		return nil, errPreferencesUserDetached
	}
	reader := u.parent.prefReader()
	file, err := reader.byHostFile(u.home, u.Domain.Data)
	if err != nil {
		return nil, err
	}
	if file == "" {
		return map[string]any{}, nil
	}
	values, err := reader.readPlist(file)
	if values == nil && err == nil {
		values = map[string]any{}
	}
	return values, err
}

func (u *mqlMacosPreferencesUser) preferences() (map[string]any, error) {
	if u.parent == nil {
		return nil, errPreferencesUserDetached
	}
	reader := u.parent.prefReader()
	file, err := reader.userPreferencesFile(u.home, u.Domain.Data)
	if err != nil {
		return nil, err
	}
	values, err := reader.readPlist(file)
	if values == nil && err == nil {
		values = map[string]any{}
	}
	return values, err
}

func (u *mqlMacosPreferencesUser) layers() ([]prefLayer, error) {
	managed := u.GetManaged()
	if managed.Error != nil {
		return nil, managed.Error
	}
	byHost := u.GetByHost()
	if byHost.Error != nil {
		return nil, byHost.Error
	}
	prefs := u.GetPreferences()
	if prefs.Error != nil {
		return nil, prefs.Error
	}
	if u.parent == nil {
		return nil, errPreferencesUserDetached
	}
	system := u.parent.GetSystem()
	if system.Error != nil {
		return nil, system.Error
	}
	return []prefLayer{
		{source: prefSourceManaged, values: asPreferenceDict(managed.Data)},
		{source: prefSourceByHost, values: asPreferenceDict(byHost.Data)},
		{source: prefSourcePreferences, values: asPreferenceDict(prefs.Data)},
		{source: prefSourceSystem, values: asPreferenceDict(system.Data)},
	}, nil
}

func (u *mqlMacosPreferencesUser) values() (map[string]any, error) {
	layers, err := u.layers()
	if err != nil {
		return nil, err
	}
	values, _ := mergePreferences(layers)
	return values, nil
}

func (u *mqlMacosPreferencesUser) sources() (map[string]any, error) {
	layers, err := u.layers()
	if err != nil {
		return nil, err
	}
	_, sources := mergePreferences(layers)
	return sources, nil
}

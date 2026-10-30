// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"maps"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// targetUser identifies an on-disk user profile, not an account resource.
// Windows names come from locally cached identity data, falling back to the
// profile directory name when the account is unavailable.
type targetUser struct {
	sid  string
	name string
	home string
	uid  int64
}

// sharedProfileLeaves are home leaf names for shared/system profiles, not real
// users (e.g. /Users/Shared, C:\Users\Public).
var sharedProfileLeaves = map[string]struct{}{
	"shared":       {},
	"public":       {},
	"default":      {},
	"default user": {},
	"all users":    {},
}

// isRealUserHome reports whether home is a genuine per-user home. Superset of
// the browser/editor filters: a known user-home prefix (incl. FreeBSD's
// /usr/home) minus shared/system profile dirs.
func isRealUserHome(home string) bool {
	if isSystemHomeDir(home) {
		return false
	}
	leaf := home
	if i := strings.LastIndexAny(leaf, `/\`); i >= 0 {
		leaf = leaf[i+1:]
	}
	if _, ok := sharedProfileLeaves[strings.ToLower(leaf)]; ok {
		return false
	}
	return true
}

// targetUserHomes enumerates real on-disk user homes, deduped by path.
// Windows reads ProfileList without enumerating local or directory accounts.
// Shared basis for resources inspecting per-user state across all accounts
// (browser/editor extensions, AI-agent skills). Missing uid defaults to -1.
func targetUserHomes(runtime *plugin.Runtime) ([]targetUser, error) {
	conn := runtime.Connection.(shared.Connection)
	if asset := conn.Asset(); asset != nil && asset.Platform != nil && asset.Platform.IsFamily("windows") {
		profiles, err := windowsProfileHomes(runtime)
		if err != nil {
			return nil, err
		}
		enrichWindowsProfileNames(runtime, profiles)
		return profiles, nil
	}

	usersResource, err := CreateResource(runtime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, fmt.Errorf("cannot list users on target: %w", err)
	}

	userList := usersResource.(*mqlUsers).GetList()
	if userList.Error != nil {
		return nil, fmt.Errorf("cannot list users on target: %w", userList.Error)
	}

	seen := map[string]struct{}{}
	var result []targetUser
	for _, u := range userList.Data {
		user := u.(*mqlUser)
		home := user.GetHome().Data
		if !isRealUserHome(home) {
			continue
		}
		if _, ok := seen[home]; ok {
			continue
		}
		seen[home] = struct{}{}

		uid := int64(-1)
		if uidVal := user.GetUid(); uidVal.Error == nil {
			uid = uidVal.Data
		}
		result = append(result, targetUser{name: user.GetName().Data, home: home, uid: uid})
	}
	return result, nil
}

const windowsProfileListPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

var windowsProfileEnvPattern = regexp.MustCompile(`%([^%]+)%`)

func windowsProfileHomes(runtime *plugin.Runtime) ([]targetUser, error) {
	root, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(windowsProfileListPath),
	})
	if err != nil {
		return nil, err
	}
	children := root.(*mqlRegistrykey).GetChildren()
	if children.Error != nil {
		return nil, fmt.Errorf("cannot list Windows profiles: %w", children.Error)
	}

	seen := map[string]struct{}{}
	var homes []targetUser
	for _, child := range children.Data {
		sid, ok := child.(string)
		if !ok {
			return nil, fmt.Errorf("invalid Windows profile key: %T", child)
		}
		switch sid {
		case "S-1-5-18", "S-1-5-19", "S-1-5-20":
			continue
		}
		key, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
			"path": llx.StringData(windowsProfileListPath + `\` + sid),
		})
		if err != nil {
			return nil, err
		}
		items := key.(*mqlRegistrykey).GetItems()
		if items.Error != nil {
			return nil, fmt.Errorf("cannot read Windows profile %s: %w", sid, items.Error)
		}
		for _, item := range items.Data {
			property := item.(*mqlRegistrykeyProperty)
			if !strings.EqualFold(property.Name.Data, "ProfileImagePath") {
				continue
			}
			value := property.GetValue()
			if value.Error != nil {
				return nil, fmt.Errorf("cannot read Windows profile path %s: %w", sid, value.Error)
			}
			home := value.Data
			if windowsProfileEnvPattern.MatchString(home) {
				// Expand against the target, which can be a remote Windows host.
				// The scanner's own environment would point at the wrong machine.
				osResource, err := CreateResource(runtime, "os.base", map[string]*llx.RawData{})
				if err != nil {
					return nil, err
				}
				env := osResource.(*mqlOsBase).GetEnv()
				if env.Error != nil {
					return nil, fmt.Errorf("cannot expand Windows profile path: %w", env.Error)
				}
				home, err = expandWindowsProfilePath(home, env.Data)
				if err != nil {
					return nil, err
				}
			}
			home = strings.TrimRight(home, `\/`)
			if !isRealUserHome(home) {
				continue
			}
			normalized := strings.ToLower(strings.ReplaceAll(home, `\`, "/"))
			if _, exists := seen[normalized]; !exists {
				seen[normalized] = struct{}{}
				homes = append(homes, targetUser{sid: sid, name: windowsProfileLeaf(home), home: home, uid: -1})
			}
		}
	}
	return homes, nil
}

func expandWindowsProfilePath(path string, env map[string]any) (string, error) {
	var err error
	expanded := windowsProfileEnvPattern.ReplaceAllStringFunc(path, func(variable string) string {
		if err != nil {
			return variable
		}
		name := variable[1 : len(variable)-1]
		for key, value := range env {
			if strings.EqualFold(key, name) {
				if text, ok := value.(string); ok && text != "" {
					return text
				}
			}
		}
		err = fmt.Errorf("cannot expand Windows profile path %q: environment variable %s is unavailable", path, name)
		return variable
	})
	return expanded, err
}

// windowsProfileLeaf works on target paths even when the scanner runs on Unix.
func windowsProfileLeaf(home string) string {
	home = strings.TrimRight(home, `\/`)
	if i := strings.LastIndexAny(home, `\/`); i >= 0 {
		return home[i+1:]
	}
	return home
}

// enrichWindowsProfileNames never resolves an account or contacts a domain.
// Retain measured account metadata if an independent query already loaded it;
// otherwise use the loaded user's volatile environment and the Entra identity
// cache, as users.list does for profiles absent from the local account database.
func enrichWindowsProfileNames(runtime *plugin.Runtime, profiles []targetUser) {
	cached := map[string]*mqlUser{}
	if resource, ok := runtime.Resources.Get("users\x00"); ok {
		users := resource.(*mqlUsers)
		// Never wait on another query that may itself be stuck enumerating accounts.
		if users.lock.TryLock() {
			maps.Copy(cached, users.usersBySid)
			users.lock.Unlock()
		}
	}

	loaded := loadedWindowsProfileSIDs(runtime)
	for i := range profiles {
		profile := &profiles[i]
		if user := cached[profile.sid]; user != nil && user.Name.IsSet() && user.Name.Error == nil {
			profile.name = user.Name.Data
			if user.Uid.IsSet() && user.Uid.Error == nil {
				profile.uid = user.Uid.Data
			}
			continue
		}
		// A renamed local account may keep its old profile directory. Its loaded
		// hive records the current username without a SAM/LSA lookup.
		if loaded[profile.sid] {
			if name := cachedWindowsProfileName(runtime, `HKEY_USERS\`+profile.sid+`\Volatile Environment`, "USERNAME"); name != "" {
				profile.name = name
			}
		}
		if strings.HasPrefix(profile.sid, "S-1-12-1-") {
			if name := cachedWindowsProfileName(runtime, `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore\Cache\`+profile.sid+`\IdentityCache\`+profile.sid, "UserName"); name != "" {
				profile.name = name
			}
		}
	}
}

// Identity caches are optional: a logged-out/deleted account need not have one.
// Failure to read display metadata must not hide a profile whose path was read.
func cachedWindowsProfileName(runtime *plugin.Runtime, path, name string) string {
	raw, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData(path)})
	if err != nil {
		return ""
	}
	items := raw.(*mqlRegistrykey).GetItems()
	if items.Error != nil {
		return ""
	}
	for _, entry := range items.Data {
		item := entry.(*mqlRegistrykeyProperty)
		if strings.EqualFold(item.Name.Data, name) {
			value := item.GetValue()
			if value.Error == nil {
				return strings.TrimSpace(value.Data)
			}
		}
	}
	return ""
}

// Only loaded profiles can have a volatile environment. One hive listing avoids
// starting a PowerShell process for every logged-out profile on remote targets.
func loadedWindowsProfileSIDs(runtime *plugin.Runtime) map[string]bool {
	loaded := map[string]bool{}
	raw, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{"path": llx.StringData("HKEY_USERS")})
	if err != nil {
		return loaded
	}
	children := raw.(*mqlRegistrykey).GetChildren()
	if children.Error != nil {
		return loaded
	}
	for _, child := range children.Data {
		if sid, ok := child.(string); ok {
			loaded[sid] = true
		}
	}
	return loaded
}

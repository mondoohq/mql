// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// firefoxBrowserConfig defines a Firefox-based browser's profile path configuration
type firefoxBrowserConfig struct {
	name    string // Human-readable browser name
	relPath string // Path relative to user home directory to profiles directory
	depth   int    // Search depth for extensions.json (0 means use default of 3)
}

// firefoxBrowserConfigs maps platform to list of Firefox-based browser configurations
// Note: Firefox Beta and Firefox ESR share the same profile directory as Firefox Release
var firefoxBrowserConfigs = map[string][]firefoxBrowserConfig{
	"linux": {
		// Standard Firefox variants (use Profiles subdirectory, depth 3)
		{name: "Firefox", relPath: ".mozilla/firefox"},
		{name: "Firefox Developer Edition", relPath: ".mozilla/firefox-dev"},
		{name: "Firefox Nightly", relPath: ".mozilla/firefox-nightly"},
		// Firefox-based browsers
		{name: "LibreWolf", relPath: ".librewolf"},
		{name: "Waterfox", relPath: ".waterfox"},
		{name: "Floorp", relPath: ".floorp"},
		{name: "Zen Browser", relPath: ".zen"},
		// Tor Browser - profile is directly under Browser dir (no Profiles subdir)
		{name: "Tor Browser", relPath: ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser", depth: 2},
		{name: "Tor Browser", relPath: ".tor-browser/Browser/TorBrowser/Data/Browser", depth: 2},
		// Mullvad Browser (Tor-based, similar structure)
		{name: "Mullvad Browser", relPath: ".local/share/mullvad-browser/Browser/TorBrowser/Data/Browser", depth: 2},
	},
	"darwin": {
		// Standard Firefox variants (use Profiles subdirectory, depth 3)
		{name: "Firefox", relPath: "Library/Application Support/Firefox"},
		{name: "Firefox Developer Edition", relPath: "Library/Application Support/Firefox Developer Edition"},
		{name: "Firefox Nightly", relPath: "Library/Application Support/Firefox Nightly"},
		// Firefox-based browsers
		{name: "LibreWolf", relPath: "Library/Application Support/LibreWolf"},
		{name: "Waterfox", relPath: "Library/Application Support/Waterfox"},
		{name: "Floorp", relPath: "Library/Application Support/Floorp"},
		{name: "Zen Browser", relPath: "Library/Application Support/Zen Browser"},
		// Tor Browser - profile is directly under Browser dir (no Profiles subdir)
		{name: "Tor Browser", relPath: "Library/Application Support/TorBrowser-Data/Browser", depth: 2},
		// Mullvad Browser
		{name: "Mullvad Browser", relPath: "Library/Application Support/Mullvad Browser/Browser", depth: 2},
	},
	"windows": {
		// Standard Firefox variants (use Profiles subdirectory, depth 3)
		{name: "Firefox", relPath: "AppData/Roaming/Mozilla/Firefox"},
		{name: "Firefox Developer Edition", relPath: "AppData/Roaming/Mozilla/Firefox Developer Edition"},
		{name: "Firefox Nightly", relPath: "AppData/Roaming/Mozilla/Firefox Nightly"},
		// Firefox-based browsers
		{name: "LibreWolf", relPath: "AppData/Roaming/LibreWolf"},
		{name: "Waterfox", relPath: "AppData/Roaming/Waterfox"},
		{name: "Floorp", relPath: "AppData/Roaming/Floorp"},
		{name: "Zen Browser", relPath: "AppData/Roaming/Zen Browser"},
		// Tor Browser - typically portable, check common location
		{name: "Tor Browser", relPath: "Desktop/Tor Browser/Browser/TorBrowser/Data/Browser", depth: 2},
		// Mullvad Browser
		{name: "Mullvad Browser", relPath: "AppData/Local/Mullvad Browser/Browser/TorBrowser/Data/Browser", depth: 2},
	},
}

// firefoxExtensionsJSON holds the addons read out of one extensions.json,
// together with the number of entries that could not be decoded. The count is
// carried rather than folded into an error because one unreadable addon says
// nothing about its neighbours, and a silently shorter list satisfies every
// assertion made about it.
type firefoxExtensionsJSON struct {
	Addons []firefoxAddonEntry `json:"addons"`
	// Set by readFirefoxExtensionsJSON as it decodes, never read from the file.
	Unreadable int `json:"-"`
}

// firefoxFlexInt is an int that also decodes from a quoted number.
//
// Firefox stores applyBackgroundUpdates as whatever the addon manager last
// wrote: current entries use a JSON number, while older and migrated ones use a
// quoted digit. Declaring the field a plain int made a single quoted value fail
// the decode of the entire file, so one addon cost a profile every addon it had
// (#10906).
type firefoxFlexInt int

func (f *firefoxFlexInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*f = 0
		return nil
	}
	// A quoted number carries the same meaning as a bare one here.
	if unquoted, err := strconv.Unquote(s); err == nil {
		s = unquoted
	}
	if s == "" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*f = firefoxFlexInt(n)
	return nil
}

// firefoxAddonEntry represents a single addon entry in extensions.json
type firefoxAddonEntry struct {
	ID                     string              `json:"id"`
	Name                   string              `json:"name"`
	Version                string              `json:"version"`
	Type                   string              `json:"type"`
	Description            string              `json:"description"`
	Active                 bool                `json:"active"`
	UserDisabled           bool                `json:"userDisabled"`
	AppDisabled            bool                `json:"appDisabled"`
	Visible                bool                `json:"visible"`
	Path                   string              `json:"path"`
	SourceURI              string              `json:"sourceURI"`
	InstallDate            int64               `json:"installDate"`
	UpdateDate             int64               `json:"updateDate"`
	DefaultLocale          *firefoxLocale      `json:"defaultLocale"`
	Location               string              `json:"location"`
	Loader                 *string             `json:"loader"`
	ApplyBackgroundUpdates firefoxFlexInt      `json:"applyBackgroundUpdates"`
	UserPermissions        *firefoxPermissions `json:"userPermissions"`
}

// firefoxLocale represents localized addon information
type firefoxLocale struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Creator     string `json:"creator"`
}

// firefoxPermissions represents the userPermissions object in Firefox
// extensions.json: the API permissions and host origins the addon was actually
// granted. Firefox has never spelled this key "permissions" on an addon entry,
// and the neighbouring optionalPermissions/requestedPermissions are a different
// question (what the addon may ask for later, not what it holds).
type firefoxPermissions struct {
	Permissions []string `json:"permissions"`
	Origins     []string `json:"origins"`
}

// firefoxSystemAddonSuffixes contains domain suffixes that identify Mozilla system addons
var firefoxSystemAddonSuffixes = []string{
	"@mozilla.org",
	"@mozilla.com",
	"@search.mozilla.org",
}

func (f *mqlFirefox) id() (string, error) {
	return "firefox", nil
}

// mqlFirefoxInternal carries the count of addon entries the decoder skipped,
// which is known only once addons() has walked every profile. unreadableAddons
// forces that walk and then reads it.
type mqlFirefoxInternal struct {
	unreadableAddons int
}

func (f *mqlFirefox) unreadableAddons() (int64, error) {
	// The count is a by-product of the scan, so make sure the scan has run.
	// GetAddons memoizes, so this costs nothing when addons was already read.
	addons := f.GetAddons()
	if addons.Error != nil {
		return 0, addons.Error
	}
	return int64(f.unreadableAddonsCount()), nil
}

func (f *mqlFirefox) unreadableAddonsCount() int {
	return f.mqlFirefoxInternal.unreadableAddons
}

func (f *mqlFirefox) addons() ([]any, error) {
	conn := f.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	if pf == nil {
		return nil, nil
	}

	platformKey := getPlatformKey(pf)
	if platformKey == "" {
		log.Debug().Str("platform", pf.Name).Msg("unsupported platform for Firefox addon detection")
		return []any{}, nil
	}

	configs, ok := firefoxBrowserConfigs[platformKey]
	if !ok {
		return []any{}, nil
	}

	// Enumerate all users so addons are discovered for every account.
	users, err := targetUserHomes(f.MqlRuntime)
	if err != nil {
		log.Debug().Err(err).Msg("could not retrieve users list")
		return []any{}, nil
	}

	addons := make([]any, 0, 32) // Pre-allocate with reasonable capacity
	seen := make(map[string]bool)
	unreadable := 0

	fs := conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	log.Debug().Str("platform", platformKey).Int("userCount", len(users)).Msg("searching for Firefox addons")

	// Iterate through each user's home directory
	for _, u := range users {
		homeDir := u.home
		uid := u.uid

		// Check each browser for this user
		for _, browserCfg := range configs {
			browserDir := filepath.Join(homeDir, browserCfg.relPath)

			// Skip browsers this user doesn't have installed. A recursive search
			// is expensive on Windows, where files.find has no native backend and
			// each call spawns a PowerShell process, so the vast majority of
			// (user x browser) combinations would pay a process start-up just to
			// learn the directory is absent.
			// See https://github.com/mondoohq/mql/issues/9104
			if !firefoxBrowserDirExists(afs, browserDir) {
				continue
			}

			// Use files.find to efficiently search for extensions.json files
			// Standard Firefox: BrowserDir/Profiles/profile_name/extensions.json (depth 3)
			// Tor/Mullvad: BrowserDir/profile.default/extensions.json (depth 2)
			searchDepth := browserCfg.depth
			if searchDepth == 0 {
				searchDepth = 3 // Default for standard Firefox profile structure
			}
			filesFind, err := CreateResource(f.MqlRuntime, "files.find", map[string]*llx.RawData{
				"from":  llx.StringData(browserDir),
				"name":  llx.StringData("extensions.json"),
				"type":  llx.StringData("f"),
				"depth": llx.IntData(searchDepth),
			})
			if err != nil {
				// Browser directory doesn't exist or can't be searched - this is normal
				continue
			}

			ff := filesFind.(*mqlFilesFind)
			fileList := ff.GetList()
			if fileList.Error != nil {
				continue
			}

			for _, file := range fileList.Data {
				f := file.(*mqlFile)
				extensionsPath := f.GetPath()
				if extensionsPath.Error != nil {
					continue
				}

				// Extract profile name from path
				profileName := filepath.Base(filepath.Dir(extensionsPath.Data))

				log.Debug().
					Str("browser", browserCfg.name).
					Str("profile", profileName).
					Str("path", extensionsPath.Data).
					Msg("found Firefox extensions.json")

				// Read and parse extensions.json
				extensionsData, err := readFirefoxExtensionsJSON(afs, extensionsPath.Data)
				if err != nil {
					log.Debug().Err(err).Str("path", extensionsPath.Data).Msg("could not read extensions.json")
					continue
				}
				unreadable += extensionsData.Unreadable

				for _, addon := range extensionsData.Addons {
					// Skip built-in/system addons that users typically don't manage
					if isFirefoxSystemAddon(addon) {
						continue
					}

					// Create unique key including user and browser to avoid deduplication across users
					uniqueKey := u.name + "|" + browserCfg.name + "|" + profileName + "|" + addon.ID
					if seen[uniqueKey] {
						continue
					}
					seen[uniqueKey] = true

					// Get the best name (prefer localized if available)
					name := addon.Name
					description := addon.Description
					creator := ""
					if addon.DefaultLocale != nil {
						if addon.DefaultLocale.Name != "" {
							name = addon.DefaultLocale.Name
						}
						if addon.DefaultLocale.Description != "" {
							description = addon.DefaultLocale.Description
						}
						creator = addon.DefaultLocale.Creator
					}

					// Derived fields
					disabled := addon.UserDisabled || addon.AppDisabled
					// applyBackgroundUpdates: 0=off, 1=on, 2=use global default.
					// We treat both 1 and 2 as true since the global default is typically on.
					autoupdate := addon.ApplyBackgroundUpdates != 0
					// Native WebExtensions have no special loader (loader is nil).
					// Legacy/XUL addons or system addons use a non-nil loader string.
					native := addon.Loader == nil && addon.Type == "extension"

					// Merge permissions and origins
					var perms []any
					if addon.UserPermissions != nil {
						merged := firefoxMergeStringSlices(addon.UserPermissions.Permissions, addon.UserPermissions.Origins)
						perms = make([]any, len(merged))
						for i, v := range merged {
							perms[i] = v
						}
					}
					if perms == nil {
						perms = []any{}
					}

					addonResource, err := CreateResource(f.MqlRuntime, "firefox.addon", map[string]*llx.RawData{
						"__id":         llx.StringData(uniqueKey),
						"identifier":   llx.StringData(addon.ID),
						"name":         llx.StringData(name),
						"version":      llx.StringData(addon.Version),
						"description":  llx.StringData(description),
						"type":         llx.StringData(addon.Type),
						"active":       llx.BoolData(addon.Active),
						"userDisabled": llx.BoolData(addon.UserDisabled),
						"disabled":     llx.BoolData(disabled),
						"visible":      llx.BoolData(addon.Visible),
						"path":         llx.StringData(addon.Path),
						"profile":      llx.StringData(profileName),
						"browser":      llx.StringData(browserCfg.name),
						"creator":      llx.StringData(creator),
						"sourceUri":    llx.StringData(addon.SourceURI),
						"installDate":  llx.IntData(addon.InstallDate),
						"updateDate":   llx.IntData(addon.UpdateDate),
						"autoupdate":   llx.BoolData(autoupdate),
						"native":       llx.BoolData(native),
						"location":     llx.StringData(addon.Location),
						"permissions":  llx.ArrayData(perms, types.String),
						"uid":          llx.IntData(uid),
					})
					if err != nil {
						log.Debug().Err(err).Str("addon", addon.ID).Msg("could not create addon resource")
						continue
					}

					addons = append(addons, addonResource)
				}
			}
		}
	}

	f.mqlFirefoxInternal.unreadableAddons = unreadable
	if unreadable > 0 {
		log.Warn().Int("count", unreadable).Msg("some Firefox addon records could not be read, addons is an incomplete inventory")
	}

	return addons, nil
}

// firefoxBrowserDirExists reports whether a browser's profile directory is
// present, treating an unreadable path or a non-directory as absent so the
// caller skips the search rather than failing the whole resource.
func firefoxBrowserDirExists(afs *afero.Afero, dir string) bool {
	exists, err := afs.DirExists(dir)
	if err != nil {
		log.Debug().Err(err).Str("path", dir).Msg("could not check browser directory")
		return false
	}
	return exists
}

// readFirefoxExtensionsJSON reads one Firefox extensions.json.
//
// The addon array is decoded entry by entry so that an addon carrying a value
// this struct cannot represent is skipped and counted instead of discarding the
// file. Decoding the array in one call meant any single unexpected value
// returned an error for the whole profile, and the caller's log-and-continue
// then reported the profile as having no addons at all.
//
// A file that is not JSON, or whose addons key is not an array, is still an
// error: that is a profile we could not read, not a profile with no addons.
func readFirefoxExtensionsJSON(afs *afero.Afero, path string) (*firefoxExtensionsJSON, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Addons []json.RawMessage `json:"addons"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	extensions := &firefoxExtensionsJSON{
		Addons: make([]firefoxAddonEntry, 0, len(envelope.Addons)),
	}
	for _, raw := range envelope.Addons {
		var addon firefoxAddonEntry
		if err := json.Unmarshal(raw, &addon); err != nil {
			extensions.Unreadable++
			log.Debug().Err(err).Str("path", path).Msg("skipping an addon entry that could not be decoded")
			continue
		}
		extensions.Addons = append(extensions.Addons, addon)
	}

	return extensions, nil
}

// isFirefoxSystemAddon checks if an addon is a built-in/system addon
// that users typically don't install or manage themselves
func isFirefoxSystemAddon(addon firefoxAddonEntry) bool {
	// Skip locale and dictionary addons - these are system-level
	if addon.Type == "locale" || addon.Type == "dictionary" {
		return true
	}

	// Check for Mozilla system addon patterns by suffix
	for _, suffix := range firefoxSystemAddonSuffixes {
		if strings.HasSuffix(addon.ID, suffix) {
			return true
		}
	}

	return false
}

// firefoxMergeStringSlices merges two string slices, skipping empty ones
func firefoxMergeStringSlices(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	result := make([]string, 0, len(a)+len(b))
	result = append(result, a...)
	result = append(result, b...)
	return result
}

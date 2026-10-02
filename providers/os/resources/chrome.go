// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// browserConfig defines a browser's extension path configuration
type browserConfig struct {
	name        string // Human-readable browser name
	relPath     string // Path relative to user home directory
	profilePath string // Additional path to profiles (e.g., "User Data" for Chrome on Windows)
}

// browserConfigs maps platform to list of browser configurations
// Each browser config specifies the relative path from user home to the browser data directory
var browserConfigs = map[string][]browserConfig{
	"linux": {
		{name: "Google Chrome", relPath: ".config/google-chrome"},
		{name: "Google Chrome Beta", relPath: ".config/google-chrome-beta"},
		{name: "Google Chrome Dev", relPath: ".config/google-chrome-unstable"},
		{name: "Chromium", relPath: ".config/chromium"},
		{name: "Microsoft Edge", relPath: ".config/microsoft-edge"},
		{name: "Microsoft Edge Beta", relPath: ".config/microsoft-edge-beta"},
		{name: "Microsoft Edge Dev", relPath: ".config/microsoft-edge-dev"},
		{name: "Brave", relPath: ".config/BraveSoftware/Brave-Browser"},
		{name: "Vivaldi", relPath: ".config/vivaldi"},
		{name: "Opera", relPath: ".config/opera"},
	},
	"darwin": {
		{name: "Google Chrome", relPath: "Library/Application Support/Google/Chrome"},
		{name: "Google Chrome Beta", relPath: "Library/Application Support/Google/Chrome Beta"},
		{name: "Google Chrome Canary", relPath: "Library/Application Support/Google/Chrome Canary"},
		{name: "Chromium", relPath: "Library/Application Support/Chromium"},
		{name: "Microsoft Edge", relPath: "Library/Application Support/Microsoft Edge"},
		{name: "Microsoft Edge Beta", relPath: "Library/Application Support/Microsoft Edge Beta"},
		{name: "Microsoft Edge Dev", relPath: "Library/Application Support/Microsoft Edge Dev"},
		{name: "Brave", relPath: "Library/Application Support/BraveSoftware/Brave-Browser"},
		{name: "Vivaldi", relPath: "Library/Application Support/Vivaldi"},
		{name: "Opera", relPath: "Library/Application Support/com.operasoftware.Opera"},
		{name: "Perplexity Comet", relPath: "Library/Application Support/Comet"},
		{name: "ChatGPT Atlas", relPath: "Library/Application Support/ChatGPT"},
	},
	"windows": {
		// AppData\Local browsers
		{name: "Google Chrome", relPath: "AppData/Local/Google/Chrome", profilePath: "User Data"},
		{name: "Google Chrome Beta", relPath: "AppData/Local/Google/Chrome Beta", profilePath: "User Data"},
		{name: "Google Chrome Canary", relPath: "AppData/Local/Google/Chrome SxS", profilePath: "User Data"},
		{name: "Microsoft Edge", relPath: "AppData/Local/Microsoft/Edge", profilePath: "User Data"},
		{name: "Microsoft Edge Beta", relPath: "AppData/Local/Microsoft/Edge Beta", profilePath: "User Data"},
		{name: "Microsoft Edge Dev", relPath: "AppData/Local/Microsoft/Edge Dev", profilePath: "User Data"},
		{name: "Brave", relPath: "AppData/Local/BraveSoftware/Brave-Browser", profilePath: "User Data"},
		{name: "Vivaldi", relPath: "AppData/Local/Vivaldi", profilePath: "User Data"},
		{name: "Perplexity Comet", relPath: "AppData/Local/Comet", profilePath: "User Data"},
		{name: "ChatGPT Atlas", relPath: "AppData/Local/OpenAI/Atlas", profilePath: "User Data"},
		// AppData\Roaming browsers (Opera has different structure)
		{name: "Opera", relPath: "AppData/Roaming/Opera Software/Opera Stable"},
	},
}

// profileDirPattern matches Chromium profile directories: "Default" or "Profile N"
var profileDirPattern = regexp.MustCompile(`^(Default|Profile \d+)$`)

// extensionPathPattern matches Chrome extension manifest paths and extracts profile and extension ID
// Group 1: profile name, Group 2: extension ID
var extensionPathPattern = regexp.MustCompile(`/([^/]+)/Extensions/([^/]+)/[^/]+/manifest\.json$`)

// chromePreferences represents the relevant parts of Chrome's Preferences file
type chromePreferences struct {
	Extensions struct {
		Settings map[string]chromePrefsExtension `json:"settings"`
	} `json:"extensions"`
}

// chromePrefsExtension represents a single extension entry in the Preferences/Secure Preferences file
type chromePrefsExtension struct {
	FromWebstore     bool                `json:"from_webstore"`
	InstallTime      string              `json:"install_time"`       // Chrome epoch (legacy Preferences)
	FirstInstallTime string              `json:"first_install_time"` // Chrome epoch (Secure Preferences)
	State            *int                `json:"state"`              // 0=disabled, 1=enabled; nil if not present
	DisableReasons   json.RawMessage     `json:"disable_reasons"`    // Can be int or []int; non-zero/non-empty means disabled
	Path             string              `json:"path"`
	Location         int                 `json:"location"` // Chrome's ManifestLocation
	Manifest         chromePrefsManifest `json:"manifest"`
}

// Chrome's ManifestLocation values for extensions loaded from a directory on
// disk: "Load unpacked" and --load-extension. Chrome stores no manifest copy
// in Preferences for these, only the absolute directory.
const (
	chromeLocationUnpacked    = 4
	chromeLocationCommandLine = 8
)

// chromePrefsManifest represents the manifest copy inside the Preferences file
type chromePrefsManifest struct {
	Name                    string                `json:"name"`
	Version                 string                `json:"version"`
	Description             string                `json:"description"`
	Author                  json.RawMessage       `json:"author"` // can be string or {"email":"..."}
	ManifestVersion         int                   `json:"manifest_version"`
	Permissions             []json.RawMessage     `json:"permissions"`               // can contain strings or objects
	HostPermissions         []string              `json:"host_permissions"`          // Manifest V3
	OptionalPermissions     []json.RawMessage     `json:"optional_permissions"`      // can contain strings or objects
	OptionalHostPermissions []string              `json:"optional_host_permissions"` // Manifest V3
	UpdateUrl               string                `json:"update_url"`
	DefaultLocale           string                `json:"default_locale"`
	Background              *chromeBackground     `json:"background"`
	ContentScripts          []chromeContentScript `json:"content_scripts"`
}

// chromeBackground represents the background configuration in a Chrome extension manifest
type chromeBackground struct {
	Persistent *bool `json:"persistent"`
}

// chromeContentScript represents a content script entry in a Chrome extension manifest
type chromeContentScript struct {
	Matches []string `json:"matches"`
	Js      []string `json:"js"`
}

// mqlChromeInternal caches both extensions and content scripts to avoid double computation
type mqlChromeInternal struct {
	cachedExtensions     []any
	cachedContentScripts []any
	fetched              bool
	lock                 sync.Mutex
}

func (c *mqlChrome) id() (string, error) {
	return "chrome", nil
}

func (c *mqlChrome) extensions() ([]any, error) {
	exts, _, err := c.fetchAll()
	return exts, err
}

func (c *mqlChrome) extensionContentScripts() ([]any, error) {
	_, scripts, err := c.fetchAll()
	return scripts, err
}

// fetchAll discovers all Chrome extensions and content scripts, caching the results
func (c *mqlChrome) fetchAll() ([]any, []any, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.fetched {
		return c.cachedExtensions, c.cachedContentScripts, nil
	}

	conn := c.MqlRuntime.Connection.(shared.Connection)
	pf := conn.Asset().Platform
	if pf == nil {
		c.fetched = true
		return nil, nil, nil
	}

	platformKey := getPlatformKey(pf)
	if platformKey == "" {
		log.Debug().Str("platform", pf.Name).Msg("unsupported platform for Chrome extension detection")
		c.fetched = true
		c.cachedExtensions = []any{}
		c.cachedContentScripts = []any{}
		return c.cachedExtensions, c.cachedContentScripts, nil
	}

	configs, ok := browserConfigs[platformKey]
	if !ok {
		c.fetched = true
		c.cachedExtensions = []any{}
		c.cachedContentScripts = []any{}
		return c.cachedExtensions, c.cachedContentScripts, nil
	}

	// Enumerate all users so extensions are discovered for every account.
	users, err := targetUserHomes(c.MqlRuntime)
	if err != nil {
		log.Debug().Err(err).Msg("could not retrieve users list")
		c.fetched = true
		c.cachedExtensions = []any{}
		c.cachedContentScripts = []any{}
		return c.cachedExtensions, c.cachedContentScripts, nil
	}

	var extensions []any
	var allContentScripts []any
	seen := make(map[string]bool)

	fs := conn.FileSystem()
	afs := &afero.Afero{Fs: fs}

	log.Debug().Str("platform", platformKey).Int("userCount", len(users)).Msg("searching for browser extensions")

	for _, u := range users {
		homeDir := u.home
		uid := u.uid

		for _, browserCfg := range configs {
			browserDir := filepath.Join(homeDir, browserCfg.relPath)
			if browserCfg.profilePath != "" {
				browserDir = filepath.Join(browserDir, browserCfg.profilePath)
			}

			exists, err := afs.DirExists(browserDir)
			if err != nil || !exists {
				continue
			}

			log.Debug().Str("browser", browserCfg.name).Str("path", browserDir).Msg("found browser directory")

			// Discover profiles
			profiles := discoverChromeProfiles(afs, browserDir)
			if len(profiles) == 0 {
				continue
			}

			for _, profileName := range profiles {
				profileDir := filepath.Join(browserDir, profileName)

				exts, scripts := c.parseProfileExtensions(afs, profileDir, profileName, browserCfg.name, uid, seen)
				extensions = append(extensions, exts...)
				allContentScripts = append(allContentScripts, scripts...)
			}
		}
	}

	if extensions == nil {
		extensions = []any{}
	}
	if allContentScripts == nil {
		allContentScripts = []any{}
	}

	c.fetched = true
	c.cachedExtensions = extensions
	c.cachedContentScripts = allContentScripts
	return extensions, allContentScripts, nil
}

// loadChromeExtensionSettings reads extensions.settings from a profile's
// Preferences and Secure Preferences files and merges them. Where the entries
// live depends on the platform: Chrome on Windows and macOS keeps them in
// Secure Preferences, while Chrome on Linux keeps them in Preferences and
// writes a Secure Preferences file that holds only MACs. An entry from Secure
// Preferences wins over the same extension in Preferences when it carries a
// manifest. ok is false when neither file could be read and parsed.
func loadChromeExtensionSettings(afs *afero.Afero, profileDir string) (map[string]chromePrefsExtension, bool) {
	merged := map[string]chromePrefsExtension{}
	ok := false
	for _, file := range []string{"Preferences", "Secure Preferences"} {
		prefsPath := filepath.Join(profileDir, file)
		data, err := afs.ReadFile(prefsPath)
		if err != nil {
			log.Debug().Err(err).Str("path", prefsPath).Msg("could not read Chrome preferences file")
			continue
		}
		var prefs chromePreferences
		if err := json.Unmarshal(data, &prefs); err != nil {
			log.Debug().Err(err).Str("path", prefsPath).Msg("could not parse Chrome preferences file")
			continue
		}
		ok = true
		for extID, entry := range prefs.Extensions.Settings {
			if prev, exists := merged[extID]; exists && prev.Manifest.hasIdentity() && !entry.Manifest.hasIdentity() {
				continue
			}
			merged[extID] = entry
		}
	}
	for extID, entry := range merged {
		if entry.Manifest.hasIdentity() {
			continue
		}
		if m, found := readUnpackedChromeManifest(afs, entry); found {
			entry.Manifest = m
			merged[extID] = entry
		}
	}
	return merged, ok
}

// readUnpackedChromeManifest reads manifest.json from the directory an
// unpacked or command-line extension loads from. found is false for other
// locations, relative paths, and a missing or unparsable manifest.
func readUnpackedChromeManifest(afs *afero.Afero, entry chromePrefsExtension) (chromePrefsManifest, bool) {
	var m chromePrefsManifest
	if entry.Location != chromeLocationUnpacked && entry.Location != chromeLocationCommandLine {
		return m, false
	}
	if !isAbsoluteExtensionPath(entry.Path) {
		return m, false
	}
	manifestPath := filepath.Join(entry.Path, "manifest.json")
	data, err := afs.ReadFile(manifestPath)
	if err != nil {
		log.Debug().Err(err).Str("path", manifestPath).Msg("could not read unpacked Chrome extension manifest")
		return m, false
	}
	if err := json.Unmarshal(data, &m); err != nil {
		log.Debug().Err(err).Str("path", manifestPath).Msg("could not parse unpacked Chrome extension manifest")
		return m, false
	}
	return m, m.hasIdentity()
}

// hasIdentity reports whether the manifest copy names a real extension.
func (m chromePrefsManifest) hasIdentity() bool {
	return m.Name != "" || m.Version != ""
}

// parseProfileExtensions parses extensions from a single Chrome profile's
// Preferences and Secure Preferences files
func (c *mqlChrome) parseProfileExtensions(
	afs *afero.Afero,
	profileDir, profileName, browserName string,
	uid int64,
	seen map[string]bool,
) ([]any, []any) {
	settings, ok := loadChromeExtensionSettings(afs, profileDir)
	if !ok {
		log.Debug().Str("profile", profileDir).Msg("no readable Chrome preferences file, trying manifest.json fallback")
		return c.fallbackManifestScan(afs, profileDir, profileName, browserName, uid, seen)
	}

	var extensions []any
	var contentScripts []any

	for extID, entry := range settings {
		// Skip entries without a manifest (not real extensions)
		if !entry.Manifest.hasIdentity() {
			continue
		}

		uniqueKey := browserName + "|" + profileDir + "|" + extID
		if seen[uniqueKey] {
			continue
		}
		seen[uniqueKey] = true

		// Resolve i18n names
		extDir := resolveExtensionDir(profileDir, entry.Path, extID)
		name := entry.Manifest.Name
		if strings.HasPrefix(name, "__MSG_") {
			if resolved := resolveChromei18n(afs, extDir, entry.Manifest.DefaultLocale, name); resolved != "" {
				name = resolved
			}
		}

		description := entry.Manifest.Description
		if strings.HasPrefix(description, "__MSG_") {
			if resolved := resolveChromei18n(afs, extDir, entry.Manifest.DefaultLocale, description); resolved != "" {
				description = resolved
			}
		}

		// Merge permissions (V2: all in permissions, V3: split into permissions + host_permissions)
		// Permissions can contain strings or objects (e.g. {"fileSystem":["write"]})
		perms := mergeStringSlices(rawMessagesToStrings(entry.Manifest.Permissions), entry.Manifest.HostPermissions)
		optPerms := mergeStringSlices(rawMessagesToStrings(entry.Manifest.OptionalPermissions), entry.Manifest.OptionalHostPermissions)

		// Extract author (can be a string or an object like {"email":"..."})
		author := extractChromeAuthor(entry.Manifest.Author)

		// State mapping: prefer explicit state field, then derive from disable_reasons
		state, enabled := resolveExtensionState(entry.State, entry.DisableReasons)

		// Persistent flag (V2 only; V3 service workers are never persistent)
		persistent := false
		if entry.Manifest.Background != nil && entry.Manifest.Background.Persistent != nil {
			persistent = *entry.Manifest.Background.Persistent
		}

		// Install time: try first_install_time (Secure Preferences) then install_time (legacy)
		installTimeStr := entry.FirstInstallTime
		if installTimeStr == "" {
			installTimeStr = entry.InstallTime
		}
		var installTime *time.Time
		if installTimeStr != "" {
			installTime = chromeTimeToGoTime(installTimeStr)
		}

		// Manifest hash from on-disk manifest.json
		manifestHash := computeManifestHash(afs, extDir)

		// Referenced: check if extension directory exists on disk
		referenced := dirExists(afs, extDir)

		// Build content scripts for this extension
		var extContentScripts []any
		for _, cs := range entry.Manifest.ContentScripts {
			for _, jsFile := range cs.Js {
				for _, matchPattern := range cs.Matches {
					csID := browserName + "|" + profileDir + "|" + extID + "|" + jsFile + "|" + matchPattern
					csResource, err := CreateResource(c.MqlRuntime, "chrome.extensionContentScript", map[string]*llx.RawData{
						"__id":        llx.StringData(csID),
						"identifier":  llx.StringData(extID),
						"version":     llx.StringData(entry.Manifest.Version),
						"browserType": llx.StringData(browserName),
						"uid":         llx.IntData(uid),
						"script":      llx.StringData(jsFile),
						"match":       llx.StringData(matchPattern),
						"profilePath": llx.StringData(profileDir),
						"path":        llx.StringData(extDir),
					})
					if err != nil {
						log.Debug().Err(err).Str("script", jsFile).Str("match", matchPattern).Msg("could not create content script resource")
						continue
					}
					extContentScripts = append(extContentScripts, csResource)
				}
			}
		}
		contentScripts = append(contentScripts, extContentScripts...)

		// Convert slices to []any for llx
		permsAny := toAnySlice(perms)
		optPermsAny := toAnySlice(optPerms)

		resourceData := map[string]*llx.RawData{
			"__id":                llx.StringData(uniqueKey),
			"identifier":          llx.StringData(extID),
			"name":                llx.StringData(name),
			"version":             llx.StringData(entry.Manifest.Version),
			"description":         llx.StringData(description),
			"manifestVersion":     llx.IntData(int64(entry.Manifest.ManifestVersion)),
			"permissions":         llx.ArrayData(permsAny, types.String),
			"optionalPermissions": llx.ArrayData(optPermsAny, types.String),
			"path":                llx.StringData(extDir),
			"profile":             llx.StringData(profileName),
			"profilePath":         llx.StringData(profileDir),
			"browser":             llx.StringData(browserName),
			"author":              llx.StringData(author),
			"updateUrl":           llx.StringData(entry.Manifest.UpdateUrl),
			"manifestHash":        llx.StringData(manifestHash),
			"fromWebstore":        llx.BoolData(entry.FromWebstore),
			"state":               llx.StringData(state),
			"enabled":             llx.BoolData(enabled),
			"persistent":          llx.BoolData(persistent),
			"defaultLocale":       llx.StringData(entry.Manifest.DefaultLocale),
			"referenced":          llx.BoolData(referenced),
			"uid":                 llx.IntData(uid),
			"contentScripts":      llx.ArrayData(extContentScripts, types.Resource("chrome.extensionContentScript")),
		}

		if installTime != nil {
			resourceData["installTime"] = llx.TimeData(*installTime)
		} else {
			resourceData["installTime"] = llx.TimeData(llx.NeverFutureTime)
		}

		ext, err := CreateResource(c.MqlRuntime, "chrome.extension", resourceData)
		if err != nil {
			log.Debug().Err(err).Str("extension", extID).Msg("could not create extension resource")
			continue
		}

		extensions = append(extensions, ext)
	}

	return extensions, contentScripts
}

// fallbackManifestScan uses the legacy manifest.json file scanning approach
// when the Preferences file is unavailable or corrupt
func (c *mqlChrome) fallbackManifestScan(
	afs *afero.Afero,
	profileDir, profileName, browserName string,
	uid int64,
	seen map[string]bool,
) ([]any, []any) {
	extensionsDir := filepath.Join(profileDir, "Extensions")
	exists, err := afs.DirExists(extensionsDir)
	if err != nil || !exists {
		return nil, nil
	}

	// Search for manifest.json files
	filesFind, err := CreateResource(c.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from":  llx.StringData(extensionsDir),
		"name":  llx.StringData("manifest.json"),
		"type":  llx.StringData("f"),
		"depth": llx.IntData(3),
	})
	if err != nil {
		return nil, nil
	}

	ff := filesFind.(*mqlFilesFind)
	fileList := ff.GetList()
	if fileList.Error != nil {
		return nil, nil
	}

	var extensions []any
	for _, f := range fileList.Data {
		file := f.(*mqlFile)
		manifestPath := file.GetPath()
		if manifestPath.Error != nil {
			continue
		}

		normalizedPath := filepath.ToSlash(manifestPath.Data)
		matches := extensionPathPattern.FindStringSubmatch(normalizedPath)
		if matches == nil {
			continue
		}

		extensionID := matches[2]
		uniqueKey := browserName + "|" + profileDir + "|" + extensionID
		if seen[uniqueKey] {
			continue
		}
		seen[uniqueKey] = true

		manifest, err := readChromeManifest(afs, manifestPath.Data)
		if err != nil {
			continue
		}

		extDir := filepath.Dir(manifestPath.Data)
		name := manifest.Name
		if strings.HasPrefix(name, "__MSG_") {
			if resolved := resolveChromei18n(afs, extDir, manifest.DefaultLocale, name); resolved != "" {
				name = resolved
			}
		}

		description := manifest.Description
		if strings.HasPrefix(description, "__MSG_") {
			if resolved := resolveChromei18n(afs, extDir, manifest.DefaultLocale, description); resolved != "" {
				description = resolved
			}
		}

		permsAny := toAnySlice(manifest.Permissions)
		manifestHash := computeManifestHash(afs, extDir)

		ext, err := CreateResource(c.MqlRuntime, "chrome.extension", map[string]*llx.RawData{
			"__id":                llx.StringData(uniqueKey),
			"identifier":          llx.StringData(extensionID),
			"name":                llx.StringData(name),
			"version":             llx.StringData(manifest.Version),
			"description":         llx.StringData(description),
			"manifestVersion":     llx.IntData(int64(manifest.ManifestVersion)),
			"permissions":         llx.ArrayData(permsAny, types.String),
			"optionalPermissions": llx.ArrayData([]any{}, types.String),
			"path":                llx.StringData(extDir),
			"profile":             llx.StringData(profileName),
			"profilePath":         llx.StringData(profileDir),
			"browser":             llx.StringData(browserName),
			"author":              llx.StringData(""),
			"updateUrl":           llx.StringData(""),
			"manifestHash":        llx.StringData(manifestHash),
			"fromWebstore":        llx.BoolData(false),
			"state":               llx.StringData("unknown"),
			"enabled":             llx.BoolData(true),
			"persistent":          llx.BoolData(false),
			"installTime":         llx.TimeData(llx.NeverFutureTime),
			"defaultLocale":       llx.StringData(manifest.DefaultLocale),
			"referenced":          llx.BoolData(true),
			"uid":                 llx.IntData(uid),
			"contentScripts":      llx.ArrayData([]any{}, types.Resource("chrome.extensionContentScript")),
		})
		if err != nil {
			continue
		}

		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// discoverChromeProfiles returns a list of profile directory names found in a browser directory
func discoverChromeProfiles(afs *afero.Afero, browserDir string) []string {
	entries, err := afs.ReadDir(browserDir)
	if err != nil {
		log.Debug().Err(err).Str("browserDir", browserDir).Msg("could not read browser directory for profile discovery")
		return nil
	}

	var profiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if profileDirPattern.MatchString(name) {
			// Verify the profile has a Preferences/Secure Preferences or Extensions directory
			profileDir := filepath.Join(browserDir, name)
			hasPrefs, _ := afs.Exists(filepath.Join(profileDir, "Preferences"))
			hasSecPrefs, _ := afs.Exists(filepath.Join(profileDir, "Secure Preferences"))
			hasExts, _ := afs.DirExists(filepath.Join(profileDir, "Extensions"))
			if hasPrefs || hasSecPrefs || hasExts {
				profiles = append(profiles, name)
			}
		}
	}

	return profiles
}

// resolveExtensionDir determines the extension directory on disk.
// When entryPath is set (the common case from Preferences), it includes the version
// subdirectory (e.g., "extID/1.2.3_0"). The fallback to just extID is only hit when
// entryPath is empty, in which case manifestHash and referenced may be inaccurate
// since manifest.json lives one level deeper at Extensions/<extID>/<version>/.
func resolveExtensionDir(profileDir, entryPath, extID string) string {
	if isAbsoluteExtensionPath(entryPath) {
		// Component and unpacked extensions record the absolute directory they
		// load from (e.g. /opt/google/chrome/resources/pdf).
		return entryPath
	}
	if entryPath != "" {
		// The path in Preferences is relative to the Extensions directory
		return filepath.Join(profileDir, "Extensions", entryPath)
	}
	return filepath.Join(profileDir, "Extensions", extID)
}

// isAbsoluteExtensionPath reports whether an extension path from Preferences is
// absolute on the target, which may be a different OS than the provider host:
// a Unix path, a Windows drive path, or a UNC path.
func isAbsoluteExtensionPath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// chromeTimeToGoTime converts a Chrome epoch time string to a Go time.Time
// Chrome epoch: microseconds since 1601-01-01
func chromeTimeToGoTime(chromeTime string) *time.Time {
	val, err := strconv.ParseInt(chromeTime, 10, 64)
	if err != nil || val == 0 {
		return nil
	}
	// Chrome epoch: microseconds since 1601-01-01
	// Guard against non-Chrome-epoch values that would produce absurd dates
	if val < 11644473600000000 {
		return nil
	}
	// Subtract the difference between 1601 and 1970 in microseconds
	unixMicro := val - 11644473600000000
	t := time.Unix(unixMicro/1000000, (unixMicro%1000000)*1000)
	return &t
}

// resolveExtensionState determines the state and enabled status of an extension
// from the state field and/or disable_reasons
func resolveExtensionState(state *int, disableReasons json.RawMessage) (string, bool) {
	if state != nil {
		switch *state {
		case 0:
			return "disabled", false
		case 1:
			return "enabled", true
		default:
			return fmt.Sprintf("unknown(%d)", *state), false
		}
	}

	// Fall back to disable_reasons: can be int or []int; non-zero/non-empty means disabled
	if len(disableReasons) > 0 && string(disableReasons) != "null" && string(disableReasons) != "0" && string(disableReasons) != "[]" {
		// Try as int first
		var intVal int
		if json.Unmarshal(disableReasons, &intVal) == nil && intVal != 0 {
			return "disabled", false
		}
		// Try as array
		var arrVal []int
		if json.Unmarshal(disableReasons, &arrVal) == nil && len(arrVal) > 0 {
			return "disabled", false
		}
	}

	// Default: assume enabled if no explicit state
	return "enabled", true
}

// extractChromeAuthor extracts the author string from the manifest's author field
// which can be either a plain string or an object like {"email":"someone@example.com"}
func extractChromeAuthor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try as string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	// Try as object
	var obj map[string]string
	if err := json.Unmarshal(raw, &obj); err == nil {
		if email, ok := obj["email"]; ok {
			return email
		}
		// Return first non-empty value
		for _, v := range obj {
			if v != "" {
				return v
			}
		}
	}

	return ""
}

// computeManifestHash computes the SHA-256 hash of the manifest.json file in the given extension directory
func computeManifestHash(afs *afero.Afero, extDir string) string {
	manifestPath := filepath.Join(extDir, "manifest.json")
	data, err := afs.ReadFile(manifestPath)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// dirExists checks if a directory exists
func dirExists(afs *afero.Afero, path string) bool {
	exists, err := afs.DirExists(path)
	return err == nil && exists
}

// rawMessagesToStrings extracts string values from a slice of json.RawMessage.
// Non-string entries (e.g., objects like {"fileSystem":["write"]}) are converted to their JSON representation.
func rawMessagesToStrings(raw []json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, r := range raw {
		var s string
		if json.Unmarshal(r, &s) == nil {
			result = append(result, s)
		} else {
			// Non-string permission (e.g., {"fileSystem":["write"]}), include as JSON string
			result = append(result, string(r))
		}
	}
	return result
}

// mergeStringSlices merges two string slices, skipping empty ones
func mergeStringSlices(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	result := make([]string, 0, len(a)+len(b))
	result = append(result, a...)
	result = append(result, b...)
	return result
}

// chromeManifest represents the structure of a Chrome extension manifest.json (for fallback parsing)
type chromeManifest struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Description     string   `json:"description"`
	ManifestVersion int      `json:"manifest_version"`
	Permissions     []string `json:"permissions"`
	DefaultLocale   string   `json:"default_locale"`
}

// getPlatformKey returns the platform key for browser configs lookup
func getPlatformKey(pf interface{ IsFamily(string) bool }) string {
	switch {
	case pf.IsFamily("linux"):
		return "linux"
	case pf.IsFamily("darwin"):
		return "darwin"
	case pf.IsFamily("windows"):
		return "windows"
	default:
		return ""
	}
}

// readChromeManifest reads and parses a Chrome extension manifest.json file (for fallback)
func readChromeManifest(afs *afero.Afero, path string) (*chromeManifest, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest chromeManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// resolveChromei18n attempts to resolve a Chrome extension localized message
// Messages are in the format __MSG_messageName__
func resolveChromei18n(afs *afero.Afero, extDir string, defaultLocale string, msgKey string) string {
	// Extract message name from __MSG_messageName__
	if !strings.HasPrefix(msgKey, "__MSG_") || !strings.HasSuffix(msgKey, "__") {
		return ""
	}
	msgName := strings.TrimPrefix(strings.TrimSuffix(msgKey, "__"), "__MSG_")

	// Build locale search order: default_locale first, then common fallbacks
	locales := []string{}
	if defaultLocale != "" {
		locales = append(locales, defaultLocale)
	}
	// Add common English locales as fallback
	for _, loc := range []string{"en", "en_US", "en_GB"} {
		if loc != defaultLocale {
			locales = append(locales, loc)
		}
	}

	for _, locale := range locales {
		messagesPath := filepath.Join(extDir, "_locales", locale, "messages.json")
		data, err := afs.ReadFile(messagesPath)
		if err != nil {
			continue
		}

		var messages map[string]struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(data, &messages); err != nil {
			continue
		}

		// Message keys are case-insensitive in Chrome
		for key, val := range messages {
			if strings.EqualFold(key, msgName) {
				return val.Message
			}
		}
	}

	return ""
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// Safari extension types to enumerate
var safariExtensionTypes = []string{
	"com.apple.Safari.web-extension",
	"com.apple.Safari.extension",
	"com.apple.Safari.content-blocker",
}

// Regex to extract extension path from pluginkit output
// Example line: "    Path = /Applications/Example.app/Contents/PlugIns/Extension.appex"
var pluginkitPathRegex = regexp.MustCompile(`^\s*Path\s*=\s*(.+)$`)

func (s *mqlSafari) extensions() ([]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)

	// Check if running on macOS
	pf := conn.Asset().Platform
	if pf == nil || pf.Family == nil || !slices.Contains(pf.Family, "darwin") {
		return nil, nil
	}

	// Check if pluginkit command exists
	afs := conn.FileSystem()
	if _, err := afs.Stat("/usr/bin/pluginkit"); err != nil {
		log.Warn().Msg("pluginkit command not found at /usr/bin/pluginkit, cannot enumerate Safari extensions")
		return []any{}, nil
	}

	// Get users list for uid and per-user Extensions.plist
	usersResource, err := CreateResource(s.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("could not get users list")
	}

	// pluginkit returns extensions for the current user only, so we scope
	// both uid and enabled state to the current user's home directory.
	enabledStates := make(map[string]bool)
	uid := int64(-1)
	if usersResource != nil {
		users := usersResource.(*mqlUsers)
		userList := users.GetList()
		if userList.Error == nil {
			// Find the current user (uid matching the process owner)
			// Since pluginkit is per-user, we pick the first valid macOS user
			// and read only their Extensions.plist for consistent uid/enabled pairing.
			for _, u := range userList.Data {
				user := u.(*mqlUser)
				home := user.GetHome()
				if home.Error != nil || home.Data == "" {
					continue
				}
				if !strings.HasPrefix(home.Data, "/Users/") || home.Data == "/Users/Shared" {
					continue
				}

				if uidVal := user.GetUid(); uidVal.Error == nil {
					uid = uidVal.Data
				}
				enabledStates = readSafariExtensionStates(&afero.Afero{Fs: afs}, home.Data)
				break
			}
		}
	}

	seen := make(map[string]bool)
	var extensions []any

	for _, extType := range safariExtensionTypes {
		// Run pluginkit to list extensions of this type
		cmd, err := conn.RunCommand("pluginkit -mAvvv -p " + extType)
		if err != nil {
			return nil, err
		}

		if cmd.ExitStatus != 0 {
			stderr, _ := io.ReadAll(cmd.Stderr)
			return nil, fmt.Errorf("pluginkit failed for %s: %s", extType, string(stderr))
		}

		scanner := bufio.NewScanner(cmd.Stdout)
		for scanner.Scan() {
			line := scanner.Text()
			matches := pluginkitPathRegex.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}

			path := strings.TrimSpace(matches[1])
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true

			// Skip system extensions
			if strings.HasPrefix(path, "/System/") {
				continue
			}

			ext, err := newSafariExtension(s.MqlRuntime, conn, path, extType, enabledStates, uid)
			if err != nil {
				// Skip extensions we can't parse
				continue
			}
			extensions = append(extensions, ext)
		}
	}

	return extensions, nil
}

// readSafariExtensionStates reads Safari's Extensions.plist and returns a map of
// bundle identifier to enabled state
func readSafariExtensionStates(afs *afero.Afero, homeDir string) map[string]bool {
	states := make(map[string]bool)

	plistPath := filepath.Join(homeDir, "Library", "Safari", "Extensions", "Extensions.plist")
	f, err := afs.Open(plistPath)
	if err != nil {
		return states
	}
	defer f.Close()

	data, err := plist.Decode(f)
	if err != nil {
		log.Debug().Err(err).Str("path", plistPath).Msg("could not decode Safari Extensions.plist")
		return states
	}

	// Extensions.plist contains a dict where keys are bundle identifiers
	// and values are dicts with an "Enabled" boolean
	for key, val := range data {
		if extData, ok := val.(map[string]any); ok {
			if enabled, ok := extData["Enabled"]; ok {
				if b, ok := enabled.(bool); ok {
					states[key] = b
				}
			}
		}
	}

	return states
}

func newSafariExtension(runtime *plugin.Runtime, conn shared.Connection, path string, extType string, enabledStates map[string]bool, uid int64) (*mqlSafariExtension, error) {
	afs := conn.FileSystem()

	// Parse Info.plist from the extension bundle
	infoPlistPath := filepath.Join(path, "Contents", "Info.plist")
	f, err := afs.Open(infoPlistPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := plist.Decode(f)
	if err != nil {
		return nil, err
	}

	// Extract extension metadata
	identifier, _ := data.GetString("CFBundleIdentifier")
	name, _ := data.GetString("CFBundleName")
	if name == "" {
		name, _ = data.GetString("CFBundleDisplayName")
	}
	version, _ := data.GetString("CFBundleShortVersionString")
	if version == "" {
		version, _ = data.GetString("CFBundleVersion")
	}
	description, _ := data.GetString("NSHumanReadableCopyright")

	// Determine container app path and name
	containerAppPath := ""
	containerAppName := ""
	if idx := strings.Index(path, ".app/"); idx != -1 {
		containerAppPath = path[:idx+4] // Include ".app"
		containerAppName = filepath.Base(containerAppPath)
		containerAppName = strings.TrimSuffix(containerAppName, ".app")
	}

	// Derive extension type name from the pluginkit type
	extensionTypeName := strings.TrimPrefix(extType, "com.apple.Safari.")

	// Determine enabled state from Extensions.plist
	enabled := true // default to true if not found in plist
	if val, ok := enabledStates[identifier]; ok {
		enabled = val
	}

	// Create the resource with a unique ID
	ext, err := CreateResource(runtime, "safari.extension", map[string]*llx.RawData{
		"__id":             llx.StringData(identifier + "|" + path),
		"identifier":       llx.StringData(identifier),
		"name":             llx.StringData(name),
		"version":          llx.StringData(version),
		"description":      llx.StringData(description),
		"extensionType":    llx.StringData(extensionTypeName),
		"path":             llx.StringData(path),
		"containerAppPath": llx.StringData(containerAppPath),
		"containerAppName": llx.StringData(containerAppName),
		"enabled":          llx.BoolData(enabled),
		"uid":              llx.IntData(uid),
	})
	if err != nil {
		return nil, err
	}

	return ext.(*mqlSafariExtension), nil
}

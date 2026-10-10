// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// newVscodeExtensionPurl builds a vscode-extension PURL per the purl-spec
// definition at:
//
//	https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/vscode-extension-definition.md
//
// Format: pkg:vscode-extension/<publisher>/<name>@<version>
// Empty publisher / name / version yields an empty string — callers that
// pass incomplete extension metadata get no PURL rather than a malformed one.
func newVscodeExtensionPurl(publisher, name, version string) string {
	if publisher == "" || name == "" {
		return ""
	}
	return packageurl.NewPackageURL("vscode-extension", publisher, name, version, nil, "").String()
}

// vsCodeEditor represents a VS Code-based editor with its extension directory
type vsCodeEditor struct {
	dir  string // Extension directory relative to user home
	name string // Human-readable editor name
}

// VS Code extension directories relative to user home (same across platforms)
var vsCodeEditors = []vsCodeEditor{
	{".vscode/extensions", "Visual Studio Code"},
	{".vscode-insiders/extensions", "Visual Studio Code Insiders"},
	{".vscode-oss/extensions", "VSCodium"},
	{".cursor/extensions", "Cursor"},
	{".antigravity/extensions", "Antigravity"},
	{".windsurf/extensions", "Windsurf"},
	{".positron/extensions", "Positron"},
	{".kiro/extensions", "Kiro"},
}

// validHomePrefixes lists path prefixes where real user home directories live.
// Anything outside these prefixes is treated as a system account.
// NOTE: Non-standard setups (FreeBSD /usr/home/, NixOS /persist/home/, custom
// /opt/users/) may need additions here if those targets should be supported.
var validHomePrefixes = []string{
	"/Users/",     // macOS
	"/home/",      // Linux, FreeBSD default
	"/root/",      // Linux root
	"/usr/home/",  // FreeBSD alternate
	"C:\\Users\\", // Windows
}

// isSystemHomeDir returns true if home looks like a system-account directory.
// It uses an allowlist approach: only paths under known user-home prefixes
// (e.g. /Users/, /home/, /root) are considered real users. Comparison is
// case- and separator-insensitive so Windows homes match regardless of drive
// case or slash direction (C:\Users\, c:\users\, C:/Users/).
func isSystemHomeDir(home string) bool {
	if home == "" {
		return true
	}
	norm := strings.ToLower(strings.ReplaceAll(home, "\\", "/"))
	for _, p := range validHomePrefixes {
		pp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
		if strings.HasPrefix(norm, pp) || norm == strings.TrimSuffix(pp, "/") {
			return false
		}
	}
	return true
}

// vscodePackageJSON represents the package.json structure for VS Code extensions
type vscodePackageJSON struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Publisher   string   `json:"publisher"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	Engines     struct {
		VSCode string `json:"vscode"`
	} `json:"engines"`
}

func (c *mqlVscode) id() (string, error) {
	return "vscode", nil
}

func (c *mqlVscode) paths() ([]any, error) {
	conn := c.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// Enumerate all users so extension paths are found for every account.
	users, err := targetUserHomes(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	var paths []string

	for _, u := range users {
		homeDir := u.home

		for _, editor := range vsCodeEditors {
			extensionsDir := filepath.Join(homeDir, editor.dir)
			// Use DirExists which is more efficient than Exists for directories
			exists, err := afs.DirExists(extensionsDir)
			if err != nil || !exists {
				continue
			}
			paths = append(paths, extensionsDir)
		}
	}

	sort.Strings(paths)

	result := make([]any, len(paths))
	for i, p := range paths {
		result[i] = p
	}
	return result, nil
}

func (c *mqlVscode) extensions() ([]any, error) {
	conn := c.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	// Enumerate all users so extensions are discovered for every account.
	users, err := targetUserHomes(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	var extensions []any
	seen := make(map[string]bool)

	for _, u := range users {
		homeDir := u.home

		for _, editor := range vsCodeEditors {
			extensionsDir := filepath.Join(homeDir, editor.dir)

			// ReadDir will fail if directory doesn't exist - no need for separate Exists check
			entries, err := afs.ReadDir(extensionsDir)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Debug().Err(err).Str("path", extensionsDir).Msg("failed to read VS Code extensions directory")
				}
				continue
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}

				// Skip .obsolete directory
				if entry.Name() == ".obsolete" {
					continue
				}

				extPath := filepath.Join(extensionsDir, entry.Name())
				packageJSONPath := filepath.Join(extPath, "package.json")

				// ReadFile will fail if file doesn't exist - no need for separate Exists check
				pkgJSON, err := readVSCodePackageJSON(afs, packageJSONPath)
				if err != nil {
					if !os.IsNotExist(err) {
						log.Debug().Err(err).Str("path", packageJSONPath).Msg("failed to parse VS Code extension package.json")
					}
					continue
				}

				// Create unique identifier
				identifier := pkgJSON.Publisher + "." + pkgJSON.Name
				if identifier == "." {
					// Fallback to directory name if publisher/name not available
					identifier = entry.Name()
				}

				// Create unique ID for caching (including path to handle multiple installs)
				uniqueID := identifier + "|" + extPath

				if seen[uniqueID] {
					continue
				}
				seen[uniqueID] = true

				// Convert categories to []any
				categories := make([]any, len(pkgJSON.Categories))
				for i, cat := range pkgJSON.Categories {
					categories[i] = cat
				}

				// Create extension resource
				ext, err := CreateResource(c.MqlRuntime, "vscode.extension", map[string]*llx.RawData{
					"__id":          llx.StringData(uniqueID),
					"identifier":    llx.StringData(identifier),
					"name":          llx.StringData(pkgJSON.Name),
					"displayName":   llx.StringData(pkgJSON.DisplayName),
					"version":       llx.StringData(pkgJSON.Version),
					"description":   llx.StringData(pkgJSON.Description),
					"publisher":     llx.StringData(pkgJSON.Publisher),
					"editor":        llx.StringData(editor.name),
					"path":          llx.StringData(extPath),
					"vscodeVersion": llx.StringData(pkgJSON.Engines.VSCode),
					"categories":    llx.ArrayData(categories, types.String),
					"purl":          llx.StringData(newVscodeExtensionPurl(pkgJSON.Publisher, pkgJSON.Name, pkgJSON.Version)),
				})
				if err != nil {
					log.Debug().Err(err).Str("extension", identifier).Msg("failed to create VS Code extension resource")
					continue
				}
				extensions = append(extensions, ext)
			}
		}
	}

	return extensions, nil
}

func (e *mqlVscodeExtension) id() (string, error) {
	return e.Identifier.Data + "|" + e.Path.Data, nil
}

// purl is populated eagerly in the vscode.extensions() enumerator from
// the extension's package.json publisher/name/version. The stub satisfies
// the generated lazy-init contract; if for any reason a caller constructs
// a vscode.extension without going through the enumerator (e.g. tests),
// returning the empty string keeps the field non-nil rather than panicking.
func (e *mqlVscodeExtension) purl() (string, error) {
	e.Purl = plugin.TValue[string]{State: plugin.StateIsSet, Data: newVscodeExtensionPurl(e.Publisher.Data, e.Name.Data, e.Version.Data)}
	return e.Purl.Data, nil
}

// readVSCodePackageJSON reads and parses a VS Code extension package.json file
func readVSCodePackageJSON(afs *afero.Afero, path string) (*vscodePackageJSON, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg vscodePackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	return &pkg, nil
}

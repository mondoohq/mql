// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wordpress

import (
	"bufio"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// WordPressPlugin represents a parsed WordPress plugin.
type WordPressPlugin struct {
	// Slug is the plugin directory name (e.g., "akismet").
	Slug string
	// Version is the "Version" header of the main plugin file, which is what
	// WordPress itself reports. A plugin without one falls back to the
	// readme.txt "Stable tag", which names the latest release in the plugin
	// directory rather than the installed copy.
	Version string
	// DisplayName is the "Plugin Name" header, or the readme's "=== Name ===".
	DisplayName string
	// License is from the "License" header.
	License string
	// RequiresWp is from the "Requires at least" header.
	RequiresWp string
	// TestedUpTo is from the readme.txt "Tested up to" header.
	TestedUpTo string
	// FilePath is the file the version was read from: the main plugin file,
	// or readme.txt when there is none.
	FilePath string
	// ReadmePath is the plugin's readme.txt, if it has one.
	ReadmePath string
}

// pluginHeaderBytes is how much of a PHP file WordPress reads looking for the
// plugin header (get_file_data reads 8 KiB).
const pluginHeaderBytes = 8 * 1024

// ScanPluginDir scans a WordPress plugins directory for installed plugins.
// Each subdirectory with a main plugin file (a top-level PHP file carrying a
// "Plugin Name" header) or a readme.txt is treated as a plugin. A symlinked
// plugin directory, which is how Debian's wordpress package links the bundled
// plugins into /var/lib/wordpress/wp-content/plugins, counts as a directory.
// A PHP file directly in the plugins directory that carries a "Plugin Name"
// header is a single-file plugin, as Hello Dolly is in the Fedora and EPEL
// wordpress package.
func ScanPluginDir(afs *afero.Afero, dir string) ([]WordPressPlugin, error) {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		log.Debug().Err(err).Str("path", dir).Msg("mql[wordpress]> could not read plugins directory")
		return nil, nil
	}

	var plugins []WordPressPlugin
	for _, entry := range entries {
		slug := entry.Name()
		pluginDir := path.Join(dir, slug)
		if !isDirOrLinkToDir(afs, entry, pluginDir) {
			if strings.EqualFold(path.Ext(slug), ".php") {
				if plugin := parseSingleFilePlugin(afs, pluginDir); plugin != nil {
					plugins = append(plugins, *plugin)
				}
			}
			continue
		}

		plugin, err := parsePlugin(afs, pluginDir, slug)
		if err != nil {
			log.Debug().Err(err).Str("path", pluginDir).Msg("mql[wordpress]> could not parse plugin")
			continue
		}
		if plugin != nil {
			plugins = append(plugins, *plugin)
		}
	}

	return plugins, nil
}

func isDirOrLinkToDir(afs *afero.Afero, entry fs.FileInfo, p string) bool {
	if entry.IsDir() {
		return true
	}
	if entry.Mode()&fs.ModeSymlink == 0 {
		return false
	}
	fi, err := afs.Stat(p)
	return err == nil && fi.IsDir()
}

// parsePlugin reads one plugin directory. The main plugin file is
// authoritative, as it is for WordPress; readme.txt fills in what the header
// does not carry ("Tested up to") and stands in for a plugin with no main file.
func parsePlugin(afs *afero.Afero, pluginDir, slug string) (*WordPressPlugin, error) {
	plugin := &WordPressPlugin{Slug: slug}

	readmePath := path.Join(pluginDir, "readme.txt")
	if exists, _ := afs.Exists(readmePath); exists {
		readme, err := parseReadme(afs, readmePath, slug)
		if err != nil {
			log.Debug().Err(err).Str("path", readmePath).Msg("mql[wordpress]> could not parse readme.txt")
		} else {
			*plugin = *readme
			plugin.ReadmePath = readmePath
		}
	}

	mainFile, headers, err := findMainPluginFile(afs, pluginDir, slug)
	if err != nil {
		return nil, err
	}
	if mainFile != "" {
		plugin.Slug = slug
		if v := headers["version"]; v != "" {
			plugin.Version = v
			plugin.FilePath = mainFile
		}
		if v := headers["plugin name"]; v != "" {
			plugin.DisplayName = v
		}
		if v := headers["license"]; v != "" {
			plugin.License = v
		}
		if v := headers["requires at least"]; v != "" {
			plugin.RequiresWp = v
		}
	}

	if plugin.Version == "" {
		return nil, nil
	}
	return plugin, nil
}

// parseSingleFilePlugin reads a PHP file that sits directly in the plugins
// directory. It is a plugin when it carries a "Plugin Name" header. Its slug
// is the "Text Domain" header, which wordpress.org requires to match the
// plugin's slug (hello.php is "hello-dolly"), or else the file name.
func parseSingleFilePlugin(afs *afero.Afero, p string) *WordPressPlugin {
	head, err := readHead(afs, p, pluginHeaderBytes)
	if err != nil {
		log.Debug().Err(err).Str("path", p).Msg("mql[wordpress]> could not read plugin file")
		return nil
	}
	headers := parsePluginHeaders(head)
	if headers["plugin name"] == "" || headers["version"] == "" {
		return nil
	}
	slug := headers["text domain"]
	if slug == "" {
		slug = strings.TrimSuffix(path.Base(p), path.Ext(p))
	}
	return &WordPressPlugin{
		Slug:        slug,
		Version:     headers["version"],
		DisplayName: headers["plugin name"],
		License:     headers["license"],
		RequiresWp:  headers["requires at least"],
		FilePath:    p,
	}
}

var pluginHeaderNames = []string{"plugin name", "version", "license", "requires at least", "text domain"}

// findMainPluginFile returns the top-level PHP file of pluginDir that carries
// a "Plugin Name" header, and its headers. It prefers <slug>.php, then takes
// the files in name order, which is the order WordPress reads them in.
func findMainPluginFile(afs *afero.Afero, pluginDir, slug string) (string, map[string]string, error) {
	entries, err := afs.ReadDir(pluginDir)
	if err != nil {
		return "", nil, err
	}
	var candidates []string
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(path.Ext(e.Name()), ".php") {
			continue
		}
		if e.Name() == slug+".php" {
			candidates = append([]string{e.Name()}, candidates...)
		} else {
			candidates = append(candidates, e.Name())
		}
	}

	for _, name := range candidates {
		p := path.Join(pluginDir, name)
		head, err := readHead(afs, p, pluginHeaderBytes)
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("mql[wordpress]> could not read plugin file")
			continue
		}
		headers := parsePluginHeaders(head)
		if headers["plugin name"] != "" {
			return p, headers, nil
		}
	}
	return "", nil, nil
}

func readHead(afs *afero.Afero, p string, n int64) ([]byte, error) {
	f, err := afs.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

var headerCommentEnd = regexp.MustCompile(`\s*(?:\*/|\?>).*`)

// parsePluginHeaders extracts the plugin headers the way WordPress's
// get_file_data does: a header is a line "Name: value", optionally led by
// "<?php" and by any run of spaces, tabs, "/", "*", "#" and "@", matched case
// insensitively. The first match wins.
func parsePluginHeaders(head []byte) map[string]string {
	headers := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(head), "\r", "\n"), "\n") {
		rest := strings.TrimLeft(line, " \t")
		rest = strings.TrimPrefix(rest, "<?php")
		rest = strings.TrimLeft(rest, " \t/*#@")
		key, value, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		if !slices.Contains(pluginHeaderNames, key) {
			continue
		}
		if _, seen := headers[key]; seen {
			continue
		}
		value = headerCommentEnd.ReplaceAllString(value, "")
		headers[key] = strings.TrimSpace(value)
	}
	return headers
}

// parseReadme reads a WordPress plugin readme.txt and extracts metadata headers.
func parseReadme(afs *afero.Afero, readmePath, slug string) (*WordPressPlugin, error) {
	f, err := afs.Open(readmePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	plugin := &WordPressPlugin{
		Slug:     slug,
		FilePath: readmePath,
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// First line: === Plugin Name ===
		if lineNum == 1 {
			if name := extractPluginName(line); name != "" {
				plugin.DisplayName = name
			}
			continue
		}

		// Stop at the description (empty line after headers or a line without a colon)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// Headers are done once we hit an empty line after having parsed some
			if plugin.Version != "" {
				break
			}
			continue
		}

		// Parse "Key: Value" headers
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch strings.ToLower(key) {
		case "stable tag":
			plugin.Version = value
		case "license":
			plugin.License = value
		case "requires at least":
			plugin.RequiresWp = value
		case "tested up to":
			plugin.TestedUpTo = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return plugin, nil
}

// extractPluginName extracts the name from "=== Plugin Name ===" format.
func extractPluginName(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "===") || !strings.HasSuffix(line, "===") {
		return ""
	}
	name := strings.TrimPrefix(line, "===")
	name = strings.TrimSuffix(name, "===")
	return strings.TrimSpace(name)
}

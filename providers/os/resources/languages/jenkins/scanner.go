// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jenkins

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// MaxPluginSize is the maximum size of a plugin file to scan (50MB).
const MaxPluginSize = 50 * 1024 * 1024

// pluginExtensions are the file extensions for Jenkins plugins.
var pluginExtensions = []string{".jpi", ".hpi"}

// JenkinsPlugin represents a parsed Jenkins plugin with metadata.
type JenkinsPlugin struct {
	Name         string
	Version      string
	LongName     string
	Url          string
	Dependencies []string
	FilePath     string
}

// ScanPluginDirExtended scans a directory and returns extended JenkinsPlugin structs.
// A directory that cannot be listed is an error. A plugin file that cannot be
// read because of its permissions is returned as an error alongside the
// plugins that could be read; one that is not a valid archive is skipped.
func ScanPluginDirExtended(afs *afero.Afero, dir string) ([]JenkinsPlugin, error) {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var plugins []JenkinsPlugin
	var refused []error
	for _, entry := range entries {
		if entry.IsDir() || !isPluginFile(entry.Name()) {
			continue
		}
		pluginPath := path.Join(dir, entry.Name())
		plugin, err := scanPlugin(afs, pluginPath)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				refused = append(refused, err)
				continue
			}
			log.Debug().Err(err).Str("path", pluginPath).Msg("mql[jenkins]> could not scan plugin")
			continue
		}
		if plugin != nil {
			plugin.FilePath = pluginPath
			plugins = append(plugins, *plugin)
		}
	}
	return plugins, errors.Join(refused...)
}

// scanPlugin reads a .jpi/.hpi file and extracts metadata from its MANIFEST.MF.
func scanPlugin(afs *afero.Afero, pluginPath string) (*JenkinsPlugin, error) {
	info, err := afs.Stat(pluginPath)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxPluginSize {
		log.Warn().Str("path", pluginPath).Int64("size", info.Size()).Msg("mql[jenkins]> skipping oversized plugin")
		return nil, nil
	}

	data, err := afs.ReadFile(pluginPath)
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	for _, file := range reader.File {
		if file.Name == "META-INF/MANIFEST.MF" {
			return parsePluginManifest(file)
		}
	}

	return nil, nil
}

// parsePluginManifest extracts Jenkins plugin metadata from a MANIFEST.MF file.
func parsePluginManifest(file *zip.File) (*JenkinsPlugin, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	headers := make(map[string]string)
	scanner := bufio.NewScanner(rc)
	var lastKey string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			break
		}

		// Continuation line
		if strings.HasPrefix(line, " ") && lastKey != "" {
			headers[lastKey] += strings.TrimPrefix(line, " ")
			continue
		}

		if key, value, ok := strings.Cut(line, ": "); ok {
			headers[key] = value
			lastKey = key
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	shortName := headers["Short-Name"]
	if shortName == "" {
		return nil, nil
	}

	// Parse dependencies: "credentials:1289.vb,git-client:4.7.0,..."
	var deps []string
	if depStr := headers["Plugin-Dependencies"]; depStr != "" {
		for _, dep := range strings.Split(depStr, ",") {
			dep = strings.TrimSpace(dep)
			// Remove optional resolution marker
			dep = strings.TrimSuffix(dep, ";resolution:=optional")
			if name, _, ok := strings.Cut(dep, ":"); ok {
				deps = append(deps, name)
			}
		}
	}

	return &JenkinsPlugin{
		Name:         shortName,
		Version:      headers["Plugin-Version"],
		LongName:     headers["Long-Name"],
		Url:          headers["Url"],
		Dependencies: deps,
	}, nil
}

func isPluginFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range pluginExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

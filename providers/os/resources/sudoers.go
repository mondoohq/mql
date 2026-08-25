// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/v13/checksums"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/sudoers"
	"go.mondoo.com/mql/v13/types"
)

// sudoersPaths lists the sudoers file paths to check per platform.
// Most systems use /etc/sudoers. BSD variants and AIX install sudo via
// package managers to non-default prefixes, so /etc/sudoers does not exist.
const defaultSudoersFile = "/etc/sudoers"

var sudoersPaths = map[string][]string{
	"freebsd":      {"/usr/local/etc/sudoers"},
	"dragonflybsd": {"/usr/local/etc/sudoers"},
	"openbsd":      {"/usr/local/etc/sudoers"},
	"netbsd":       {"/usr/pkg/etc/sudoers"},
	"aix":          {"/opt/freeware/etc/sudoers"},
}

func initSudoers(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' it must be a string")
		}

		// If a custom path is provided, just use that file
		files, err := getSortedPathFiles(runtime, path)
		if err != nil {
			return nil, nil, err
		}
		args["files"] = llx.ArrayData(files, types.Resource("file"))
		delete(args, "path")
	}

	return args, nil, nil
}

func (s *mqlSudoers) id() (string, error) {
	checksum := checksums.New
	for i := range s.Files.Data {
		path := s.Files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}
	return checksum.String(), nil
}

func (se *mqlSudoersUserSpec) id() (string, error) {
	file := se.File.Data
	lineNum := strconv.FormatInt(se.LineNumber.Data, 10)

	// Create unique ID from file path and line number
	id := file + ":" + lineNum + ":user_spec"

	return id, nil
}

func (sd *mqlSudoersDefault) id() (string, error) {
	file := sd.File.Data
	lineNum := strconv.FormatInt(sd.LineNumber.Data, 10)

	// Create unique ID from file path and line number
	id := file + ":" + lineNum + ":default"

	return id, nil
}

func (sa *mqlSudoersAlias) id() (string, error) {
	file := sa.File.Data
	lineNum := strconv.FormatInt(sa.LineNumber.Data, 10)
	aliasType := sa.Type.Data

	// Create unique ID from file path, line number, and alias type
	id := file + ":" + lineNum + ":" + aliasType + "_alias"

	return id, nil
}

// sudoersPathsForPlatform returns the sudoers file paths to check for a given platform.
func sudoersPathsForPlatform(conn shared.Connection) []string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if paths, ok := sudoersPaths[asset.Platform.Name]; ok {
			return paths
		}
	}
	return []string{resolveVendorConfigPath(conn.FileSystem(), defaultSudoersFile)}
}

// files returns the list of sudoers configuration files
func (s *mqlSudoers) files() ([]any, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	visited := make(map[string]bool)
	var allFiles []any
	var errs []error

	// Try platform-specific sudoers paths
	for _, path := range sudoersPathsForPlatform(conn) {
		s.collectSudoersFiles(conn, path, visited, &allFiles, &errs)
	}

	if len(errs) > 0 {
		return allFiles, errors.Join(errs...)
	}

	return allFiles, nil
}

// collectSudoersFiles recursively collects sudoers files, following include directives
func (s *mqlSudoers) collectSudoersFiles(conn shared.Connection, path string, visited map[string]bool, allFiles *[]any, errs *[]error) {
	// Avoid infinite loops
	if visited[path] {
		return
	}
	visited[path] = true

	// Check if file exists
	fileRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to create file resource for %s: %w", path, err))
		return
	}
	f := fileRes.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to check if %s exists: %w", path, exists.Error))
		return
	}

	if !exists.Data {
		return
	}

	// Add this file to the list
	*allFiles = append(*allFiles, f)

	// Read file content to find include directives
	content := f.GetContent()
	if content.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to read %s: %w", path, content.Error))
		return
	}

	// Parse include directives
	lines := strings.Split(content.Data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for @include or #include
		if matches := sudoers.IncludeRegex.FindStringSubmatch(line); matches != nil {
			includePath := strings.TrimSpace(matches[1])
			s.collectSudoersFiles(conn, includePath, visited, allFiles, errs)
		}

		// Check for @includedir or #includedir
		if matches := sudoers.IncludedirRegex.FindStringSubmatch(line); matches != nil {
			includeDir := strings.TrimSpace(matches[1])
			s.collectSudoersDir(conn, includeDir, visited, allFiles, errs)
		}
	}
}

// collectSudoersDir collects all sudoers files from a directory
func (s *mqlSudoers) collectSudoersDir(conn shared.Connection, dirPath string, visited map[string]bool, allFiles *[]any, errs *[]error) {
	// Check if directory exists
	dirRes, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(dirPath),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to create file resource for directory %s: %w", dirPath, err))
		return
	}
	dir := dirRes.(*mqlFile)
	dirExists := dir.GetExists()
	if dirExists.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to check if directory %s exists: %w", dirPath, dirExists.Error))
		return
	}

	if !dirExists.Data {
		return
	}

	// Get all files from the directory
	files, err := CreateResource(s.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from": llx.StringData(dirPath),
		"type": llx.StringData("file"),
	})
	if err != nil {
		*errs = append(*errs, fmt.Errorf("failed to list files in %s: %w", dirPath, err))
		return
	}

	ff := files.(*mqlFilesFind)
	list := ff.GetList()
	if list.Error != nil {
		*errs = append(*errs, fmt.Errorf("failed to get file list from %s: %w", dirPath, list.Error))
		return
	}

	// Process each file in the directory
	for i := range list.Data {
		file := list.Data[i].(*mqlFile)
		basename := file.GetBasename()
		if basename.Error != nil {
			*errs = append(*errs, fmt.Errorf("failed to get basename for file in %s: %w", dirPath, basename.Error))
			continue
		}

		// Skip README files as per sudoers convention
		if strings.Contains(strings.ToUpper(basename.Data), "README") {
			continue
		}

		// Skip files with . or ~ in the name (sudoers convention)
		if strings.Contains(basename.Data, ".") || strings.Contains(basename.Data, "~") {
			continue
		}

		// Recursively process this file (it may have its own includes)
		filePath := file.Path.Data
		s.collectSudoersFiles(conn, filePath, visited, allFiles, errs)
	}
}

// content aggregates the content from all sudoers files
func (s *mqlSudoers) content(files []any) (string, error) {
	var res strings.Builder
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		res.WriteString(content.Data)
		res.WriteString("\n")
	}

	if len(errs) > 0 {
		return res.String(), errors.Join(errs...)
	}

	return res.String(), nil
}

// userSpecs parses all sudoers files and returns user specification entries
func (s *mqlSudoers) userSpecs(files []any) ([]any, error) {
	var allEntries []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		entries, err := parseSudoersUserSpecs(s.MqlRuntime, file.Path.Data, content.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse %s: %w", file.Path.Data, err))
			continue
		}

		allEntries = append(allEntries, entries...)
	}

	if len(errs) > 0 {
		return allEntries, errors.Join(errs...)
	}

	return allEntries, nil
}

// parseSudoersUserSpecs parses user specs from content and creates MQL resources
func parseSudoersUserSpecs(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	parsed := sudoers.ParseUserSpecs(filePath, content)
	var entries []any

	for _, spec := range parsed {
		entry, err := CreateResource(runtime, "sudoers.userSpec", map[string]*llx.RawData{
			"file":        llx.StringData(spec.File),
			"lineNumber":  llx.IntData(int64(spec.LineNumber)),
			"users":       llx.ArrayData(toAnySlice(spec.Users), types.String),
			"hosts":       llx.ArrayData(toAnySlice(spec.Hosts), types.String),
			"runasUsers":  llx.ArrayData(toAnySlice(spec.RunasUsers), types.String),
			"runasGroups": llx.ArrayData(toAnySlice(spec.RunasGroups), types.String),
			"tags":        llx.ArrayData(toAnySlice(spec.Tags), types.String),
			"commands":    llx.ArrayData(toAnySlice(spec.Commands), types.String),
		})
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry.(*mqlSudoersUserSpec))
	}

	return entries, nil
}

// defaults parses all sudoers files and returns default entries
func (s *mqlSudoers) defaults(files []any) ([]any, error) {
	var allDefaults []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		defaults, err := parseSudoersDefaults(s.MqlRuntime, file.Path.Data, content.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse %s: %w", file.Path.Data, err))
			continue
		}

		allDefaults = append(allDefaults, defaults...)
	}

	if len(errs) > 0 {
		return allDefaults, errors.Join(errs...)
	}

	return allDefaults, nil
}

// parseSudoersDefaults parses defaults from content and creates MQL resources
func parseSudoersDefaults(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	parsed := sudoers.ParseDefaults(filePath, content)
	var entries []any

	for _, def := range parsed {
		entry, err := CreateResource(runtime, "sudoers.default", map[string]*llx.RawData{
			"file":       llx.StringData(def.File),
			"lineNumber": llx.IntData(int64(def.LineNumber)),
			"raw":        llx.StringData(def.Raw),
			"scope":      llx.StringData(def.Scope),
			"target":     llx.StringData(def.Target),
			"parameter":  llx.StringData(def.Parameter),
			"value":      llx.StringData(def.Value),
			"operation":  llx.StringData(def.Operation),
			"negated":    llx.BoolData(def.Negated),
		})
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry.(*mqlSudoersDefault))
	}

	return entries, nil
}

// aliases parses all sudoers files and returns alias definitions
func (s *mqlSudoers) aliases(files []any) ([]any, error) {
	var allAliases []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		aliases, err := parseSudoersAliases(s.MqlRuntime, file.Path.Data, content.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse %s: %w", file.Path.Data, err))
			continue
		}

		allAliases = append(allAliases, aliases...)
	}

	if len(errs) > 0 {
		return allAliases, errors.Join(errs...)
	}

	return allAliases, nil
}

// parseSudoersAliases parses aliases from content and creates MQL resources
func parseSudoersAliases(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	parsed := sudoers.ParseAliases(filePath, content)
	var entries []any

	for _, alias := range parsed {
		entry, err := CreateResource(runtime, "sudoers.alias", map[string]*llx.RawData{
			"file":       llx.StringData(alias.File),
			"lineNumber": llx.IntData(int64(alias.LineNumber)),
			"type":       llx.StringData(alias.Type),
			"name":       llx.StringData(alias.Name),
			"members":    llx.ArrayData(toAnySlice(alias.Members), types.String),
		})
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry.(*mqlSudoersAlias))
	}

	return entries, nil
}

// toAnySlice converts a []string to []any
func toAnySlice(s []string) []any {
	result := make([]any, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

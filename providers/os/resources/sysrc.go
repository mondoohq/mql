// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// sysrcPaths lists the rc.conf file paths to check on FreeBSD systems.
var sysrcPaths = []string{
	"/etc/rc.conf",
	"/etc/rc.conf.local",
	"/usr/local/etc/rc.conf",
}

// sysrcDirs lists the rc.conf.d directories to check on FreeBSD systems.
var sysrcDirs = []string{
	"/etc/rc.conf.d",
}

func initSysrc(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' it must be a string")
		}

		files, err := getSortedPathFiles(runtime, path)
		if err != nil {
			return nil, nil, err
		}
		args["files"] = llx.ArrayData(files, types.Resource("file"))
		delete(args, "path")
	}

	return args, nil, nil
}

func (s *mqlSysrc) id() (string, error) {
	if len(s.Files.Data) == 0 {
		return "sysrc", nil
	}
	checksum := checksums.New
	for i := range s.Files.Data {
		path := s.Files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}
	return checksum.String(), nil
}

func (s *mqlSysrcEntry) id() (string, error) {
	return s.File.Data + ":" + s.Name.Data, nil
}

// files returns the list of rc.conf configuration files
func (s *mqlSysrc) files() ([]any, error) {
	var allFiles []any
	var errs []error

	for _, path := range sysrcPaths {
		s.collectFile(path, &allFiles, &errs)
	}

	for _, dir := range sysrcDirs {
		s.collectDir(dir, &allFiles, &errs)
	}

	if len(errs) > 0 {
		return allFiles, errors.Join(errs...)
	}

	return allFiles, nil
}

// collectFile adds a single file to the list if it exists
func (s *mqlSysrc) collectFile(path string, allFiles *[]any, errs *[]error) {
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

	*allFiles = append(*allFiles, f)
}

// collectDir adds all files from a directory to the list
func (s *mqlSysrc) collectDir(dirPath string, allFiles *[]any, errs *[]error) {
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

	for i := range list.Data {
		file := list.Data[i].(*mqlFile)
		*allFiles = append(*allFiles, file)
	}
}

// content aggregates the content from all rc.conf files
func (s *mqlSysrc) content(files []any) (string, error) {
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

// entries parses all rc.conf files and returns key-value entries
func (s *mqlSysrc) entries(files []any) ([]any, error) {
	var allEntries []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		entries, err := parseSysrcEntries(s.MqlRuntime, file.Path.Data, content.Data)
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

// SysrcEntry represents a parsed rc.conf variable assignment.
type SysrcEntry struct {
	Name  string
	Value string
}

// ParseSysrc parses rc.conf content and returns key-value entries.
// rc.conf files use shell variable assignment syntax: key="value" or key=value.
// When the same variable is assigned multiple times, only the last assignment
// is kept, matching real sysrc semantics.
func ParseSysrc(content string) []SysrcEntry {
	// Use ordered deduplication: track insertion order but let later values win
	seen := map[string]int{} // name -> index in entries
	var entries []SysrcEntry

	for raw := range strings.Lines(content) {
		line := strings.TrimSpace(raw)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value assignments
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}

		name := strings.TrimSpace(line[:eqIdx])
		value := strings.TrimSpace(line[eqIdx+1:])

		// Strip surrounding quotes from value
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		if idx, ok := seen[name]; ok {
			// Update existing entry in place (last assignment wins)
			entries[idx].Value = value
		} else {
			seen[name] = len(entries)
			entries = append(entries, SysrcEntry{Name: name, Value: value})
		}
	}

	return entries
}

// parseSysrcEntries parses rc.conf content and creates MQL resources for each entry.
func parseSysrcEntries(runtime *plugin.Runtime, filePath string, content string) ([]any, error) {
	parsed := ParseSysrc(content)
	var resources []any

	for _, entry := range parsed {
		resource, err := CreateResource(runtime, "sysrc.entry", map[string]*llx.RawData{
			"name":  llx.StringData(entry.Name),
			"value": llx.StringData(entry.Value),
			"file":  llx.StringData(filePath),
		})
		if err != nil {
			return nil, err
		}

		resources = append(resources, resource.(*mqlSysrcEntry))
	}

	return resources, nil
}

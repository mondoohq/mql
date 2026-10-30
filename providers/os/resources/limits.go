// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/limits"
)

const (
	defaultLimitsFile = "/etc/security/limits.conf"
	defaultLimitsDir  = "/etc/security/limits.d"
)

func initLimits(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return args, nil, nil
}

func (l *mqlLimits) id() (string, error) {
	return "limits", nil
}

func (le *mqlLimitsEntry) id() (string, error) {
	file := le.File.Data
	if file == nil {
		return "", errors.New("cannot determine limits entry ID (missing file)")
	}

	lineNum := strconv.FormatInt(le.LineNumber.Data, 10)

	// Create unique ID from file path and line number
	id := file.Path.Data + ":" + lineNum

	return id, nil
}

// files returns the list of limits configuration files
func (l *mqlLimits) files() ([]any, error) {
	var allFiles []any

	var fs afero.Fs
	if conn, ok := l.MqlRuntime.Connection.(shared.Connection); ok {
		fs = conn.FileSystem()
	}

	// Add main limits file. On distributions that ship packaged defaults under
	// /usr/etc (openSUSE Leap 16, SLE 16) this is where the file actually is.
	mainFile, err := CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(resolveVendorConfigPath(fs, defaultLimitsFile)),
	})
	if err != nil {
		return nil, err
	}
	f := mainFile.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}

	if exists.Data {
		allFiles = append(allFiles, f)
	}

	// Drop-ins merge across both trees, with /etc shadowing a same-named file
	// in /usr/etc.
	var dropIns []*mqlFile
	for _, dir := range vendorConfigDirs(fs, defaultLimitsDir) {
		// pam_limits globs limits.d/*.conf, which does not descend into
		// subdirectories
		files, err := CreateResource(l.MqlRuntime, "files.find", map[string]*llx.RawData{
			"from":  llx.StringData(dir),
			"type":  llx.StringData("file"),
			"depth": llx.IntData(1),
		})
		if err != nil {
			return nil, err
		}

		ff := files.(*mqlFilesFind)
		list := ff.GetList()
		if list.Error != nil {
			return nil, list.Error
		}

		// Filter for .conf files from limits.d
		for i := range list.Data {
			file := list.Data[i].(*mqlFile)
			basename := file.GetBasename()
			if basename.Error != nil {
				continue
			}

			if !isLimitsDropIn(basename.Data) {
				continue
			}
			if vendorConfigShadowed(fs, file.Path.Data) {
				continue
			}
			dropIns = append(dropIns, file)
		}
	}

	sortLimitsDropIns(dropIns)
	for _, file := range dropIns {
		allFiles = append(allFiles, file)
	}

	return allFiles, nil
}

// isLimitsDropIn reports whether pam_limits' limits.d/*.conf glob matches a
// file name. Like any glob `*`, it does not match a leading dot.
func isLimitsDropIn(name string) bool {
	return strings.HasSuffix(name, ".conf") && !strings.HasPrefix(name, ".")
}

// sortLimitsDropIns puts limits.d files in the order pam_limits reads them:
// sorted by file name with strcmp, whichever of /etc and /usr/etc they come
// from (read_limits_dir in pam_limits.c). files.find returns them in
// directory order, so on Debian 13 60-local.conf came before
// 10-coredump-debian.conf. Order matters: for the same kind of domain, an
// entry read later replaces an earlier one.
func sortLimitsDropIns(files []*mqlFile) {
	sort.SliceStable(files, func(i, j int) bool {
		return path.Base(files[i].Path.Data) < path.Base(files[j].Path.Data)
	})
}

// entries parses all limits files and returns structured entries
func (l *mqlLimits) entries(files []any) ([]any, error) {
	var allEntries []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		entries, err := parseLimitsContent(l.MqlRuntime, file, content.Data)
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

// parseLimitsContent parses the content of a limits file and creates MQL resources
func parseLimitsContent(runtime *plugin.Runtime, file *mqlFile, content string) ([]any, error) {
	parsed := limits.ParseLines(file.Path.Data, content)
	var entries []any

	for _, e := range parsed {
		entry, err := CreateResource(runtime, "limits.entry", map[string]*llx.RawData{
			"file":       llx.ResourceData(file, "file"),
			"lineNumber": llx.IntData(int64(e.LineNumber)),
			"domain":     llx.StringData(e.Domain),
			"type":       llx.StringData(e.Type),
			"item":       llx.StringData(e.Item),
			"value":      llx.StringData(e.Value),
		})
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry.(*mqlLimitsEntry))
	}

	return entries, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/crontab"
)

// System crontab paths (with user field)
var systemCrontabPaths = []string{
	"/etc/crontab",
}

// System cron.d directory (with user field)
var systemCronDirs = []string{
	"/etc/cron.d",
}

// User crontab directories (without user field, filename is the user)
var userCrontabDirs = []string{
	"/var/spool/cron/crontabs", // Debian/Ubuntu
	"/var/spool/cron",          // RHEL/CentOS/Fedora
	"/usr/lib/cron/tabs",       // macOS
}

func (c *mqlCrontab) id() (string, error) {
	return "crontab", nil
}

func (c *mqlCrontab) entries() ([]any, error) {
	conn, ok := c.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	fsys := conn.FileSystem()
	if fsys == nil {
		return nil, errors.New("filesystem not available")
	}
	afs := &afero.Afero{Fs: fsys}

	var allEntries []any
	var allFiles []any

	// Parse system crontabs (/etc/crontab)
	for _, path := range systemCrontabPaths {
		entries, fileRes, err := c.parseCrontabFile(afs, path, true, "")
		if err != nil {
			continue // Skip files that don't exist or can't be read
		}
		allEntries = append(allEntries, entries...)
		if fileRes != nil {
			allFiles = append(allFiles, fileRes)
		}
	}

	// Parse system cron.d directory
	for _, dir := range systemCronDirs {
		entries, files, err := c.parseCronDir(afs, dir, true)
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
		allFiles = append(allFiles, files...)
	}

	// Parse user crontabs
	for _, dir := range userCrontabDirs {
		entries, files, err := c.parseUserCrontabDir(afs, dir)
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
		allFiles = append(allFiles, files...)
	}

	// Store files for the files() method
	c.Files = plugin.TValue[[]any]{Data: allFiles, State: plugin.StateIsSet}

	return allEntries, nil
}

func (c *mqlCrontab) files() ([]any, error) {
	// Trigger entries() which populates Files
	result := c.GetEntries()
	if result.Error != nil {
		return nil, result.Error
	}
	return c.Files.Data, nil
}

// parseCrontabFile parses a single crontab file
func (c *mqlCrontab) parseCrontabFile(afs *afero.Afero, path string, hasUserField bool, defaultUser string) ([]any, plugin.Resource, error) {
	f, err := afs.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	entries, err := crontab.ParseCrontab(f, hasUserField)
	if err != nil {
		return nil, nil, err
	}

	// Create file resource
	fileRes, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, nil, err
	}

	var resources []any
	for _, entry := range entries {
		user := entry.User
		if user == "" && defaultUser != "" {
			user = defaultUser
		}

		entryRes, err := CreateResource(c.MqlRuntime, "crontab.entry", map[string]*llx.RawData{
			"lineNumber": llx.IntData(int64(entry.LineNumber)),
			"minute":     llx.StringData(entry.Minute),
			"hour":       llx.StringData(entry.Hour),
			"dayOfMonth": llx.StringData(entry.DayOfMonth),
			"month":      llx.StringData(entry.Month),
			"dayOfWeek":  llx.StringData(entry.DayOfWeek),
			"user":       llx.StringData(user),
			"command":    llx.StringData(entry.Command),
			"file":       llx.ResourceData(fileRes, "file"),
		})
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, entryRes)
	}

	return resources, fileRes, nil
}

// parseCronDir parses all files in a cron directory (like /etc/cron.d)
func (c *mqlCrontab) parseCronDir(afs *afero.Afero, dir string, hasUserField bool) ([]any, []any, error) {
	files, err := afs.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	var allEntries []any
	var allFiles []any

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// Skip files starting with . or ending with common backup suffixes
		name := file.Name()
		if strings.HasPrefix(name, ".") ||
			strings.HasSuffix(name, "~") ||
			strings.HasSuffix(name, ".bak") ||
			strings.HasSuffix(name, ".dpkg-old") ||
			strings.HasSuffix(name, ".dpkg-new") ||
			strings.HasSuffix(name, ".dpkg-dist") ||
			strings.HasSuffix(name, ".rpmsave") ||
			strings.HasSuffix(name, ".rpmnew") {
			continue
		}

		path := filepath.Join(dir, name)
		entries, fileRes, err := c.parseCrontabFile(afs, path, hasUserField, "")
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
		if fileRes != nil {
			allFiles = append(allFiles, fileRes)
		}
	}

	return allEntries, allFiles, nil
}

// parseUserCrontabDir parses user crontabs where filename is the username
func (c *mqlCrontab) parseUserCrontabDir(afs *afero.Afero, dir string) ([]any, []any, error) {
	files, err := afs.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	var allEntries []any
	var allFiles []any

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// Skip hidden files and common backup files
		name := file.Name()
		if strings.HasPrefix(name, ".") ||
			strings.HasSuffix(name, "~") ||
			strings.HasSuffix(name, ".bak") {
			continue
		}

		// The filename is the username for user crontabs
		username := name
		path := filepath.Join(dir, name)

		// User crontabs don't have the user field - the filename is the user
		entries, fileRes, err := c.parseCrontabFile(afs, path, false, username)
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
		if fileRes != nil {
			allFiles = append(allFiles, fileRes)
		}
	}

	return allEntries, allFiles, nil
}

func (e *mqlCrontabEntry) id() (string, error) {
	file := e.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "", errors.New("cannot determine crontab entry ID (missing file)")
	}

	path := file.Data.GetPath()
	if path.Error != nil {
		return "", path.Error
	}

	lineNum := e.GetLineNumber()
	if lineNum.Error != nil {
		return "", lineNum.Error
	}

	return fmt.Sprintf("%s:%d", path.Data, lineNum.Data), nil
}

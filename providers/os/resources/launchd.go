// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/types"
)

// launchd directories to scan
var launchdDirectories = []struct {
	path    string
	source  string
	jobType string
}{
	{"/System/Library/LaunchDaemons", "system", "daemon"},
	{"/Library/LaunchDaemons", "library", "daemon"},
	{"/Library/Apple/System/Library/LaunchDaemons", "system", "daemon"},
	{"/System/Library/LaunchAgents", "system", "agent"},
	{"/Library/LaunchAgents", "library", "agent"},
	{"/Library/Apple/System/Library/LaunchAgents", "system", "agent"},
}

// User agent directory (relative to home)
const userLaunchAgentsDir = "Library/LaunchAgents"

func initLaunchd(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if !platform.IsFamily("darwin") {
		return nil, nil, errors.New("launchd resource is only supported on macOS")
	}

	return args, nil, nil
}

func (l *mqlLaunchd) id() (string, error) {
	return "launchd", nil
}

func (l *mqlLaunchd) jobs() ([]any, error) {
	conn, ok := l.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	fsys := conn.FileSystem()
	if fsys == nil {
		return nil, errors.New("filesystem not available")
	}
	afs := &afero.Afero{Fs: fsys}

	var allJobs []any

	// Parse system and library directories
	for _, dir := range launchdDirectories {
		jobs, err := l.parseJobsInDirectory(afs, dir.path, dir.source, dir.jobType)
		if err != nil {
			log.Debug().Err(err).Str("path", dir.path).Msg("launchd> skipping directory")
			continue
		}
		allJobs = append(allJobs, jobs...)
	}

	// Parse user agents from home directories
	userJobs, err := l.parseUserAgents(afs)
	if err != nil {
		log.Debug().Err(err).Msg("launchd> error enumerating user agents")
	}
	allJobs = append(allJobs, userJobs...)

	return allJobs, nil
}

func (l *mqlLaunchd) parseUserAgents(afs *afero.Afero) ([]any, error) {
	// Get list of users to find their home directories
	usersRes, err := CreateResource(l.MqlRuntime, "users", nil)
	if err != nil {
		return nil, err
	}
	users := usersRes.(*mqlUsers)
	userList := users.GetList()
	if userList.Error != nil {
		return nil, userList.Error
	}

	var allJobs []any
	for _, u := range userList.Data {
		user := u.(*mqlUser)
		home := user.GetHome()
		if home.Error != nil || home.Data == "" {
			continue
		}

		// Skip system accounts with well-known non-user home directories
		if isSystemHomeDir(home.Data) {
			continue
		}

		userAgentDir := filepath.Join(home.Data, userLaunchAgentsDir)
		jobs, err := l.parseJobsInDirectory(afs, userAgentDir, "user", "agent")
		if err != nil {
			log.Debug().Err(err).Str("path", userAgentDir).Msg("launchd> skipping user LaunchAgents directory")
			continue
		}
		allJobs = append(allJobs, jobs...)
	}

	return allJobs, nil
}

func (l *mqlLaunchd) parseJobsInDirectory(afs *afero.Afero, dirPath, source, jobType string) ([]any, error) {
	files, err := afs.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var jobs []any
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// Only process .plist files (case-insensitive check for macOS compatibility)
		if !strings.HasSuffix(strings.ToLower(file.Name()), ".plist") {
			continue
		}

		path := filepath.Join(dirPath, file.Name())
		job, err := l.parseJobFile(afs, path, source, jobType)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("launchd> skipping plist file")
			continue
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

func (l *mqlLaunchd) parseJobFile(afs *afero.Afero, path, source, jobType string) (*mqlLaunchdJob, error) {
	f, err := afs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := plist.Decode(f)
	if err != nil {
		return nil, err
	}

	// Create file resource
	fileRes, err := CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	// Extract fields from plist
	label := launchdGetString(data, "Label")
	program := launchdGetString(data, "Program")
	workingDirectory := launchdGetString(data, "WorkingDirectory")
	userName := launchdGetString(data, "UserName")
	groupName := launchdGetString(data, "GroupName")
	processType := launchdGetString(data, "ProcessType")
	runAtLoad := launchdGetBool(data, "RunAtLoad")
	disabled := launchdGetBool(data, "Disabled")
	startInterval := launchdGetInt(data, "StartInterval")
	programArguments := launchdGetStringArray(data, "ProgramArguments")
	watchPaths := launchdGetStringArray(data, "WatchPaths")
	stdoutPath := launchdGetString(data, "StandardOutPath")
	stderrPath := launchdGetString(data, "StandardErrorPath")
	rootDirectory := launchdGetString(data, "RootDirectory")
	keepAlive := launchdParseKeepAlive(data)
	sockets := launchdGetDict(data, "Sockets")
	machServices := launchdGetDict(data, "MachServices")
	startCalendarInterval := launchdGetDictArray(data, "StartCalendarInterval")
	environmentVariables := launchdGetStringMap(data, "EnvironmentVariables")
	// llx's dict converter accepts map[string]any but not the named type
	// plist.Data, so hand it the underlying map.
	content := map[string]any(data)

	// Create the job resource with path as __id
	job, err := CreateResource(l.MqlRuntime, "launchd.job", map[string]*llx.RawData{
		"__id":                  llx.StringData(path),
		"label":                 llx.StringData(label),
		"path":                  llx.StringData(path),
		"type":                  llx.StringData(jobType),
		"source":                llx.StringData(source),
		"runAtLoad":             llx.BoolData(runAtLoad),
		"program":               llx.StringData(program),
		"programArguments":      llx.ArrayData(programArguments, types.String),
		"disabled":              llx.BoolData(disabled),
		"keepAlive":             llx.DictData(keepAlive),
		"workingDirectory":      llx.StringData(workingDirectory),
		"environmentVariables":  llx.MapData(environmentVariables, types.String),
		"userName":              llx.StringData(userName),
		"groupName":             llx.StringData(groupName),
		"processType":           llx.StringData(processType),
		"startInterval":         llx.IntData(startInterval),
		"startCalendarInterval": llx.ArrayData(startCalendarInterval, types.Dict),
		"sockets":               llx.DictData(sockets),
		"machServices":          llx.DictData(machServices),
		"watchPaths":            llx.ArrayData(watchPaths, types.String),
		"stdoutPath":            llx.StringData(stdoutPath),
		"stderrPath":            llx.StringData(stderrPath),
		"rootDirectory":         llx.StringData(rootDirectory),
		"file":                  llx.ResourceData(fileRes, "file"),
		"content":               llx.DictData(content),
	})
	if err != nil {
		return nil, err
	}

	return job.(*mqlLaunchdJob), nil
}

func (j *mqlLaunchdJob) id() (string, error) {
	return j.Path.Data, nil
}

// Helper functions for extracting typed values from plist data

func launchdGetString(data plist.Data, key string) string {
	if val, ok := data.GetString(key); ok {
		return val
	}
	return ""
}

func launchdGetBool(data plist.Data, key string) bool {
	if val, exists := data[key]; exists {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func launchdGetInt(data plist.Data, key string) int64 {
	if val, ok := data.GetNumber(key); ok {
		return int64(math.Round(val))
	}
	return 0
}

// launchdParseKeepAlive normalizes the KeepAlive field which can be either
// a boolean or a dictionary with conditions. Returns a consistent structure:
//   - {"enabled": true/false} for simple boolean values
//   - {"enabled": true, "conditions": {...}} for conditional KeepAlive
func launchdParseKeepAlive(data plist.Data) map[string]any {
	val, exists := data["KeepAlive"]
	if !exists {
		return nil
	}

	switch v := val.(type) {
	case bool:
		return map[string]any{"enabled": v}
	case map[string]any:
		return map[string]any{"enabled": true, "conditions": v}
	}
	return nil
}

func launchdGetDict(data plist.Data, key string) map[string]any {
	if val, exists := data[key]; exists {
		if m, ok := val.(map[string]any); ok {
			return m
		}
	}
	return nil
}

func launchdGetStringArray(data plist.Data, key string) []any {
	if list, ok := data.GetList(key); ok {
		result := make([]any, len(list))
		for i, item := range list {
			if s, ok := item.(string); ok {
				result[i] = s
			} else {
				result[i] = ""
			}
		}
		return result
	}
	return []any{}
}

// launchdGetDictArray handles fields like StartCalendarInterval which Apple
// allows as either a single dict or an array of dicts, normalizing to an array.
func launchdGetDictArray(data plist.Data, key string) []any {
	if list, ok := data.GetList(key); ok {
		result := make([]any, len(list))
		for i, item := range list {
			if d, ok := item.(map[string]any); ok {
				result[i] = d
			} else {
				result[i] = map[string]any{}
			}
		}
		return result
	}
	// Handle single dict case (Apple allows either dict or array)
	if val, exists := data[key]; exists {
		if d, ok := val.(map[string]any); ok {
			return []any{d}
		}
	}
	return []any{}
}

func launchdGetStringMap(data plist.Data, key string) map[string]any {
	if val, exists := data[key]; exists {
		if m, ok := val.(map[string]any); ok {
			result := make(map[string]any, len(m))
			for k, v := range m {
				if s, ok := v.(string); ok {
					result[k] = s
				} else {
					result[k] = fmt.Sprintf("%v", v)
				}
			}
			return result
		}
	}
	return map[string]any{}
}

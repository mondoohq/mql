// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/inetd"
)

const (
	defaultInetdConfig    = "/etc/inetd.conf"
	defaultInetdConfigDir = "/etc/inetd.d"
)

func initInetdConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in inetd.config initialization, it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")

		delete(args, "path")
	}

	return args, nil, nil
}

func (s *mqlInetdConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return "inetd.config/" + file.Data.Path.Data, nil
}

func (s *mqlInetdConfig) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultInetdConfig),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlInetdConfig) files(file *mqlFile) ([]any, error) {
	if file == nil {
		return nil, errors.New("no base inetd config file to read")
	}

	res := []any{file}

	// Drop-in files under /etc/inetd.d are only part of the default
	// configuration. When the caller points at a custom file, we read just
	// that file.
	if file.Path.Data == defaultInetdConfig {
		dropins, err := s.dropInFiles()
		if err != nil {
			return nil, err
		}
		res = append(res, dropins...)
	}

	return res, nil
}

// dropInFiles returns the sorted set of files under /etc/inetd.d, or nil when
// that directory doesn't exist.
func (s *mqlInetdConfig) dropInFiles() ([]any, error) {
	raw, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultInetdConfigDir),
	})
	if err != nil {
		return nil, err
	}
	dir := raw.(*mqlFile)

	exists := dir.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, nil
	}

	return getSortedPathFiles(s.MqlRuntime, defaultInetdConfigDir)
}

// inetdFileContent returns the file's content, or an empty string when the
// file is absent. A missing /etc/inetd.conf is a normal state (the system
// simply doesn't run inetd), so it yields no entries rather than an error.
func inetdFileContent(file *mqlFile) (string, error) {
	exists := file.GetExists()
	if exists.Error != nil {
		return "", exists.Error
	}
	if !exists.Data {
		return "", nil
	}

	content := file.GetContent()
	if content.Error != nil {
		return "", content.Error
	}
	if content.IsNull() {
		return "", nil
	}
	return content.Data, nil
}

func (s *mqlInetdConfig) content(files []any) (string, error) {
	parts := make([]string, 0, len(files))
	for i := range files {
		c, err := inetdFileContent(files[i].(*mqlFile))
		if err != nil {
			return "", err
		}
		parts = append(parts, c)
	}
	return strings.Join(parts, "\n"), nil
}

func (s *mqlInetdConfig) entries(files []any) ([]any, error) {
	res := []any{}
	parser := &inetd.Parser{}
	for i := range files {
		file := files[i].(*mqlFile)

		content, err := inetdFileContent(file)
		if err != nil {
			return nil, err
		}
		if content == "" {
			continue
		}

		for _, e := range parser.Parse(content) {
			ctx, err := CreateResource(s.MqlRuntime, "file.context", map[string]*llx.RawData{
				"file":  llx.ResourceData(file, "file"),
				"range": llx.RangeData(llx.NewRange().AddLine(uint32(e.Line))),
			})
			if err != nil {
				return nil, err
			}

			obj, err := CreateResource(s.MqlRuntime, "inetd.config.entry", map[string]*llx.RawData{
				// The line number keeps the id unique when a file repeats the
				// same service+protocol across multiple lines; without it the
				// later entry would silently shadow the earlier one.
				"__id":       llx.StringData(fmt.Sprintf("%s/%d/%s/%s", file.Path.Data, e.Line, e.Name, e.Protocol)),
				"name":       llx.StringData(e.Name),
				"address":    llx.StringData(e.Address),
				"socketType": llx.StringData(e.SocketType),
				"protocol":   llx.StringData(e.Protocol),
				"wait":       llx.StringData(e.Wait),
				"user":       llx.StringData(e.User),
				"server":     llx.StringData(e.Server),
				"arguments":  llx.StringData(e.Arguments),
				"context":    llx.ResourceData(ctx, "file.context"),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, obj)
		}
	}
	return res, nil
}

func (s *mqlInetdConfig) serviceNames(entries []any) ([]any, error) {
	res := []any{}
	seen := map[string]struct{}{}
	for i := range entries {
		name := entries[i].(*mqlInetdConfigEntry).Name.Data
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		res = append(res, name)
	}
	return res, nil
}

func (s *mqlInetdConfigEntry) context() (*mqlFileContext, error) {
	return nil, errors.New("context was not provided for inetd.config entry")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

func initNtpConf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in ntp.conf initialization, it must be a string")
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

const defaultNtpConf = "/etc/ntp.conf"

func (s *mqlNtpConf) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "", errors.New("cannot get file for ntp.conf")
	}
	return file.Data.Path.Data, nil
}

func (s *mqlNtpConf) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(defaultNtpConf),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlNtpConf) content(file *mqlFile) (string, error) {
	return fileContentOrEmpty(file)
}

func (s *mqlNtpConf) settings(content string) ([]any, error) {
	lines := strings.Split(content, "\n")

	settings := []any{}
	var line string
	for i := range lines {
		line = lines[i]
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[0:idx]
		}
		line = strings.Trim(line, " \t\r")

		if line != "" {
			settings = append(settings, line)
		}
	}

	return settings, nil
}

func (s *mqlNtpConf) servers(settings []any) ([]any, error) {
	return directiveValues(settings, "server"), nil
}

func (s *mqlNtpConf) restrict(settings []any) ([]any, error) {
	return directiveValues(settings, "restrict"), nil
}

func (s *mqlNtpConf) fudge(settings []any) ([]any, error) {
	return directiveValues(settings, "fudge"), nil
}

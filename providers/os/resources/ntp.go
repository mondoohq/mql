// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
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

// Solaris keeps its ntp configuration under /etc/inet, and the file ntpd reads
// is an SMF property of the ntp service: the Oracle Cloud image points it at
// /etc/inet/ntp.linklocal.
const (
	solarisDefaultNtpConf = "/etc/inet/ntp.conf"
	solarisNtpConfCommand = "svcprop -p config/configfile svc:/network/ntp:default"
)

// solarisNtpConfPath picks the file ntpd reads from the output of
// solarisNtpConfCommand, falling back to the Solaris default when the property
// is unset or the service does not exist.
func solarisNtpConfPath(svcpropOut string, exitCode int64) string {
	path := strings.TrimSpace(svcpropOut)
	if exitCode != 0 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\n ") {
		return solarisDefaultNtpConf
	}
	return path
}

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
	path := defaultNtpConf
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if ok && conn.Asset() != nil && conn.Asset().Platform != nil && conn.Asset().Platform.Name == "solaris" {
		o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(solarisNtpConfCommand),
		})
		if err != nil {
			return nil, err
		}
		cmd := o.(*mqlCommand)
		exit := cmd.GetExitcode()
		if exit.Error != nil {
			return nil, exit.Error
		}
		path = solarisNtpConfPath(cmd.GetStdout().Data, exit.Data)
	}

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
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

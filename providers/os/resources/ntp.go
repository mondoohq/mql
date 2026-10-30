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

// NTPsec on Debian (12 and later) and Ubuntu (24.04 and later) reads
// /etc/ntpsec/ntp.conf. The dpkg file list says the package is installed, as
// opposed to removed with its conffiles left behind.
const (
	ntpsecNtpConf  = "/etc/ntpsec/ntp.conf"
	ntpsecDpkgList = "/var/lib/dpkg/info/ntpsec.list"
)

// ntpConfPath picks the file ntpd reads on hosts other than Solaris: NTPsec's
// when NTPsec is installed or when only its file is there, /etc/ntp.conf
// otherwise.
func ntpConfPath(exists func(path string) bool) string {
	if !exists(ntpsecNtpConf) {
		return defaultNtpConf
	}
	if exists(ntpsecDpkgList) || !exists(defaultNtpConf) {
		return ntpsecNtpConf
	}
	return defaultNtpConf
}

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
	} else if ok {
		fs := conn.FileSystem()
		path = ntpConfPath(func(p string) bool {
			_, err := fs.Stat(p)
			return err == nil
		})
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

func (s *mqlNtpConf) pools(settings []any) ([]any, error) {
	return directiveValues(settings, "pool"), nil
}

func (s *mqlNtpConf) peers(settings []any) ([]any, error) {
	return directiveValues(settings, "peer"), nil
}

func (s *mqlNtpConf) restrict(settings []any) ([]any, error) {
	return directiveValues(settings, "restrict"), nil
}

func (s *mqlNtpConf) fudge(settings []any) ([]any, error) {
	return directiveValues(settings, "fudge"), nil
}

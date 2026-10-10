// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package systemd

import (
	"io"
	"regexp"
	"strings"
)

var MACHINE_INFO_REGEX = regexp.MustCompile(`(?m)^\s*(.+?)\s*=\s*['"]?(.*?)['"]?\s*$`)

type MachineInfo struct {
	PrettyHostname string
	IconName       string
	Chassis        string
	Deployment     string
}

// https://www.freedesktop.org/software/systemd/man/latest/machine-info.html
// ParseMachineInfo parses the content of/etc /machine-info as specified for systemd
func ParseMachineInfo(r io.Reader) (MachineInfo, error) {
	res := MachineInfo{}

	content, err := io.ReadAll(r)
	if err != nil {
		return res, err
	}

	m := MACHINE_INFO_REGEX.FindAllStringSubmatch(string(content), -1)
	for _, value := range m {
		switch strings.ToLower(value[1]) {
		case "pretty_hostname":
			res.PrettyHostname = value[2]
		case "icon_name":
			res.IconName = value[2]
		case "chassis":
			res.Chassis = value[2]
		case "deployment":
			res.Deployment = value[2]
		}
	}
	return res, nil
}

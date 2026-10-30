// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// AIXSmbiosManager gets system information from AIX systems.
// smbios is not a thing on AIX, but we implement this interface
type AIXSmbiosManager struct {
	provider shared.Connection
}

func (s *AIXSmbiosManager) Name() string {
	return "AIX Smbios Manager"
}

func (s *AIXSmbiosManager) Info() (*SmBiosInfo, error) {

	cmd, err := s.provider.RunCommand("prtconf")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to run prtconf: " + string(stderr))
	}

	baseBoardInfo, sysInfo, err := ParsePrtConf(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	return &SmBiosInfo{
		BaseBoardInfo: baseBoardInfo,
		SysInfo:       sysInfo,
	}, nil
}

func ParsePrtConf(reader io.Reader) (BaseBoardInfo, SysInfo, error) {
	baseBoardInfo := BaseBoardInfo{
		Vendor: "IBM",
	}
	sysInfo := SysInfo{
		Vendor: "IBM",
		Family: "IBM Power Systems",
	}

	processLine := func(line, key string, target *string) {
		if strings.Contains(line, key) {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				*target = strings.TrimSpace(parts[1])
			}
		}
	}

	// Read each line from the reader
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		// Process the line to extract relevant information

		processLine(line, "System Model", &baseBoardInfo.Model)
		sysInfo.Model = baseBoardInfo.Model

		processLine(line, "Machine Serial Number", &baseBoardInfo.SerialNumber)
		sysInfo.SerialNumber = baseBoardInfo.SerialNumber

		processLine(line, "Firmware Version", &baseBoardInfo.Version)
		sysInfo.Version = baseBoardInfo.Version
	}
	if err := scanner.Err(); err != nil {
		return baseBoardInfo, sysInfo, err
	}
	return baseBoardInfo, sysInfo, nil
}

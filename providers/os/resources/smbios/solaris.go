// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SolarisSmbiosManager reads the SMBIOS tables of an x86 Solaris or illumos
// system with smbios(8), which needs no privileges. SPARC systems have no
// SMBIOS and no smbios command.
type SolarisSmbiosManager struct {
	provider shared.Connection
}

func (s *SolarisSmbiosManager) Name() string {
	return "Solaris Smbios Manager"
}

func (s *SolarisSmbiosManager) Info() (*SmBiosInfo, error) {
	cmd, err := s.provider.RunCommand("/usr/sbin/smbios")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, errors.New("failed to run smbios: " + strings.TrimSpace(string(stderr)))
	}
	return ParseSolarisSmbios(cmd.Stdout)
}

// ParseSolarisSmbios reads smbios(8) output. Each structure starts with an
// `ID SIZE TYPE` header followed by a line naming its type
// (`256   73   SMB_TYPE_SYSTEM (system information)`) and indented
// `Key: value` lines. Only the first structure of each type is used, which is
// what /sys/class/dmi/id reports on Linux too.
func ParseSolarisSmbios(r io.Reader) (*SmBiosInfo, error) {
	smInfo := &SmBiosInfo{}
	fields := map[string]map[string]*string{
		"SMB_TYPE_BIOS": {
			"Vendor":         &smInfo.BIOS.Vendor,
			"Version String": &smInfo.BIOS.Version,
			"Release Date":   &smInfo.BIOS.ReleaseDate,
		},
		"SMB_TYPE_SYSTEM": {
			"Manufacturer":  &smInfo.SysInfo.Vendor,
			"Product":       &smInfo.SysInfo.Model,
			"Version":       &smInfo.SysInfo.Version,
			"Serial Number": &smInfo.SysInfo.SerialNumber,
			"UUID":          &smInfo.SysInfo.UUID,
			"Family":        &smInfo.SysInfo.Family,
			"SKU Number":    &smInfo.SysInfo.SKU,
		},
		"SMB_TYPE_BASEBOARD": {
			"Manufacturer":  &smInfo.BaseBoardInfo.Vendor,
			"Product":       &smInfo.BaseBoardInfo.Model,
			"Version":       &smInfo.BaseBoardInfo.Version,
			"Serial Number": &smInfo.BaseBoardInfo.SerialNumber,
			"Asset Tag":     &smInfo.BaseBoardInfo.AssetTag,
		},
		"SMB_TYPE_CHASSIS": {
			"Manufacturer":  &smInfo.ChassisInfo.Vendor,
			"Version":       &smInfo.ChassisInfo.Version,
			"Serial Number": &smInfo.ChassisInfo.SerialNumber,
			"Asset Tag":     &smInfo.ChassisInfo.AssetTag,
			"Chassis Type":  &smInfo.ChassisInfo.Type,
		},
	}

	var current map[string]*string
	seen := map[string]bool{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fs := strings.Fields(line)

		// structure header: "<id> <size> SMB_TYPE_... (description)"
		if len(fs) >= 3 && strings.HasPrefix(fs[2], "SMB_TYPE_") {
			current = nil
			if f, ok := fields[fs[2]]; ok && !seen[fs[2]] {
				seen[fs[2]] = true
				current = f
			}
			continue
		}
		if current == nil {
			continue
		}

		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		dst, ok := current[key]
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if key == "Chassis Type" {
			value = solarisChassisType(value)
		}
		*dst = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return smInfo, nil
}

// solarisChassisType turns "0x1 (other)" into the decimal SMBIOS code "1",
// which is how Linux reports chassis_type.
func solarisChassisType(value string) string {
	code, _, _ := strings.Cut(value, " ")
	n, err := strconv.ParseInt(strings.TrimPrefix(code, "0x"), 16, 64)
	if err != nil {
		return value
	}
	return strconv.FormatInt(n, 10)
}

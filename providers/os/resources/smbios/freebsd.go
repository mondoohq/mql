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

// FreeBSDSmbiosManager reads the SMBIOS tables on FreeBSD. FreeBSD has no
// /sys/class/dmi/id; the loader parses the tables at boot and publishes them
// in the kernel environment as smbios.* variables, which kenv prints.
type FreeBSDSmbiosManager struct {
	provider shared.Connection
}

func (s *FreeBSDSmbiosManager) Name() string {
	return "FreeBSD Smbios Manager"
}

func (s *FreeBSDSmbiosManager) Info() (*SmBiosInfo, error) {
	// kenv without arguments dumps the whole kernel environment in one call.
	// Asking for several names at once is not supported (it prints usage).
	cmd, err := s.provider.RunCommand("kenv")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, errors.New("failed to run kenv: " + strings.TrimSpace(string(stderr)))
	}
	return ParseKenvSmbios(cmd.Stdout)
}

// ParseKenvSmbios reads kenv output (one name="value" per line) and maps the
// smbios.* variables the FreeBSD loader sets onto the same fields the Linux
// manager fills from /sys/class/dmi/id.
func ParseKenvSmbios(r io.Reader) (*SmBiosInfo, error) {
	smInfo := &SmBiosInfo{}
	fields := map[string]*string{
		"smbios.bios.vendor":     &smInfo.BIOS.Vendor,
		"smbios.bios.version":    &smInfo.BIOS.Version,
		"smbios.bios.reldate":    &smInfo.BIOS.ReleaseDate,
		"smbios.system.maker":    &smInfo.SysInfo.Vendor,
		"smbios.system.product":  &smInfo.SysInfo.Model,
		"smbios.system.version":  &smInfo.SysInfo.Version,
		"smbios.system.serial":   &smInfo.SysInfo.SerialNumber,
		"smbios.system.uuid":     &smInfo.SysInfo.UUID,
		"smbios.system.family":   &smInfo.SysInfo.Family,
		"smbios.system.sku":      &smInfo.SysInfo.SKU,
		"smbios.planar.maker":    &smInfo.BaseBoardInfo.Vendor,
		"smbios.planar.product":  &smInfo.BaseBoardInfo.Model,
		"smbios.planar.version":  &smInfo.BaseBoardInfo.Version,
		"smbios.planar.serial":   &smInfo.BaseBoardInfo.SerialNumber,
		"smbios.planar.tag":      &smInfo.BaseBoardInfo.AssetTag,
		"smbios.chassis.maker":   &smInfo.ChassisInfo.Vendor,
		"smbios.chassis.version": &smInfo.ChassisInfo.Version,
		"smbios.chassis.serial":  &smInfo.ChassisInfo.SerialNumber,
		"smbios.chassis.tag":     &smInfo.ChassisInfo.AssetTag,
		"smbios.chassis.type":    &smInfo.ChassisInfo.Type,
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		dst, ok := fields[strings.TrimSpace(name)]
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		*dst = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return smInfo, nil
}

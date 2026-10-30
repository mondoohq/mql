// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type LinuxSmbiosManager struct {
	provider shared.Connection
}

func (s *LinuxSmbiosManager) Name() string {
	return "Linux Smbios Manager"
}

func (s *LinuxSmbiosManager) Info() (*SmBiosInfo, error) {
	return readLinuxSmbios(s.provider.FileSystem())
}

// dmiRoot is the sysfs directory the kernel exports the SMBIOS tables through.
const dmiRoot = "/sys/class/dmi/id/"

func readLinuxSmbios(fs afero.Fs) (*SmBiosInfo, error) {
	smInfo := &SmBiosInfo{}
	afs := &afero.Afero{Fs: fs}
	root := dmiRoot

	wErr := afs.Walk(root, func(path string, info os.FileInfo, fErr error) error {
		if fErr != nil {
			// The directory itself may not exist at all, on a platform with no
			// DMI tables or a scan that cannot reach sysfs. That is not an
			// error: it just means there is nothing to report.
			if path == root {
				return filepath.SkipDir
			}
			// A single entry we cannot even stat is skipped on its own. Walk
			// reads SkipDir from a file as "skip the rest of this directory",
			// which would drop every attribute alphabetically after it.
			log.Debug().Err(fErr).Str("path", path).Msg("skipping unreadable dmi entry")
			return nil
		}

		if info.IsDir() && path != root {
			return filepath.SkipDir
		}

		var dst *string
		switch info.Name() {
		case "bios_date":
			dst = &smInfo.BIOS.ReleaseDate
		case "bios_vendor":
			dst = &smInfo.BIOS.Vendor
		case "bios_version":
			dst = &smInfo.BIOS.Version
		case "board_asset_tag":
			dst = &smInfo.BaseBoardInfo.AssetTag
		case "board_name":
			dst = &smInfo.BaseBoardInfo.Model
		case "board_serial":
			dst = &smInfo.BaseBoardInfo.SerialNumber
		case "board_vendor":
			dst = &smInfo.BaseBoardInfo.Vendor
		case "board_version":
			dst = &smInfo.BaseBoardInfo.Version
		case "chassis_asset_tag":
			dst = &smInfo.ChassisInfo.AssetTag
		case "chassis_serial":
			dst = &smInfo.ChassisInfo.SerialNumber
		case "chassis_type":
			dst = &smInfo.ChassisInfo.Type
		case "chassis_vendor":
			dst = &smInfo.ChassisInfo.Vendor
		case "chassis_version":
			dst = &smInfo.ChassisInfo.Version
		case "product_family":
			dst = &smInfo.SysInfo.Family
		case "product_name":
			dst = &smInfo.SysInfo.Model
		case "product_serial":
			dst = &smInfo.SysInfo.SerialNumber
		case "product_sku":
			dst = &smInfo.SysInfo.SKU
		case "product_uuid":
			dst = &smInfo.SysInfo.UUID
		case "product_version":
			dst = &smInfo.SysInfo.Version
		case "sys_vendor":
			dst = &smInfo.SysInfo.Vendor
		}

		if dst != nil {
			// product_serial, board_serial, chassis_serial and product_uuid are
			// mode 0400 root-only on every Linux host, so a scan that is not
			// root cannot read them. Losing one of those must not cost us the
			// world-readable attributes next to it -- bios vendor and version,
			// the product name, the chassis type -- which is what firmware
			// audits actually ask for.
			if err := readDmiAttribute(fs, path, dst); err != nil {
				log.Debug().Err(err).Str("path", path).Msg("could not read dmi attribute")
			}
		}

		return nil
	})

	// If the error is SkipDir we can safely ignore it
	if wErr != nil && wErr != filepath.SkipDir {
		return nil, wErr
	}

	return smInfo, nil
}

// readDmiAttribute reads one sysfs DMI attribute into dst, leaving dst
// untouched when the file cannot be read.
func readDmiAttribute(fs afero.Fs, path string, dst *string) error {
	f, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	*dst = strings.TrimSpace(string(data))
	return nil
}

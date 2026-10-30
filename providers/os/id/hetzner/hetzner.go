// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hetzner

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/hetznercloud"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

const (
	hetznerIdentifierFileLinux = "/sys/class/dmi/id/sys_vendor"
)

func Detect(conn shared.Connection, pf *inventory.Platform) (string, string, []string) {
	sysVendor := ""
	if pf.IsFamily(inventory.FAMILY_LINUX) {
		content, err := afero.ReadFile(conn.FileSystem(), hetznerIdentifierFileLinux)
		if err != nil {
			log.Debug().Err(err).Msgf("unable to read %s", hetznerIdentifierFileLinux)
			return "", "", nil
		}
		sysVendor = strings.TrimSpace(string(content))
	} else {
		smbiosMgr, err := smbios.ResolveManager(conn, pf)
		if err != nil {
			log.Debug().Err(err).Msg("failed to resolve smbios manager")
			return "", "", nil
		}

		info, err := smbiosMgr.Info()
		if err != nil {
			log.Debug().Err(err).Msg("failed to query smbios")
			return "", "", nil
		}
		sysVendor = info.SysInfo.Vendor
	}

	if strings.Contains(sysVendor, "Hetzner") {
		mdsvc, err := hetznercloud.Resolve(conn, pf)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get hetzner metadata resolver")
			return "", "", nil
		}
		id, err := mdsvc.Identify()
		if err == nil {
			return id.InstanceID, id.Hostname, nil
		}
		log.Debug().Err(err).
			Strs("platform", pf.GetFamily()).
			Msg("failed to get Hetzner platform id")
	}

	return "", "", nil
}

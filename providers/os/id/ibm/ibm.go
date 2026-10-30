// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ibm

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/ibmcompute"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

var identifierFilesLinux = []string{
	"/sys/class/dmi/id/chassis_vendor",
	"/sys/class/dmi/id/uevent",
	"/sys/class/dmi/id/modalias",
}

func Detect(conn shared.Connection, pf *inventory.Platform) (string, string, []string) {
	sysVendor := ""
	if pf.IsFamily(inventory.FAMILY_LINUX) && pf.Name != "aix" {
		// Fetching the product version from the smbios manager is slow
		// because it iterates through files we don't need to check. This
		// is an optimization for our sshfs. Also, be aware that on linux,
		// you may not have access to all the smbios things under /sys, so
		// you want to make sure to only check some files for detection
		//
		// NOTE: The smbios implementation for AIX systems use the command
		// `prtconf` which is exactly what we need and performant.
		for _, identityFile := range identifierFilesLinux {
			content, err := afero.ReadFile(conn.FileSystem(), identityFile)
			if err == nil {
				sysVendor = string(content)
				break
			}
			log.Debug().Err(err).Msgf("unable to read %s", identityFile)
		}
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

	if strings.Contains(sysVendor, "IBM") {
		mdsvc, err := ibmcompute.Resolve(conn, pf)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get metadata resolver")
			return "", "", nil
		}
		id, err := mdsvc.Identify()
		if err == nil {
			return id.InstanceID, id.InstanceName, id.PlatformMrns
		}
		log.Debug().Err(err).
			Strs("platform", pf.GetFamily()).
			Msg("failed to get IBM platform id")
	}

	return "", "", nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vmware

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/vmware/vmtoolsd"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

var identifierFilesLinux = []string{
	"/sys/devices/virtual/dmi/id/product_name", // Expected: "VMware Virtual Platform"
	"/sys/class/dmi/id/sys_vendor",             // Expected: "VMware, Inc."
	// For windows, the smbios will return:                  "VMware, Inc."
}

func Detect(conn shared.Connection, pf *inventory.Platform) (string, string, []string) {
	sysVendor := ""
	if pf.IsFamily(inventory.FAMILY_LINUX) {
		// Fetching the product version from the smbios manager is slow
		// because it iterates through files we don't need to check. This
		// is an optimization for our sshfs. Also, be aware that on linux,
		// you may not have access to all the smbios things under /sys, so
		// you want to make sure to only check some files for detection
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
		// For windows we expect this to be: "VMware, Inc."
		sysVendor = info.SysInfo.Vendor
	}

	if strings.Contains(sysVendor, "VMware") {
		mdsvc, err := vmtoolsd.Resolve(conn, pf)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get metadata resolver")
			return "", "", nil
		}
		id, err := mdsvc.Identify()
		if err == nil {
			relatedIds := []string{}
			if id.VCenterMOID != "" {
				relatedIds = append(relatedIds, id.VCenterMOID)
			}
			if id.VSphereMOID != "" {
				relatedIds = append(relatedIds, id.VSphereMOID)
			}
			return id.UUID, "", relatedIds
		}
		log.Debug().Err(err).
			Strs("platform", pf.GetFamily()).
			Msg("failed to get VMware platform id")
	}

	return "", "", nil
}

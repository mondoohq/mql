// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aws

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/awsebs"
	"go.mondoo.com/mql/providers/os/id/awsec2"
	"go.mondoo.com/mql/providers/os/id/awsecs"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

func readValue(conn shared.Connection, fPath string) string {
	content, err := afero.ReadFile(conn.FileSystem(), fPath)
	if err != nil {
		log.Debug().Err(err).Msgf("unable to read %s", fPath)
		return ""
	}
	return string(content)
}

func Detect(conn shared.Connection, p *inventory.Platform) (string, string, []string) {
	var values []string
	if conn.Type() == shared.Type_FileSystem {
		// Special case for when we are running an EBS scan. The mounted volume doesn't have
		// information about `/sys` because it is a virtual pseudo-filesystem. For these type
		// of connections we detect if we are connected to an EBS volume in a different way.

		if p.IsFamily(inventory.FAMILY_LINUX) {
			values = []string{
				readValue(conn, "/etc/cloud/cloud.cfg"),
			}
		} else {
			values = []string{
				// @afiune how do we detect the mounted drive?
				readValue(conn, "\\ProgramData\\Amazon\\EC2Launch\\config\\agent-config.json"),
			}
		}
	} else if p.IsFamily(inventory.FAMILY_LINUX) {
		// Fetching the data from the smbios manager is slow for some transports
		// because it iterates through files we don't need to check. This
		// is an optimization for our sshfs. Also, be aware that on linux,
		// you may not have access to all the smbios things under /sys, so
		// you want to make sure to only check the files we actually look at

		values = []string{
			readValue(conn, "/sys/class/dmi/id/product_version"),
			readValue(conn, "/sys/class/dmi/id/bios_vendor"),
		}
	} else {
		smbiosMgr, err := smbios.ResolveManager(conn, p)
		if err != nil {
			log.Debug().Err(err).Msg("failed to resolve smbios manager")
			return "", "", nil
		}

		info, err := smbiosMgr.Info()
		if err != nil {
			log.Debug().Err(err).Msg("failed to query smbios")
			return "", "", nil
		}
		values = []string{
			info.SysInfo.Version,
			info.BIOS.Vendor,
		}
	}

	isAws := false
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), "amazon") {
			isAws = true
			break
		}
	}

	if isAws {
		mdsvc, err := awsec2.Resolve(conn, p)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get metadata resolver")
			return "", "", nil
		}
		id, err := mdsvc.Identify()
		if err == nil {
			return id.InstanceID, id.InstanceName, []string{id.AccountID}
		}
		log.Debug().Err(err).
			Strs("platform", p.GetFamily()).
			Str("method", "awsec2").
			Msg("failed to get AWS platform id")
		// try ecs
		mdsvcEcs, err := awsecs.Resolve(conn, p)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get metadata resolver")
			return "", "", nil
		}
		idEcs, err := mdsvcEcs.Identify()
		if err == nil {
			return idEcs.PlatformIds[0], idEcs.Name, []string{idEcs.AccountPlatformID}
		}
		log.Debug().Err(err).
			Strs("platform", p.GetFamily()).
			Str("method", "awsecs").
			Msg("failed to get AWS platform id")

		// try ebs TODO @afiune
		mdsvcEBS, err := awsebs.Resolve(conn, p)
		if err != nil {
			log.Debug().Err(err).Msg("failed to get metadata resolver")
			return "", "", nil
		}
		idEBS, err := mdsvcEBS.Identify()
		if err == nil {
			return idEBS.InstanceMachineID, idEBS.InstanceID, idEBS.PlatformIDs
		}
		log.Debug().Err(err).
			Strs("platform", p.GetFamily()).
			Str("method", "awsebs").
			Msg("failed to get AWS platform id")
	}

	return "", "", nil
}

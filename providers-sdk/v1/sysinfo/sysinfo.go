// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sysinfo

import (
	"errors"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/execruntime"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/id"
	"go.mondoo.com/mql/providers/os/id/hostname"
	"go.mondoo.com/mql/providers/os/resources/networkinterface"
)

type SystemInfo struct {
	Version    string              `json:"version,omitempty"`
	Build      string              `json:"build,omitempty"`
	Platform   *inventory.Platform `json:"platform,omitempty"`
	IP         string              `json:"ip,omitempty"`
	Hostname   string              `json:"platform_hostname,omitempty"`
	Labels     map[string]string   `json:"labels,omitempty"`
	PlatformId string              `json:"platform_id,omitempty"`
}

func Get() (*SystemInfo, error) {
	log.Debug().Msg("Gathering system information")

	sysInfo := &SystemInfo{
		Version: mql.GetVersion(),
		Build:   mql.GetBuild(),
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{{
			Type:     "local",
			Discover: &inventory.Discovery{Targets: []string{"none"}},
		}},
	}

	conn := local.NewConnection(0, &inventory.Config{
		Type: "local",
	}, &asset)

	fingerprint, platform, _ := id.IdentifyPlatform(conn, &plugin.ConnectReq{}, asset.Platform, asset.IdDetector)
	if fingerprint != nil {
		if len(fingerprint.PlatformIDs) > 0 {
			sysInfo.PlatformId = fingerprint.PlatformIDs[0]
		}
	}

	if platform == nil {
		return nil, errors.New("failed to detect the OS")
	}

	sysInfo.Platform = platform

	sysInfo.Hostname, _ = hostname.Hostname(conn, sysInfo.Platform)

	// determine ip address
	ipAddr, err := networkinterface.GetOutboundIP()
	if err == nil {
		sysInfo.IP = ipAddr.String()
	}

	// detect the execution runtime
	execEnv := execruntime.Detect()
	sysInfo.Labels = map[string]string{
		"environment": execEnv.Id,
	}

	return sysInfo, nil
}

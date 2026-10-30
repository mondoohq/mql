// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/vmware/vmtoolsd"
)

const VMWARE Provider = "VMware"

// vmware implements the OSCloud interface for VMware
type vmware struct {
	conn shared.Connection
}

func (v *vmware) Provider() Provider {
	return VMWARE
}

func (v *vmware) Instance() (*InstanceMetadata, error) {
	vmtoolsSvc, err := vmtoolsd.Resolve(v.conn, v.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.vmware> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := vmtoolsSvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.vmware> failed to get raw metadata")
		return nil, err
	}
	if metadata == nil {
		log.Debug().Msg("os.cloud.vmware> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := &InstanceMetadata{Metadata: metadata}

	m, ok := metadata.(map[string]any)
	if !ok {
		return instanceMd, errors.New("unexpected raw metadata")
	}

	// TODO look into more metadata

	if value, ok := m["hostname"]; ok {
		instanceMd.PrivateHostname = value.(string)
	}

	if value, ok := m["ipv4"]; ok {
		instanceMd.PrivateIpv4 = []Ipv4Address{{IP: value.(string)}}
	}

	return instanceMd, nil
}

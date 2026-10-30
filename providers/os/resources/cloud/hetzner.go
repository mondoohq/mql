// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/hetznercloud"
)

const HETZNER Provider = "Hetzner"

// hetznerCloud implements the OSCloud interface for Hetzner Cloud
type hetznerCloud struct {
	conn shared.Connection
}

// NewHetznerCloud creates a new Hetzner cloud instance.
func NewHetznerCloud(conn shared.Connection) (OSCloud, error) {
	return &hetznerCloud{conn: conn}, nil
}

func (h *hetznerCloud) Provider() Provider {
	return HETZNER
}

func (h *hetznerCloud) Instance() (*InstanceMetadata, error) {
	mdsvc, err := hetznercloud.Resolve(h.conn, h.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.hetzner> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.hetzner> failed to get raw metadata")
		return nil, err
	}
	if metadata == nil {
		log.Debug().Msg("os.cloud.hetzner> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := InstanceMetadata{Metadata: metadata}

	m, ok := metadata.(map[string]any)
	if !ok {
		return &instanceMd, errors.New("unexpected raw metadata")
	}

	if value, ok := m["hostname"]; ok {
		if hostname, ok := value.(string); ok {
			instanceMd.PrivateHostname = hostname
		}
	}

	if value, ok := m["local-ipv4"]; ok {
		if localIP, ok := value.(string); ok && localIP != "" {
			instanceMd.PrivateIpv4 = []Ipv4Address{{IP: localIP}}
		}
	}

	if value, ok := m["public-ipv4"]; ok {
		if publicIP, ok := value.(string); ok && publicIP != "" {
			instanceMd.PublicIpv4 = []Ipv4Address{{IP: publicIP}}
		}
	}

	return &instanceMd, nil
}

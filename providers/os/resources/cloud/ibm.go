// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/ibmcompute"
)

const IBM Provider = "IBM"

// ibm implements the OSCloud interface for IBM Cloud
type ibm struct {
	conn shared.Connection
}

func (i *ibm) Provider() Provider {
	return IBM
}

func (i *ibm) Instance() (*InstanceMetadata, error) {
	mdsvc, err := ibmcompute.Resolve(i.conn, i.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.ibm> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).Msg("os.cloud.ibm> failed to get raw metadata")
		return nil, err
	}
	if metadata == nil {
		log.Debug().Msg("os.cloud.ibm> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := &InstanceMetadata{Metadata: metadata}

	// TODO extract network information

	return instanceMd, nil
}

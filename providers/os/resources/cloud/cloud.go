// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/clouddetect"
)

type Provider string

// OSCloud is the interface that defines what information does the os `cloud`
// resource need. We implement this interface for every CSP we support and.
// The entry point of this interface is the `Resolve()` function.
type OSCloud interface {
	Provider() Provider
	Instance() (*InstanceMetadata, error)
}

// Resolve runs cloud detection on the provided connection to identify if
// we are running on the cloud, and if so, in which cloud are we running on.
func Resolve(conn shared.Connection) (OSCloud, error) {
	platformInfo := clouddetect.Detect(conn, conn.Asset().GetPlatform())
	if platformInfo == nil {
		log.Debug().Msg("os.cloud> unable to detect cloud")
		return &none{}, nil
	}

	log.Debug().Str("cloud", string(platformInfo.CloudProvider)).Msg("os.cloud> detected")

	switch platformInfo.CloudProvider {
	case clouddetect.AWS:
		return &aws{conn}, nil
	case clouddetect.GCP:
		return &gcp{conn}, nil
	case clouddetect.AZURE:
		return &azure{conn}, nil
	case clouddetect.VMWARE:
		return &vmware{conn}, nil
	case clouddetect.IBM:
		return &ibm{conn}, nil
	case clouddetect.HETZNER:
		return &hetznerCloud{conn}, nil
	default:
		return &none{}, nil
	}
}

const UNKNOWN Provider = "Unknown"

// none implements the OSCloud interface for cases where we can't detect
// the cloud provider we are running on.
type none struct{}

func (n *none) Provider() Provider {
	return UNKNOWN
}
func (n *none) Instance() (*InstanceMetadata, error) {
	return nil, errors.New("unknown provider information")
}

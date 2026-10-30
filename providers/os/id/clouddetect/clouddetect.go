// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package clouddetect

import (
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/aws"
	"go.mondoo.com/mql/providers/os/id/azure"
	"go.mondoo.com/mql/providers/os/id/gcp"
	"go.mondoo.com/mql/providers/os/id/hetzner"
	"go.mondoo.com/mql/providers/os/id/ibm"
	"go.mondoo.com/mql/providers/os/id/vmware"
)

type (
	RelatedPlatformID = string
	PlatformName      = string
	PlatformID        = string
)

type detectorFunc func(conn shared.Connection, p *inventory.Platform) (PlatformID, PlatformName, []RelatedPlatformID)

// CloudProviderType is the type of cloud provider that the cloud detect detected
type CloudProviderType string

var (
	UNKNOWN CloudProviderType = "UNKNOWN"
	AWS     CloudProviderType = "AWS"
	GCP     CloudProviderType = "GCP"
	AZURE   CloudProviderType = "AZURE"
	VMWARE  CloudProviderType = "VMWARE"
	IBM     CloudProviderType = "IBM"
	HETZNER CloudProviderType = "HETZNER"
)

var detectors = map[CloudProviderType]detectorFunc{
	AWS:     aws.Detect,
	GCP:     gcp.Detect,
	AZURE:   azure.Detect,
	VMWARE:  vmware.Detect,
	IBM:     ibm.Detect,
	HETZNER: hetzner.Detect,
}

// PlatformInfo contains platform information gathered from one of our cloud detectors.
type PlatformInfo struct {
	ID                 string
	Name               string
	Kind               string
	RelatedPlatformIDs []string
	CloudProvider      CloudProviderType
}

// Detect tried to detect if we are running on a cloud asset, and if so, it returns
// the platform information, otherwise it returns a `nil` pointer.
func Detect(conn shared.Connection, p *inventory.Platform) *PlatformInfo {
	wg := sync.WaitGroup{}
	wg.Add(len(detectors))

	valChan := make(chan PlatformInfo, len(detectors))
	for i := range detectors {
		go func(provider CloudProviderType, f detectorFunc) {
			defer wg.Done()

			id, name, related := f(conn, p)
			if id != "" {
				valChan <- PlatformInfo{
					ID:                 id,
					Name:               name,
					CloudProvider:      provider,
					RelatedPlatformIDs: related,
				}
			}
		}(i, detectors[i])
	}

	wg.Wait()
	close(valChan)

	platformIds := []string{}
	relatedPlatformIds := []string{}
	cloudProvider := UNKNOWN
	var name string
	for v := range valChan {
		platformIds = append(platformIds, v.ID)
		name = v.Name
		cloudProvider = v.CloudProvider
		relatedPlatformIds = append(relatedPlatformIds, v.RelatedPlatformIDs...)
	}

	if len(platformIds) == 0 {
		return nil
	} else if len(platformIds) > 1 {
		log.Error().Strs("detected", platformIds).Msg("multiple cloud platform ids detected")
		return nil
	}

	return &PlatformInfo{
		ID:                 platformIds[0],
		Name:               name,
		CloudProvider:      cloudProvider,
		Kind:               inventory.AssetKindCloudVM,
		RelatedPlatformIDs: relatedPlatformIds,
	}
}

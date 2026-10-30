// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"errors"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/detector/containerenv"
	"go.mondoo.com/mql/providers/os/id"
	"go.mondoo.com/mql/providers/os/id/clouddetect"
	"go.mondoo.com/mql/providers/os/id/hostname"
	"go.mondoo.com/mql/providers/os/id/ids"
	"go.mondoo.com/mql/providers/os/id/machineid"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// default id detectors
var IdDetectors = []string{
	ids.IdDetector_Hostname,
	ids.IdDetector_CloudDetect,
}

func hasDetector(detectors map[string]struct{}, any ...string) bool {
	for i := range any {
		if _, ok := detectors[any[i]]; ok {
			return true
		}
	}
	return false
}

func mapDetectors(raw []string) map[string]struct{} {
	raw = ids.ExpandDefault(raw, IdDetectors)
	res := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		res[v] = struct{}{}
	}
	return res
}

func (s *Service) detect(asset *inventory.Asset, conn shared.Connection) error {
	pf, ok := detector.DetectOS(conn)
	if !ok {
		return errors.New("failed to detect OS")
	}
	asset.MergePlatform(pf)

	// A local scan started inside a container, or an SSH session into one,
	// reaches a container even though the connection doesn't say so. connect
	// has already defaulted an unset kind to baremetal by now.
	inContainer := (asset.Platform.Kind == "" || asset.Platform.Kind == inventory.AssetKindBaremetal) &&
		asset.Platform.IsFamily("linux") && containerenv.InContainer(conn)
	if inContainer {
		asset.Platform.Kind = "container"
	}
	if asset.Platform.Kind == "" {
		asset.Platform.Kind = inventory.AssetKindBaremetal
	}
	if asset.Connections[0].Runtime == "vagrant" {
		// detect overrides this
		asset.Platform.Kind = inventory.AssetKindCloudVM
	}

	// Container connections bring their own platform id. A container found
	// by looking from the inside has none, so it keeps the id detectors.
	var detectors map[string]struct{}
	if inContainer || !slices.Contains([]string{"container-image", "container"}, asset.Platform.Kind) {
		detectors = mapDetectors(asset.IdDetector)
	}

	if hasDetector(detectors, ids.IdDetector_Hostname) {
		log.Debug().Msg("run hostname id detector")
		if id, ok := hostname.Hostname(conn, asset.Platform); ok {
			asset.PlatformIds = append(asset.PlatformIds, id)
		}
	}

	if hasDetector(detectors, ids.IdDetector_CloudDetect) {
		log.Debug().Msg("run cloud platform detector")
		cloudPlatformInfo := clouddetect.Detect(conn, asset.Platform)
		if cloudPlatformInfo != nil {
			log.Debug().Interface("info", cloudPlatformInfo).Msg("cloud platform detected")
			asset.PlatformIds = append(asset.PlatformIds, cloudPlatformInfo.ID)
			if cloudPlatformInfo.Name != "" {
				// if we weren't able to detect a name for this asset, don't update to an empty value
				asset.Name = cloudPlatformInfo.Name
			}
			// This also wins over a container found from the inside: with
			// the VM's metadata service reachable, the asset already carries
			// the VM's platform id and name, and calling it a container
			// would relabel the VM's asset.
			asset.Platform.Kind = cloudPlatformInfo.Kind
			// RelatedAssets is kept for backward compatibility until
			// consumers migrate to relationships (ADR 030).
			//nolint:staticcheck
			asset.RelatedAssets = append(asset.RelatedAssets, relatedIds2assets(cloudPlatformInfo.RelatedPlatformIDs)...)
		}
	}

	if hasDetector(detectors, ids.IdDetector_MachineID) {
		log.Debug().Msg("run machineID id detector")
		id, hostErr := machineid.MachineId(conn, asset.Platform)
		if hostErr != nil {
			log.Warn().Err(hostErr).Msg("failure in machineID detector")
		} else if id != "" {
			asset.PlatformIds = append(asset.PlatformIds, id)
		}
	}

	// First sort the platform IDs and then call Compact, because Compact removes only consecutive duplicates
	slices.Sort(asset.PlatformIds)
	asset.PlatformIds = slices.Compact(asset.PlatformIds)

	// If the asset connection had the DelayDiscovery flag and the current asset doesn't, we just performed
	// discovery for the asset and we need to update it.
	if conn.Asset().Connections[0].DelayDiscovery && !asset.Connections[0].DelayDiscovery {
		conn.UpdateAsset(asset)
	}
	return nil
}

func relatedIds2assets(ids []string) []*inventory.Asset {
	res := make([]*inventory.Asset, len(ids))
	for i := range ids {
		res[i] = &inventory.Asset{Id: ids[i]}
	}
	return res
}

// RelatedAssets is kept for backward compatibility until consumers migrate to
// relationships (ADR 030).
//
//nolint:staticcheck
func appendRelatedAssetsFromFingerprint(f *id.PlatformFingerprint, a *inventory.Asset) {
	if f == nil || len(f.RelatedAssets) == 0 {
		return
	}
	included := make(map[string]struct{}, len(a.RelatedAssets))
	for i := range a.RelatedAssets {
		included[a.RelatedAssets[i].Id] = struct{}{}
	}
	for _, ra := range f.RelatedAssets {
		shouldAdd := true
		for _, pId := range ra.PlatformIDs {
			if _, ok := included[pId]; ok {
				shouldAdd = false
				break
			}
		}
		if shouldAdd {
			a.RelatedAssets = append(a.RelatedAssets, &inventory.Asset{Id: ra.PlatformIDs[0]})
		}
	}
}

func (s *Service) assetName(asset *inventory.Asset, conn shared.Connection) {
	// for macOS we want to use the computer name, therefore we detect the computer name
	if asset != nil && asset.Platform != nil && asset.Platform.Name == "macos" {
		// run command to get computer name and use it as asset name
		f, err := conn.FileSystem().Open("/Library/Preferences/SystemConfiguration/preferences.plist")
		if err == nil {
			data, err := plist.Decode(f)
			if err == nil {
				if computerName, ok := data.GetString("System", "System", "ComputerName"); ok {
					asset.Name = RemoveNonASCII(computerName)
				}
			}
		}
	}
}

// RemoveNonASCII removes all non-ASCII characters
// macOS may use non ASCII characters for the computer name. This breaks the progress bar until v12.13.0
func RemoveNonASCII(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c <= 127 {
			result.WriteRune(c)
		}
	}
	return result.String()
}

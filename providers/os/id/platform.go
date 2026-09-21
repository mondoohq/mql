// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/awsec2"
	"go.mondoo.com/mql/providers/os/id/awsecs"
	"go.mondoo.com/mql/providers/os/id/biosuuid"
	"go.mondoo.com/mql/providers/os/id/clouddetect"
	"go.mondoo.com/mql/providers/os/id/hostname"
	"go.mondoo.com/mql/providers/os/id/hypervisor"
	"go.mondoo.com/mql/providers/os/id/ids"
	"go.mondoo.com/mql/providers/os/id/machineid"
	"go.mondoo.com/mql/providers/os/id/serialnumber"
	"go.mondoo.com/mql/providers/os/id/windowsadsid"
)

type PlatformFingerprint struct {
	PlatformIDs       []string
	Name              string
	Runtime           string
	Kind              string
	RelatedAssets     []PlatformFingerprint
	ActiveIdDetectors []string
}

type platformInfo struct {
	IDs                []string
	Name               string
	Kind               string
	RelatedPlatformIDs []string
}

func IdentifyPlatform(conn shared.Connection, req *plugin.ConnectReq, p *inventory.Platform, idDetectors []string) (*PlatformFingerprint, *inventory.Platform, error) {
	var ok bool
	if p == nil {
		p, ok = detector.DetectOS(conn)
		if !ok {
			return nil, nil, errors.New("cannot detect os")
		}
	}

	var fingerprint PlatformFingerprint
	var platformIds []string
	var relatedIds []string

	// Detect hypervisor for two purposes: auto-adding the BIOS UUID detector
	// when no idDetectors are provided, and setting p.Kind at the bottom.
	var detectedHypervisor string
	var isVM bool
	if len(idDetectors) == 0 || p.Kind == "" {
		detectedHypervisor, isVM = hypervisor.Hypervisor(conn, p)
		if isVM {
			log.Debug().Str("hypervisor", detectedHypervisor).Msg("detected hypervisor for ID detection")
		}
	}

	if len(idDetectors) == 0 {
		// fallback to default id detectors
		//
		// we want to make sure that we mark assets running in the cloud to `virtualmachine`,
		// therefore we use the cloud detect detector as our first option.

		switch conn.Type() {
		case shared.Type_Local:
			idDetectors = []string{ids.IdDetector_CloudDetect, ids.IdDetector_Hostname}
			if mql.Features(req.Features).IsActive(mql.SerialNumberAsID) {
				idDetectors = append(idDetectors, ids.IdDetector_SerialNumber)
			}
			// Automatically use BIOS UUID for VMs since serial numbers may not be unique
			// (e.g., OpenStack passes through the host's serial number to VMs)
			if mql.Features(req.Features).IsActive(mql.BiosUUIDAsID) || isVM {
				idDetectors = append(idDetectors, ids.IdDetector_BiosUUID)
			}
		case shared.Type_SSH:
			idDetectors = []string{ids.IdDetector_CloudDetect, ids.IdDetector_Hostname}
			// Use BIOS UUID for SSH connections when explicitly enabled or when VM is detected
			if mql.Features(req.Features).IsActive(mql.BiosUUIDAsID) || isVM {
				idDetectors = append(idDetectors, ids.IdDetector_BiosUUID)
			}
		case shared.Type_Tar, shared.Type_FileSystem, shared.Type_DockerSnapshot:
			idDetectors = []string{ids.IdDetector_Hostname}
		}
	}
	fingerprint.ActiveIdDetectors = idDetectors

	for i := range idDetectors {
		idDetector := idDetectors[i]
		platformInfo, err := gatherPlatformInfo(conn, p, idDetector)
		if err != nil {
			// we only err if we found zero platform ids, if we try multiple, a fail of an individual one is okay
			log.Debug().Err(err).Str("detector", string(idDetector)).Msg("could not determine platform info")
			continue
		}
		if len(platformInfo.IDs) > 0 {
			platformIds = append(platformIds, platformInfo.IDs...)
		}
		if len(platformInfo.RelatedPlatformIDs) > 0 {
			relatedIds = append(relatedIds, platformInfo.RelatedPlatformIDs...)
		}

		if len(platformInfo.Name) > 0 {
			fingerprint.Name = platformInfo.Name
		} else {
			// check if we get a name for the asset, eg. aws instance id
			for _, id := range platformInfo.IDs {
				name := GatherNameForPlatformId(id)
				if name != "" {
					fingerprint.Name = name
				}
			}
		}

		if len(platformInfo.Kind) > 0 {
			p.Kind = platformInfo.Kind
		}

		// check whether we can extract runtime and kind information
		for _, id := range platformInfo.IDs {
			runtime, kind := ExtractPlatformAndKindFromPlatformId(id)
			if runtime != "" {
				fingerprint.Runtime = runtime
				fingerprint.Kind = kind
			}
		}
	}

	// A mounted filesystem is the one target that can legitimately carry no
	// machine identity. An extracted container root filesystem is the common
	// case: the runtime writes /etc/hostname when the container starts, so the
	// copy in the image layers is empty, and the DMI and cloud-init sources the
	// other detectors read are absent from an image altogether. Fall back to
	// whatever identity the tree does hold, and finally to the mount path, so
	// the asset stays scannable instead of being discarded for having no id.
	if len(platformIds) == 0 && conn.Type() == shared.Type_FileSystem {
		for _, fallback := range []string{ids.IdDetector_MachineID, ids.IdDetector_MountPath} {
			info, err := gatherPlatformInfo(conn, p, fallback)
			if err != nil || len(info.IDs) == 0 {
				log.Debug().Err(err).Str("detector", fallback).Msg("no platform id from fallback detector")
				continue
			}

			log.Debug().Str("detector", fallback).Strs("platform-ids", info.IDs).
				Msg("filesystem carries no hostname, falling back for the platform id")
			platformIds = append(platformIds, info.IDs...)
			if fingerprint.Name == "" {
				fingerprint.Name = info.Name
			}
			idDetectors = append(idDetectors, fallback)
			fingerprint.ActiveIdDetectors = idDetectors
			break
		}
	}

	// if we found zero platform ids something went wrong
	if len(platformIds) == 0 {
		return nil, p, errors.New("could not determine a platform identifier")
	}

	fingerprint.PlatformIDs = platformIds
	for _, v := range relatedIds {
		fingerprint.RelatedAssets = append(fingerprint.RelatedAssets, PlatformFingerprint{
			PlatformIDs: []string{v},
			Name:        GatherNameForPlatformId(v),
		})
	}

	// If at this point we couldn't detect the platform kind, use the hypervisor
	// detection result to mark the asset as a virtual machine
	if p.Kind == "" && isVM {
		log.Debug().Str("hypervisor", detectedHypervisor).Msg("setting platform kind based on detected hypervisor")
		p.Kind = inventory.AssetKindCloudVM
	}

	log.Debug().Interface("id-detector", idDetectors).Strs("platform-ids", platformIds).Msg("detected platform ids")
	return &fingerprint, p, nil
}

func GatherNameForPlatformId(id string) string {
	if awsec2.IsValidMondooInstanceId(id) {
		structId, _ := awsec2.ParseMondooInstanceID(id)
		return structId.Id
	} else if accountID, err := awsec2.ParseMondooAccountID(id); err == nil {
		return fmt.Sprintf("AWS Account %s", accountID)
	}
	return ""
}

func ExtractPlatformAndKindFromPlatformId(id string) (string, string) {
	if awsec2.ParseEc2PlatformID(id) != nil {
		return "aws-ec2", inventory.AssetKindCloudVM
	} else if awsec2.IsValidMondooAccountId(id) {
		return "aws", "api"
	} else if awsecs.IsValidMondooECSContainerId(id) {
		return "aws-ecs", "container"
	}
	return "", ""
}

func gatherPlatformInfo(conn shared.Connection, pf *inventory.Platform, idDetector string) (*platformInfo, error) {
	var identifier string
	switch idDetector {
	case ids.IdDetector_Hostname:
		// NOTE: we need to be careful with hostname's since they are not required to be unique
		hostname, ok := hostname.Hostname(conn, pf)
		if ok && len(hostname) > 0 {
			identifier = "//platformid.api.mondoo.app/hostname/" + hostname
			return &platformInfo{
				IDs:                []string{identifier},
				Name:               hostname,
				RelatedPlatformIDs: []string{},
			}, nil
		}
		return &platformInfo{}, nil
	case ids.IdDetector_MachineID:
		guid, hostErr := machineid.MachineId(conn, pf)
		if hostErr == nil && len(guid) > 0 {
			identifier = "//platformid.api.mondoo.app/machineid/" + guid
			return &platformInfo{
				IDs:                []string{identifier},
				Name:               "",
				RelatedPlatformIDs: []string{},
			}, hostErr
		}
		return &platformInfo{}, nil
	case ids.IdDetector_SerialNumber:
		serial, err := serialnumber.SerialNumber(conn, pf)
		if err == nil && len(serial) > 0 {
			identifier = "//platformid.api.mondoo.app/serialnumber/" + serial
			return &platformInfo{
				IDs:                []string{identifier},
				Name:               "",
				RelatedPlatformIDs: []string{},
			}, nil
		}
		return &platformInfo{}, nil
	case ids.IdDetector_BiosUUID:
		uuid, err := biosuuid.BiosUUID(conn, pf)
		if err == nil && len(uuid) > 0 {
			identifier = "//platformid.api.mondoo.app/bios-uuid/" + uuid
			return &platformInfo{
				IDs:                []string{identifier},
				Name:               "",
				RelatedPlatformIDs: []string{},
			}, nil
		}
		return &platformInfo{}, nil
	case ids.IdDetector_WindowsADSID:
		sid, err := windowsadsid.WindowsADSID(conn, pf)
		if err != nil {
			return nil, err
		}
		if len(sid) > 0 {
			identifier = "//platformid.api.mondoo.app/windows-ad-sid/" + sid
			return &platformInfo{
				IDs:                []string{identifier},
				Name:               "",
				RelatedPlatformIDs: []string{},
			}, nil
		}
		return &platformInfo{}, nil
	case ids.IdDetector_AwsEcs:
		metadata, err := awsecs.Resolve(conn, pf)
		if err != nil {
			return nil, err
		}
		ident, err := metadata.Identify()
		if err != nil {
			return nil, err
		}
		if len(ident.PlatformIds) != 0 {
			return &platformInfo{
				IDs:                ident.PlatformIds,
				Name:               ident.Name,
				RelatedPlatformIDs: []string{ident.AccountPlatformID},
			}, nil
		}
		return &platformInfo{}, nil
	case ids.IdDetector_MountPath:
		mounted, ok := conn.(shared.ConnectionWithMountPath)
		if !ok {
			return &platformInfo{}, nil
		}

		// The path is resolved to an absolute one so that the same tree reached
		// by two spellings stays one asset. Two directories still collide only
		// if they are the same directory.
		path, err := filepath.Abs(mounted.MountPath())
		if err != nil {
			return nil, err
		}

		sum := sha256.Sum256([]byte(path))
		return &platformInfo{
			IDs:                []string{"//platformid.api.mondoo.app/runtime/filesystem/hash/" + hex.EncodeToString(sum[:])},
			Name:               path,
			RelatedPlatformIDs: []string{},
		}, nil
	case ids.IdDetector_CloudDetect:
		cloudPlatformInfo := clouddetect.Detect(conn, pf)
		if cloudPlatformInfo != nil {
			return &platformInfo{
				IDs:                []string{cloudPlatformInfo.ID},
				Name:               cloudPlatformInfo.Name,
				RelatedPlatformIDs: cloudPlatformInfo.RelatedPlatformIDs,
				Kind:               cloudPlatformInfo.Kind,
			}, nil
		}
		return &platformInfo{}, nil
	default:
		return nil, fmt.Errorf("the provided id-detector is not supported: %s", idDetector)
	}
}

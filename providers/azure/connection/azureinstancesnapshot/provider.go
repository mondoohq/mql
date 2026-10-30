// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/azauth"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azure/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/device"
	"go.mondoo.com/mql/providers/os/connection/local"
)

const (
	SnapshotConnectionType shared.ConnectionType = "azure-snapshot"
	DiskTargetType         string                = "disk"
	SnapshotTargetType     string                = "snapshot"
	InstanceTargetType     string                = "instance"
	SkipCleanup            string                = "skip-snapshot-cleanup"
	SkipSetup              string                = "skip-snapshot-setup"
	Lun                    string                = "lun"
)

type AzureSnapshotConnection struct {
	// the device connection, used to mount the disk once we attach it to the VM
	*device.DeviceConnection
	// the snapshot creator, used to create snapshots and disks via the Azure API
	snapshotCreator *snapshotCreator
	// the VM we are connected to
	instanceInfo instanceInfo
	// only set if the connection mounts the disk. used for detaching the disk via the Azure API
	mountedDiskInfo mountedDiskInfo
	identifier      string
}

type assetInfo struct {
	assetName  string
	platformId string
}

type scanTarget struct {
	TargetType     string
	Target         string
	ResourceGroup  string
	SubscriptionId string
}

type mountedDiskInfo struct {
	diskId   string
	diskName string
}

func ParseTarget(conf *inventory.Config, scanner azureScannerInstance) (scanTarget, error) {
	target := conf.Options["target"]
	if target == "" {
		return scanTarget{}, errors.New("target is required")
	}
	id, err := arm.ParseResourceID(target)
	if err != nil {
		log.Debug().Str("id", target).Msg("could not parse target as an ARM resource id, going to use the scanner's resource group and subscription id")
		return scanTarget{
			TargetType:     conf.Options["type"],
			Target:         target,
			ResourceGroup:  scanner.resourceGroup,
			SubscriptionId: scanner.subscriptionId,
		}, nil
	}
	return scanTarget{
		TargetType:     conf.Options["type"],
		Target:         id.Name,
		ResourceGroup:  id.ResourceGroupName,
		SubscriptionId: id.SubscriptionID,
	}, nil
}

func NewAzureSnapshotConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*AzureSnapshotConnection, error) {
	var cred *vault.Credential
	if len(conf.Credentials) > 0 {
		cred = conf.Credentials[0]
	}
	methods, err := azauth.ParseCredentialMethods(conf.Options["auth-method"])
	if err != nil {
		return nil, err
	}
	// an empty token file leaves azidentity to fall back to
	// AZURE_FEDERATED_TOKEN_FILE, so only the option needs forwarding here
	token, err := azauth.GetTokenFromCredential(cred, &azauth.ChainedTokenOptions{
		TenantID:           conf.Options["tenant-id"],
		ClientID:           conf.Options["client-id"],
		FederatedTokenFile: conf.Options["azure-federated-token-file"],
		Methods:            methods,
		Source:             "azure-snapshot-connection",
	})
	if err != nil {
		return nil, err
	}

	localConn := local.NewConnection(id, conf, asset)

	// 1. check if we run on an azure instance
	scanner, err := determineScannerInstanceInfo(localConn)
	if err != nil {
		return nil, err
	}

	// 2. determine the target
	target, err := ParseTarget(conf, scanner)
	if err != nil {
		return nil, err
	}

	sc, err := NewSnapshotCreator(token, scanner.subscriptionId)
	if err != nil {
		return nil, err
	}

	instanceInfo, err := GetInstanceInfo(scanner.resourceGroup, scanner.name, scanner.subscriptionId, token)
	if err != nil {
		return nil, err
	}

	c := &AzureSnapshotConnection{
		snapshotCreator: sc,
		identifier:      conf.PlatformId,
		instanceInfo:    instanceInfo,
	}

	lun, err := c.instanceInfo.getFirstAvailableLun()
	if err != nil {
		c.Close()
		return nil, err
	}

	diskInfo, ai, err := c.setupDiskAndMount(target, lun)
	if err != nil {
		c.Close()
		return nil, err
	}
	asset.Name = ai.assetName
	conf.PlatformId = ai.platformId
	c.mountedDiskInfo = diskInfo

	// note: this is important for the device manager to know which LUN to use
	conf.Options[Lun] = fmt.Sprintf("%d", lun)
	conf.Options[device.PlatformIdInject] = ai.platformId
	// create and initialize device conn provider
	deviceConn, err := device.NewDeviceConnection(id, &inventory.Config{
		PlatformId: conf.PlatformId,
		Options:    conf.Options,
		Type:       conf.Type,
		Record:     conf.Record,
	}, asset)
	if err != nil {
		c.Close()
		return nil, err
	}

	c.DeviceConnection = deviceConn
	asset.Platform.Kind = c.Kind()
	asset.Platform.Runtime = c.Runtime()
	return c, nil
}

var _ plugin.Closer = (*AzureSnapshotConnection)(nil)

func (c *AzureSnapshotConnection) Close() {
	log.Debug().Msg("closing azure snapshot connection")
	if c == nil {
		return
	}

	// we first close the device connection, which will unmount the disk
	if c.DeviceConnection != nil {
		c.DeviceConnection.Close()
	}
	if c.snapshotCreator != nil {
		if c.mountedDiskInfo.diskName != "" {
			err := c.snapshotCreator.detachDisk(c.mountedDiskInfo.diskName, c.instanceInfo)
			if err != nil {
				log.Error().Err(err).Msg("unable to detach volume")
			}
		}

		if c.mountedDiskInfo.diskName != "" {
			err := c.snapshotCreator.deleteCreatedDisk(c.instanceInfo.resourceGroup, c.mountedDiskInfo.diskName)
			if err != nil {
				log.Error().Err(err).Msg("could not delete created disk")
			}
		}
	}
}

func (c *AzureSnapshotConnection) Kind() string {
	return "api"
}

func (c *AzureSnapshotConnection) Runtime() string {
	return "azure-vm"
}

func (c *AzureSnapshotConnection) Identifier() (string, error) {
	return c.identifier, nil
}

func (c *AzureSnapshotConnection) Type() shared.ConnectionType {
	return SnapshotConnectionType
}

func (c *AzureSnapshotConnection) Config() *inventory.Config {
	return c.DeviceConnection.Conf()
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// Graph application permissions for the escrow listings. Both are the
// metadata-only ("ReadBasic") variants. The secret-bearing permissions,
// DeviceLocalCredential.Read.All for LAPS passwords and BitlockerKey.Read.All
// for recovery keys, are deliberately never needed.
const (
	permLapsReadBasic      = "DeviceLocalCredential.ReadBasic.All"
	permBitlockerReadBasic = "BitlockerKey.ReadBasic.All"
)

// keyEscrowCache holds the tenant-wide escrow listings, each fetched once and
// shared by the root lists and every per-device accessor, so scanning N
// devices costs one listing call per kind rather than one call per device.
type keyEscrowCache struct {
	lapsOnce     sync.Once
	laps         []any
	lapsByDevice map[string]*mqlMicrosoftDeviceLocalCredential
	lapsErr      error

	bitlockerOnce     sync.Once
	bitlocker         []any
	bitlockerByDevice map[string][]any
	bitlockerErr      error

	devicesOnce       sync.Once
	devicesByDeviceId map[string]*mqlMicrosoftDevice
	devicesErr        error
}

func escrowMicrosoftRoot(runtime *plugin.Runtime) (*mqlMicrosoft, error) {
	res, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoft), nil
}

// loadDeviceLocalCredentials lists every Windows LAPS backup in the tenant.
//
// SECURITY: metadata only. The request never sets $select=credentials, which
// is the only way Graph returns the backed-up passwords (and which needs the
// separate DeviceLocalCredential.Read.All permission). Without it the list
// returns id, deviceName, lastBackupDateTime and refreshDateTime only.
//
// Permissions: DeviceLocalCredential.ReadBasic.All
// see https://learn.microsoft.com/en-us/graph/api/directory-list-devicelocalcredentials?view=graph-rest-1.0
func (a *mqlMicrosoft) loadDeviceLocalCredentials() ([]any, map[string]*mqlMicrosoftDeviceLocalCredential, error) {
	c := &a.keyEscrow
	c.lapsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			c.lapsErr = err
			return
		}
		infos, err := fetchDeviceLocalCredentials(context.Background(), graphClient)
		if err != nil {
			c.lapsErr = err
			return
		}

		list := []any{}
		byDevice := map[string]*mqlMicrosoftDeviceLocalCredential{}
		for _, info := range infos {
			if info == nil || info.GetId() == nil {
				continue
			}
			r, err := CreateResource(a.MqlRuntime, "microsoft.deviceLocalCredential", deviceLocalCredentialArgs(info))
			if err != nil {
				c.lapsErr = err
				return
			}
			cred := r.(*mqlMicrosoftDeviceLocalCredential)
			list = append(list, cred)
			byDevice[cred.Id.Data] = cred
		}
		c.laps = list
		c.lapsByDevice = byDevice
	})
	return c.laps, c.lapsByDevice, c.lapsErr
}

// fetchDeviceLocalCredentials pages through /directory/deviceLocalCredentials.
//
// SECURITY: no request configuration on purpose. The default response carries
// no credentials; Graph returns passwords only for $select=credentials. Never
// add a $select here.
func fetchDeviceLocalCredentials(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient) ([]models.DeviceLocalCredentialInfoable, error) {
	resp, err := graphClient.Directory().DeviceLocalCredentials().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permLapsReadBasic)
	}
	infos, err := iterate[models.DeviceLocalCredentialInfoable](ctx, resp, graphClient.GetAdapter(),
		models.CreateDeviceLocalCredentialInfoCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permLapsReadBasic)
	}
	return infos, nil
}

// fetchBitlockerRecoveryKeys pages through
// /informationProtection/bitlocker/recoveryKeys.
//
// SECURITY: the collection response carries no key property. Never request a
// single key with recoveryKeys/{id}?$select=key.
func fetchBitlockerRecoveryKeys(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient) ([]models.BitlockerRecoveryKeyable, error) {
	resp, err := graphClient.InformationProtection().Bitlocker().RecoveryKeys().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permBitlockerReadBasic)
	}
	keys, err := iterate[models.BitlockerRecoveryKeyable](ctx, resp, graphClient.GetAdapter(),
		models.CreateBitlockerRecoveryKeyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permBitlockerReadBasic)
	}
	return keys, nil
}

// deviceLocalCredentialArgs maps a LAPS backup record to resource arguments.
// It reads metadata getters only; GetCredentials is never consulted.
func deviceLocalCredentialArgs(info models.DeviceLocalCredentialInfoable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData("microsoft.deviceLocalCredential/" + *info.GetId()),
		"id":                 llx.StringDataPtr(info.GetId()),
		"deviceName":         llx.StringDataPtr(info.GetDeviceName()),
		"lastBackupDateTime": graphTimeData(info.GetLastBackupDateTime()),
		"refreshDateTime":    graphTimeData(info.GetRefreshDateTime()),
	}
}

// loadBitlockerRecoveryKeys lists every BitLocker recovery key escrowed in the
// tenant.
//
// SECURITY: metadata only. The list endpoint never returns the key material;
// Graph returns it only from recoveryKeys/{id}?$select=key, which is never
// called here (and which needs the separate BitlockerKey.Read.All permission).
//
// Permissions: BitlockerKey.ReadBasic.All
// see https://learn.microsoft.com/en-us/graph/api/bitlocker-list-recoverykeys?view=graph-rest-1.0
func (a *mqlMicrosoft) loadBitlockerRecoveryKeys() ([]any, map[string][]any, error) {
	c := &a.keyEscrow
	c.bitlockerOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			c.bitlockerErr = err
			return
		}
		keys, err := fetchBitlockerRecoveryKeys(context.Background(), graphClient)
		if err != nil {
			c.bitlockerErr = err
			return
		}

		list := []any{}
		byDevice := map[string][]any{}
		for _, key := range keys {
			if key == nil || key.GetId() == nil {
				continue
			}
			r, err := CreateResource(a.MqlRuntime, "microsoft.bitlockerRecoveryKey", bitlockerRecoveryKeyArgs(key))
			if err != nil {
				c.bitlockerErr = err
				return
			}
			k := r.(*mqlMicrosoftBitlockerRecoveryKey)
			list = append(list, k)
			if k.DeviceId.Data != "" {
				byDevice[k.DeviceId.Data] = append(byDevice[k.DeviceId.Data], k)
			}
		}
		c.bitlocker = list
		c.bitlockerByDevice = byDevice
	})
	return c.bitlocker, c.bitlockerByDevice, c.bitlockerErr
}

// bitlockerRecoveryKeyArgs maps a recovery key record to resource arguments.
// It reads metadata getters only; GetKey is never consulted.
func bitlockerRecoveryKeyArgs(key models.BitlockerRecoveryKeyable) map[string]*llx.RawData {
	var volumeType *string
	if vt := key.GetVolumeType(); vt != nil {
		s := vt.String()
		volumeType = &s
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData("microsoft.bitlockerRecoveryKey/" + *key.GetId()),
		"id":              llx.StringDataPtr(key.GetId()),
		"createdDateTime": graphTimeData(key.GetCreatedDateTime()),
		"deviceId":        llx.StringDataPtr(key.GetDeviceId()),
		"volumeType":      llx.StringDataPtr(volumeType),
	}
}

// devicesByDeviceId indexes the tenant's device list by its Entra deviceId,
// the key LAPS and BitLocker records carry. It reuses the same
// microsoft.devices list a query would load, so it costs no extra calls when
// that list is already resolved.
func (a *mqlMicrosoft) devicesByDeviceId() (map[string]*mqlMicrosoftDevice, error) {
	c := &a.keyEscrow
	c.devicesOnce.Do(func() {
		r, err := NewResource(a.MqlRuntime, "microsoft.devices", map[string]*llx.RawData{})
		if err != nil {
			c.devicesErr = err
			return
		}
		list := r.(*mqlMicrosoftDevices).GetList()
		if list.Error != nil {
			c.devicesErr = list.Error
			return
		}
		idx := make(map[string]*mqlMicrosoftDevice, len(list.Data))
		for _, d := range list.Data {
			dev, ok := d.(*mqlMicrosoftDevice)
			if !ok || dev.DeviceId.Data == "" {
				continue
			}
			idx[dev.DeviceId.Data] = dev
		}
		c.devicesByDeviceId = idx
	})
	return c.devicesByDeviceId, c.devicesErr
}

func (a *mqlMicrosoft) deviceLocalCredentials() ([]any, error) {
	list, _, err := a.loadDeviceLocalCredentials()
	return list, err
}

func (a *mqlMicrosoft) bitlockerRecoveryKeys() ([]any, error) {
	list, _, err := a.loadBitlockerRecoveryKeys()
	return list, err
}

// escrowDevice resolves an Entra deviceId to the tenant's microsoft.device,
// setting field to null when no device carries that id.
func escrowDevice(runtime *plugin.Runtime, deviceId string, field *plugin.TValue[*mqlMicrosoftDevice]) (*mqlMicrosoftDevice, error) {
	if deviceId == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := escrowMicrosoftRoot(runtime)
	if err != nil {
		return nil, err
	}
	idx, err := root.devicesByDeviceId()
	if err != nil {
		return nil, err
	}
	dev, ok := idx[deviceId]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return dev, nil
}

func (a *mqlMicrosoftDeviceLocalCredential) device() (*mqlMicrosoftDevice, error) {
	return escrowDevice(a.MqlRuntime, a.Id.Data, &a.Device)
}

func (a *mqlMicrosoftBitlockerRecoveryKey) device() (*mqlMicrosoftDevice, error) {
	return escrowDevice(a.MqlRuntime, a.DeviceId.Data, &a.Device)
}

func (a *mqlMicrosoftDevice) localAdminPasswordBackup() (*mqlMicrosoftDeviceLocalCredential, error) {
	if a.DeviceId.Data == "" {
		a.LocalAdminPasswordBackup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := escrowMicrosoftRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	_, byDevice, err := root.loadDeviceLocalCredentials()
	if err != nil {
		return nil, err
	}
	cred, ok := byDevice[a.DeviceId.Data]
	if !ok {
		a.LocalAdminPasswordBackup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cred, nil
}

func (a *mqlMicrosoftDevice) bitlockerRecoveryKeys() ([]any, error) {
	if a.DeviceId.Data == "" {
		return []any{}, nil
	}
	root, err := escrowMicrosoftRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	_, byDevice, err := root.loadBitlockerRecoveryKeys()
	if err != nil {
		return nil, err
	}
	keys := byDevice[a.DeviceId.Data]
	if keys == nil {
		return []any{}, nil
	}
	return keys, nil
}

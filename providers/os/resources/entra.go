// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
)

type mqlEntraInternal struct {
	lock    sync.Mutex
	fetched bool
}

func (e *mqlEntra) id() (string, error) {
	return "entra", nil
}

// entraResult is what the platform reduces to before it is set on the fields.
// A device without an Entra device identity has no device or tenant ID, so
// those are null rather than empty strings nobody read.
type entraResult struct {
	deviceID string
	tenantID string
}

// entraFromIdentity maps the detected device identity to the entra fields. The
// device is joined when it has an Entra device ID. The tenant is only reported
// for a joined device, so a tenant read from an Intune certificate alone never
// passes as an Entra device identity.
func entraFromIdentity(id detwin.DeviceIdentity) entraResult {
	if id.EntraDeviceID == "" {
		return entraResult{}
	}
	return entraResult{deviceID: id.EntraDeviceID, tenantID: id.EntraTenantID}
}

func (r entraResult) set(e *mqlEntra) {
	e.Joined = plugin.TValue[bool]{Data: r.deviceID != "", State: plugin.StateIsSet}
	e.DeviceId = mdmStringField(r.deviceID)
	e.TenantId = mdmStringField(r.tenantID)
}

// populate reads the device identity once and sets every field. The identity
// is detected with the platform, from the device certificates; reading it back
// from the platform labels keeps these fields and the labels in agreement.
// Platforms without Entra detection report joined as false.
func (e *mqlEntra) populate() error {
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.fetched {
		return nil
	}

	conn, ok := e.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("entra is not supported on this connection")
	}
	platform := conn.Asset().Platform

	var res entraResult
	if platform != nil && platform.IsFamily(inventory.FAMILY_WINDOWS) {
		res = entraFromIdentity(detwin.DeviceIdentityFromLabels(platform))
	}
	res.set(e)
	e.fetched = true
	return nil
}

func (e *mqlEntra) joined() (bool, error)     { return false, e.populate() }
func (e *mqlEntra) deviceId() (string, error) { return "", e.populate() }
func (e *mqlEntra) tenantId() (string, error) { return "", e.populate() }

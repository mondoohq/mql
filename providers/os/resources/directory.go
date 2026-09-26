// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
)

type mqlDirectoryInternal struct {
	lock    sync.Mutex
	fetched bool
}

func (d *mqlDirectory) id() (string, error) {
	return "directory", nil
}

// entraMembership is the device's Microsoft Entra ID membership, reduced from
// the detected identity. A zero value means the device is not a member.
type entraMembership struct {
	deviceID string
	tenantID string
}

// entraFromIdentity maps the detected device identity to the Entra membership.
// The device is a member when it has an Entra device ID. The tenant is only
// reported for a member, so a tenant read from an Intune certificate alone
// never passes as an Entra device identity.
func entraFromIdentity(id detwin.DeviceIdentity) entraMembership {
	if id.EntraDeviceID == "" {
		return entraMembership{}
	}
	return entraMembership{deviceID: id.EntraDeviceID, tenantID: id.EntraTenantID}
}

func (e entraMembership) member() bool { return e.deviceID != "" }

// directoryResult holds every membership detected for the device. Each
// directory is its own field, because a device can be a member of several.
type directoryResult struct {
	entra entraMembership
}

func (r directoryResult) set(d *mqlDirectory) error {
	d.Joined = plugin.TValue[bool]{Data: r.entra.member(), State: plugin.StateIsSet}

	if !r.entra.member() {
		d.Entra = plugin.TValue[*mqlDirectoryEntra]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil
	}
	raw, err := CreateResource(d.MqlRuntime, "directory.entra", map[string]*llx.RawData{
		"__id":     llx.StringData("directory.entra"),
		"deviceId": mdmStringData(r.entra.deviceID),
		"tenantId": mdmStringData(r.entra.tenantID),
	})
	if err != nil {
		return err
	}
	d.Entra = plugin.TValue[*mqlDirectoryEntra]{Data: raw.(*mqlDirectoryEntra), State: plugin.StateIsSet}
	return nil
}

// populate reads the device identity once and sets every field. The identity
// is detected with the platform, from the device certificates; reading it back
// from the platform labels keeps these fields and the labels in agreement.
// Platforms without directory detection report no membership.
func (d *mqlDirectory) populate() error {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.fetched {
		return nil
	}

	conn, ok := d.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("directory is not supported on this connection")
	}
	platform := conn.Asset().Platform

	var res directoryResult
	if platform != nil && platform.IsFamily(inventory.FAMILY_WINDOWS) {
		res.entra = entraFromIdentity(detwin.DeviceIdentityFromLabels(platform))
	}
	if err := res.set(d); err != nil {
		return err
	}
	d.fetched = true
	return nil
}

func (d *mqlDirectory) joined() (bool, error) { return false, d.populate() }

func (d *mqlDirectory) entra() (*mqlDirectoryEntra, error) { return nil, d.populate() }

// initDirectoryEntra makes directory.entra reachable by its own path. The
// resource shares its name with the directory field that returns it, so a
// query for directory.entra resolves to the resource; without this it would be
// built from empty arguments and report null for every field.
func initDirectoryEntra(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "directory", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlDirectory).GetEntra()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.IsNull() {
		return nil, nil, errors.New("cannot read directory.entra: the device has no Microsoft Entra device identity")
	}
	return args, v.Data, nil
}

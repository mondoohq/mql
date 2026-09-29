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

type mqlIdpInternal struct {
	lock    sync.Mutex
	fetched bool
}

func (i *mqlIdp) id() (string, error) {
	return "idp", nil
}

// entraMembership is the device's Microsoft Entra ID membership, reduced from
// the detected identity. A zero value means the device is not a member.
type entraMembership struct {
	deviceID string
	tenantID string
	joinType string
}

// entraFromIdentity maps the detected device identity to the Entra membership.
// The device is a member when it has an Entra device ID. The tenant is only
// reported for a member, so a tenant read from an Intune certificate alone
// never passes as an Entra device identity.
func entraFromIdentity(id detwin.DeviceIdentity) entraMembership {
	if id.EntraDeviceID == "" {
		return entraMembership{}
	}
	return entraMembership{deviceID: id.EntraDeviceID, tenantID: id.EntraTenantID, joinType: id.EntraJoinType}
}

func (e entraMembership) member() bool { return e.deviceID != "" }

// idpResult holds every membership detected for the device. Each identity
// provider is its own field, because a device can belong to several.
//
// Each provider also records whether it was read. That is the difference
// between "this device belongs to none" and "nobody looked", and only the
// first of those is a fact joined may report.
type idpResult struct {
	// entraRead is whether the Microsoft Entra identity was read.
	entraRead bool
	entra     entraMembership
	ad        adResult
}

func (r idpResult) set(i *mqlIdp) error {
	null := plugin.StateIsSet | plugin.StateIsNull

	entraMember := r.entraRead && r.entra.member()
	adIsMember := r.ad.state == membershipRead && r.ad.membership.member()

	switch {
	case entraMember || adIsMember:
		i.Joined = plugin.TValue[bool]{Data: true, State: plugin.StateIsSet}
	case r.ad.state == membershipUnreadable:
		// Active Directory is looked for here but its source could not be
		// read, so the device may well be a member.
		i.Joined = plugin.TValue[bool]{State: null}
	case r.entraRead || r.ad.state == membershipRead:
		i.Joined = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	default:
		// Nothing was read on this platform, so there is no membership to
		// report either way. A measured false here would claim the device
		// belongs to no identity provider on the strength of a lookup that
		// never happened.
		i.Joined = plugin.TValue[bool]{State: null}
	}

	if !entraMember {
		i.Entra = plugin.TValue[*mqlIdpEntra]{State: null}
	} else {
		raw, err := CreateResource(i.MqlRuntime, "idp.entra", map[string]*llx.RawData{
			"__id":     llx.StringData("idp.entra"),
			"deviceId": mdmStringData(r.entra.deviceID),
			"tenantId": mdmStringData(r.entra.tenantID),
			"joinType": mdmStringData(r.entra.joinType),
		})
		if err != nil {
			return err
		}
		i.Entra = plugin.TValue[*mqlIdpEntra]{Data: raw.(*mqlIdpEntra), State: plugin.StateIsSet}
	}

	if !adIsMember {
		i.ActiveDirectory = plugin.TValue[*mqlIdpActiveDirectory]{State: null}
	} else {
		raw, err := CreateResource(i.MqlRuntime, "idp.activeDirectory", map[string]*llx.RawData{
			"__id":   llx.StringData("idp.activeDirectory"),
			"domain": mdmStringData(r.ad.membership.domain),
			"forest": mdmStringData(r.ad.membership.forest),
		})
		if err != nil {
			return err
		}
		i.ActiveDirectory = plugin.TValue[*mqlIdpActiveDirectory]{Data: raw.(*mqlIdpActiveDirectory), State: plugin.StateIsSet}
	}
	return nil
}

// populate reads the device identity once and sets every field. The Entra
// identity is detected with the platform, from the device certificates;
// reading it back from the platform labels keeps these fields and the labels
// in agreement. Active Directory membership is read here, from the local
// configuration of each platform. Platforms without identity-provider
// detection report no membership.
func (i *mqlIdp) populate() error {
	i.lock.Lock()
	defer i.lock.Unlock()
	if i.fetched {
		return nil
	}

	conn, ok := i.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("idp is not supported on this connection")
	}
	platform := conn.Asset().Platform

	// Only Windows client editions are asked for their device certificates, so
	// on anything else the absence of identity labels says nothing. Ask the
	// detector which platforms it read rather than inferring it from empty
	// labels, so the two cannot drift apart.
	var res idpResult
	if platform != nil && platform.IsFamily(inventory.FAMILY_WINDOWS) && detwin.IdentityDetectable(platform) {
		res.entraRead = true
		res.entra = entraFromIdentity(detwin.DeviceIdentityFromLabels(platform))
	}
	res.ad = readActiveDirectory(conn, platform)
	if err := res.set(i); err != nil {
		return err
	}
	i.fetched = true
	return nil
}

func (i *mqlIdp) joined() (bool, error) { return false, i.populate() }

func (i *mqlIdp) entra() (*mqlIdpEntra, error) { return nil, i.populate() }

func (i *mqlIdp) activeDirectory() (*mqlIdpActiveDirectory, error) { return nil, i.populate() }

// initIdpEntra makes idp.entra reachable by its own path. The resource shares
// its name with the idp field that returns it, so a query for idp.entra
// resolves to the resource; without this it would be built from empty
// arguments and report null for every field.
func initIdpEntra(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "idp", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlIdp).GetEntra()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.IsNull() {
		return nil, nil, errors.New("cannot read idp.entra: the device has no Microsoft Entra device identity")
	}
	return args, v.Data, nil
}

// initIdpActiveDirectory makes idp.activeDirectory reachable by its own path,
// for the same reason as initIdpEntra.
func initIdpActiveDirectory(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "idp", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlIdp).GetActiveDirectory()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.IsNull() {
		return nil, nil, errors.New("cannot read idp.activeDirectory: the device is not a member of an Active Directory domain")
	}
	return args, v.Data, nil
}

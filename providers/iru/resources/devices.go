// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/connection/client"
	"go.mondoo.com/mql/types"
)

// mqlIruDeviceInternal caches the blueprint and user IDs picked up from the
// device listing row so the typed blueprint() / user() cross-references can
// resolve them without re-walking the fleet.
type mqlIruDeviceInternal struct {
	cacheBlueprintId string
	cacheUserId      string
}

// devices walks the /devices listing and materializes each row as an
// iru.device resource. Hardware, FileVault, network, and volume fields that
// come from /devices/{id}/details are populated lazily by the computed
// methods further down this file.
func (r *mqlIru) devices() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IruConnection)
	devices, err := conn.Client.ListDevices()
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Msg("iru> access denied to devices; returning empty list")
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(devices))
	for i := range devices {
		dev, err := newMqlIruDevice(r.MqlRuntime, &devices[i])
		if err != nil {
			return nil, err
		}
		res = append(res, dev)
	}
	return res, nil
}

// newMqlIruDevice builds an iru.device from a /devices listing row and
// populates the Internal struct's blueprint/user IDs so the typed
// cross-references resolve. Shared between devices() and initIruDevice.
func newMqlIruDevice(runtime *plugin.Runtime, d *client.Device) (*mqlIruDevice, error) {
	tags := make([]any, 0, len(d.Tags))
	for _, t := range d.Tags {
		tags = append(tags, t)
	}
	raw := map[string]*llx.RawData{
		"id":              llx.StringData(d.DeviceID),
		"name":            llx.StringData(d.DeviceName),
		"serialNumber":    llx.StringData(d.SerialNumber),
		"udid":            llx.StringData(d.UDID),
		"assetTag":        llx.StringData(d.AssetTag),
		"model":           llx.StringData(d.Model),
		"platform":        llx.StringData(d.Platform),
		"osVersion":       llx.StringData(d.OSVersion),
		"mdmEnabled":      llx.BoolData(d.MDMEnabled),
		"agentInstalled":  llx.BoolData(d.AgentInstalled),
		"agentVersion":    llx.StringData(d.AgentVersion),
		"blueprintName":   llx.StringData(d.BlueprintName),
		"lastCheckIn":     llx.TimeDataPtr(client.ParseTime(d.LastCheckIn)),
		"firstEnrollment": llx.TimeDataPtr(client.ParseTime(d.FirstEnrollment)),
		"lastEnrollment":  llx.TimeDataPtr(client.ParseTime(d.LastEnrollment)),
		"isMissing":       llx.BoolData(d.IsMissing),
		"isRemoved":       llx.BoolData(d.IsRemoved),
		"lostModeStatus":  llx.StringData(d.LostModeStatus),
		"tags":            llx.ArrayData(tags, types.String),
	}
	item, err := CreateResource(runtime, "iru.device", raw)
	if err != nil {
		return nil, err
	}
	dev := item.(*mqlIruDevice)
	dev.cacheBlueprintId = d.BlueprintID
	if u := d.EmbeddedUser(); u != nil {
		dev.cacheUserId = u.ID
	}
	return dev, nil
}

func (c *mqlIruDevice) id() (string, error) {
	return "iru.device/" + c.Id.Data, nil
}

// initIruDevice supports `iru.device(id: ...)` lookups by ID. It resolves
// the device from the cached tenant-wide listing so the listing's summary
// fields (platform, osVersion, blueprint/user refs, tags, …) are populated;
// the /devices/{id}/details endpoint doesn't carry these and would leave
// `@defaults` fields blank.
func initIruDevice(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.IruConnection)
	devices, err := conn.Client.ListDevices()
	if err != nil {
		return args, nil, err
	}
	for i := range devices {
		if devices[i].DeviceID != id {
			continue
		}
		dev, err := newMqlIruDevice(runtime, &devices[i])
		if err != nil {
			return nil, nil, err
		}
		return nil, dev, nil
	}
	return nil, nil, fmt.Errorf("iru.device with id %q not found", id)
}

// getDetails is the single fetch every lazy hardware/network/posture field
// on iru.device shares. The connection caches the result per device ID so
// repeated calls (filevault, volumes, memory, …) all hit one network round
// trip.
func (c *mqlIruDevice) getDetails() (*client.DeviceDetails, error) {
	conn := c.MqlRuntime.Connection.(*connection.IruConnection)
	return conn.GetDeviceDetails(c.Id.Data)
}

// --- General --------------------------------------------------------------

func (c *mqlIruDevice) systemVersion() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.General.SystemVersion, nil
}

func (c *mqlIruDevice) bootVolume() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.General.BootVolume, nil
}

func (c *mqlIruDevice) lastUser() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.General.LastUser, nil
}

func (c *mqlIruDevice) timeSinceBoot() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.General.TimeSinceBoot, nil
}

// --- MDM ------------------------------------------------------------------

func (c *mqlIruDevice) supervised() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return client.ParseBool(d.MDM.Supervised), nil
}

func (c *mqlIruDevice) mdmInstallDate() (*time.Time, error) {
	d, err := c.getDetails()
	if err != nil {
		return nil, err
	}
	return client.ParseTime(d.MDM.InstallDate), nil
}

// --- Hardware -------------------------------------------------------------

func (c *mqlIruDevice) modelIdentifier() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.HardwareOverview.ModelIdentifier, nil
}

func (c *mqlIruDevice) processor() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.HardwareOverview.ProcessorName, nil
}

func (c *mqlIruDevice) processorSpeed() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.HardwareOverview.ProcessorSpeed, nil
}

func (c *mqlIruDevice) processorCount() (int64, error) {
	d, err := c.getDetails()
	if err != nil {
		return 0, err
	}
	return c.parseIntField(d.HardwareOverview.NumberOfProcessors, "processorCount"), nil
}

func (c *mqlIruDevice) coreCount() (int64, error) {
	d, err := c.getDetails()
	if err != nil {
		return 0, err
	}
	return c.parseIntField(d.HardwareOverview.TotalNumberOfCores, "coreCount"), nil
}

func (c *mqlIruDevice) memory() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.HardwareOverview.Memory, nil
}

func (c *mqlIruDevice) memoryBytes() (int64, error) {
	d, err := c.getDetails()
	if err != nil {
		return 0, err
	}
	return client.ParseMemoryBytes(d.HardwareOverview.Memory), nil
}

// parseIntField parses an integer field from the detail endpoint, warning
// (rather than silently returning 0) when the API hands back a non-empty
// value that isn't numeric, so a zero from a decode problem is
// distinguishable from a genuinely absent field in the logs.
func (c *mqlIruDevice) parseIntField(s, field string) int64 {
	n, ok := client.ParseIntOK(s)
	if !ok {
		log.Warn().Str("value", s).Str("field", field).Str("device", c.Id.Data).
			Msg("iru> unexpected non-integer value; using 0")
	}
	return n
}

func (c *mqlIruDevice) batteryHealth() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.HardwareOverview.BatteryHealth, nil
}

// --- FileVault. Only escrow/type/rotation are exposed, never the raw key.
// --------------------------------------------------------------------------

func (c *mqlIruDevice) filevaultEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.FileVault.Enabled, nil
}

func (c *mqlIruDevice) filevaultRecoveryKeyEscrowed() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.FileVault.PRKEscrowed, nil
}

func (c *mqlIruDevice) filevaultRecoveryKeyType() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.FileVault.RecoveryKeyType, nil
}

func (c *mqlIruDevice) filevaultNextRotation() (*time.Time, error) {
	d, err := c.getDetails()
	if err != nil {
		return nil, err
	}
	return client.ParseTime(d.FileVault.NextRotation), nil
}

func (c *mqlIruDevice) filevaultRegenRequired() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.FileVault.RegenRequired, nil
}

// --- Activation lock ------------------------------------------------------

func (c *mqlIruDevice) activationLockSupported() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.ActivationLock.Supported, nil
}

func (c *mqlIruDevice) userActivationLockEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.ActivationLock.UserEnabled, nil
}

func (c *mqlIruDevice) deviceActivationLockEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.ActivationLock.DeviceEnabled, nil
}

func (c *mqlIruDevice) activationLockAllowedWhileSupervised() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.ActivationLock.AllowedWhileSupervised, nil
}

// --- Security / network / recovery ----------------------------------------

func (c *mqlIruDevice) remoteDesktopEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.SecurityInfo.RemoteDesktopEnabled, nil
}

func (c *mqlIruDevice) ipAddress() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.Network.IPAddress, nil
}

func (c *mqlIruDevice) publicIpAddress() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.Network.PublicIP, nil
}

func (c *mqlIruDevice) localHostname() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.Network.LocalHostname, nil
}

func (c *mqlIruDevice) macAddress() (string, error) {
	d, err := c.getDetails()
	if err != nil {
		return "", err
	}
	return d.Network.MACAddress, nil
}

func (c *mqlIruDevice) recoveryLockEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.Recovery.RecoveryLockEnabled, nil
}

func (c *mqlIruDevice) firmwarePasswordEnabled() (bool, error) {
	d, err := c.getDetails()
	if err != nil {
		return false, err
	}
	return d.Recovery.FirmwarePasswordExists, nil
}

// --- Volumes / parameters / apps / profiles -------------------------------

func (c *mqlIruDevice) volumes() ([]any, error) {
	d, err := c.getDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(d.Volumes))
	for _, v := range d.Volumes {
		res = append(res, map[string]any{
			"name":         v.Name,
			"format":       v.Format,
			"identifier":   v.Identifier,
			"capacity":     v.Capacity,
			"available":    v.Available,
			"percent_used": v.PercentUsed,
			"encrypted":    v.Encrypted,
		})
	}
	return res, nil
}

func (c *mqlIruDevice) parameters() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.IruConnection)
	params, err := conn.GetDeviceParameters(c.Id.Data)
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Str("device", c.Id.Data).Msg("iru> access denied to device parameters; skipping")
			return nil, nil
		}
		return nil, err
	}
	res := make([]any, 0, len(params))
	for _, p := range params {
		res = append(res, map[string]any{
			"item_id":     p.ItemID,
			"name":        p.Name,
			"category":    p.Category,
			"subcategory": p.Subcategory,
			"status":      p.Status,
		})
	}
	return res, nil
}

func (c *mqlIruDevice) apps() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.IruConnection)
	apps, err := conn.GetDeviceApps(c.Id.Data)
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Str("device", c.Id.Data).Msg("iru> access denied to device apps; skipping")
			return nil, nil
		}
		return nil, err
	}
	res := make([]any, 0, len(apps))
	for _, a := range apps {
		// bundle_id is not a reliable per-device key: macOS reports the same
		// bundle at multiple paths and some rows carry an empty bundle_id, so
		// keying on it alone collapses distinct apps into one cache entry. Key
		// on the install's identifying content (bundle + path + name + version)
		// instead: unique for distinct installs, stable if the API reorders
		// rows between fetches, and collapsing only genuine duplicate rows.
		item, err := CreateResource(c.MqlRuntime, "iru.app", map[string]*llx.RawData{
			"__id":             llx.StringData(fmt.Sprintf("iru.app/%s/%s|%s|%s|%s", c.Id.Data, a.BundleID, a.Path, a.Name, a.Version)),
			"name":             llx.StringData(a.Name),
			"bundleId":         llx.StringData(a.BundleID),
			"version":          llx.StringData(a.Version),
			"appId":            llx.StringData(a.AppID),
			"bundleSize":       llx.IntData(c.parseIntField(a.BundleSize, "app.bundleSize")),
			"source":           llx.StringData(a.Source),
			"process":          llx.StringData(a.Process),
			"signature":        llx.StringData(a.Signature),
			"path":             llx.StringData(a.Path),
			"creationDate":     llx.TimeDataPtr(client.ParseTime(a.CreationDate)),
			"modificationDate": llx.TimeDataPtr(client.ParseTime(a.ModificationDate)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (c *mqlIruDevice) profiles() ([]any, error) {
	d, err := c.getDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(d.InstalledProfiles))
	for _, p := range d.InstalledProfiles {
		payloadTypes := make([]any, 0, len(p.PayloadTypes))
		for _, pt := range p.PayloadTypes {
			payloadTypes = append(payloadTypes, pt)
		}
		// Key on the profile's uuid plus identifier: unique for distinct
		// profiles, stable if the API reorders rows, and (unlike keying on a
		// possibly-empty uuid alone) collapsing only genuine duplicate rows.
		item, err := CreateResource(c.MqlRuntime, "iru.profile", map[string]*llx.RawData{
			"__id":         llx.StringData(fmt.Sprintf("iru.profile/%s/%s|%s", c.Id.Data, p.UUID, p.Identifier)),
			"name":         llx.StringData(p.Name),
			"uuid":         llx.StringData(p.UUID),
			"identifier":   llx.StringData(p.Identifier),
			"organization": llx.StringData(p.Organization),
			"verified":     llx.StringData(p.Verified),
			"installDate":  llx.TimeDataPtr(client.ParseTime(p.InstallDate)),
			"payloadTypes": llx.ArrayData(payloadTypes, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

// --- Typed cross-references -----------------------------------------------

// blueprint resolves the device's assigned blueprint from the memoized
// tenant-wide listing. It degrades to null (rather than failing the whole
// `iru.devices` query) when the token can list devices but not blueprints, or
// when the device points at a blueprint the listing does not return, mirroring
// how the top-level `iru.blueprints` accessor degrades on access-denied.
func (c *mqlIruDevice) blueprint() (*mqlIruBlueprint, error) {
	if c.cacheBlueprintId == "" {
		c.Blueprint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.IruConnection)
	bps, err := conn.ListBlueprints()
	if err != nil {
		if client.IsAccessDenied(err) {
			c.Blueprint.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	for i := range bps {
		if bps[i].ID != c.cacheBlueprintId {
			continue
		}
		bp, err := CreateResource(c.MqlRuntime, "iru.blueprint", blueprintArgs(&bps[i]))
		if err != nil {
			return nil, err
		}
		return bp.(*mqlIruBlueprint), nil
	}
	// Dangling reference: the device names a blueprint absent from the listing.
	c.Blueprint.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// user resolves the device's assigned end-user from the memoized tenant-wide
// listing, degrading to null on the same access-denied / dangling-reference
// conditions as blueprint above.
func (c *mqlIruDevice) user() (*mqlIruUser, error) {
	if c.cacheUserId == "" {
		c.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := c.MqlRuntime.Connection.(*connection.IruConnection)
	users, err := conn.ListUsers()
	if err != nil {
		if client.IsAccessDenied(err) {
			c.User.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	for i := range users {
		if users[i].ID != c.cacheUserId {
			continue
		}
		u, err := CreateResource(c.MqlRuntime, "iru.user", userArgs(&users[i]))
		if err != nil {
			return nil, err
		}
		return u.(*mqlIruUser), nil
	}
	// Dangling reference: the device names a user absent from the listing.
	c.User.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

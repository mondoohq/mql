// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/resources/eos"
)

// =====================================================================
// arista.eos.consoleSettings
// =====================================================================

func (a *mqlAristaEosConsoleSettings) id() (string, error) {
	return "arista.eos.consoleSettings", nil
}

func (a *mqlAristaEos) consoleSettings() (*mqlAristaEosConsoleSettings, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	c := eos.ParseConsoleSettings(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.consoleSettings", map[string]*llx.RawData{
		"configured":            llx.BoolData(c.Configured),
		"idleTimeout":           llx.IntData(int64(c.IdleTimeout)),
		"sessionTimeout":        llx.IntData(int64(c.SessionTimeout)),
		"sessionTimeoutWarning": llx.IntData(int64(c.SessionTimeoutWarning)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosConsoleSettings), nil
}

// =====================================================================
// arista.eos.eapi containment
// =====================================================================

func (a *mqlAristaEosEapi) vrfs() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return stringSliceToAny(eos.ParseEapiContainment(rc).Vrfs), nil
}

func (a *mqlAristaEosEapi) sessionTimeout() (int64, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return 0, err
	}
	return int64(eos.ParseEapiContainment(rc).SessionTimeout), nil
}

// =====================================================================
// arista.eos.stormControl (list)
// =====================================================================

// id keys a statement on the interface plus the traffic class, since an
// interface carries at most one ceiling per class but may carry several
// classes, and the `cpu` form is a separate statement from the port-level one
// for the same class.
func (a *mqlAristaEosStormControl) id() (string, error) {
	if a.Interface.Error != nil {
		return "", a.Interface.Error
	}
	if a.TrafficClass.Error != nil {
		return "", a.TrafficClass.Error
	}
	if a.Cpu.Error != nil {
		return "", a.Cpu.Error
	}
	scope := "port"
	if a.Cpu.Data {
		scope = "cpu"
	}
	return "arista.eos.stormControl/" + a.Interface.Data + "/" + scope + "/" + a.TrafficClass.Data, nil
}

func (a *mqlAristaEos) stormControls() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	settings := eos.ParseStormControl(rc)
	res := make([]any, 0, len(settings))
	for _, s := range settings {
		mqlS, err := CreateResource(a.MqlRuntime, "arista.eos.stormControl", map[string]*llx.RawData{
			"interface":    llx.StringData(s.Interface),
			"trafficClass": llx.StringData(s.TrafficClass),
			"level":        llx.FloatData(s.Level),
			"unit":         llx.StringData(s.Unit),
			"cpu":          llx.BoolData(s.Cpu),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlS)
	}
	return res, nil
}

// =====================================================================
// arista.eos.user role edge
// =====================================================================

// roleByName resolves a role name against the roles defined on the device.
//
// The lookup goes through the arista.eos resource, whose roles field the
// runtime caches after the first read, so resolving a role for every account
// costs one `show users roles` call rather than one per account.
func roleByName(runtime *plugin.Runtime, name string) (*mqlAristaEosRole, error) {
	o, err := CreateResource(runtime, "arista.eos", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	roles := o.(*mqlAristaEos).GetRoles()
	if roles.Error != nil {
		return nil, roles.Error
	}
	for _, r := range roles.Data {
		mqlRole, ok := r.(*mqlAristaEosRole)
		if !ok {
			continue
		}
		if mqlRole.Name.Error == nil && mqlRole.Name.Data == name {
			return mqlRole, nil
		}
	}
	return nil, nil
}

func (a *mqlAristaEosUser) roleRef() (*mqlAristaEosRole, error) {
	if a.Role.Error != nil {
		return nil, a.Role.Error
	}
	// An account with no role of its own runs under the role marked default,
	// which is a different fact from the one this field reports.
	if a.Role.Data == "" {
		a.RoleRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	mqlRole, err := roleByName(a.MqlRuntime, a.Role.Data)
	if err != nil {
		return nil, err
	}
	if mqlRole == nil {
		// The account names a role that is not defined on the device. The
		// role field keeps the configured name, so the mismatch stays
		// visible rather than becoming an error.
		a.RoleRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlRole, nil
}

// =====================================================================
// arista.eos.snmpUser / snmpGroup / snmpView / snmpHost
// =====================================================================

// snmpConfig parses the SNMP configuration off the running-config, memoized
// on the running-config resource so the several SNMP collections share one
// walk of the device configuration.
func snmpConfig(runtime *plugin.Runtime) (*eos.SnmpConfig, error) {
	rc, err := runningConfigResource(runtime)
	if err != nil {
		return nil, err
	}
	return rc.fetchSnmpConfig()
}

// id keys a user on the group as well as the name, since the same security
// name may be declared against more than one group, and on the remote agent,
// since a name may be declared for the local agent and a remote one.
func (a *mqlAristaEosSnmpUser) id() (string, error) {
	if a.Name.Error != nil {
		return "", a.Name.Error
	}
	if a.Group.Error != nil {
		return "", a.Group.Error
	}
	if a.RemoteAddress.Error != nil {
		return "", a.RemoteAddress.Error
	}
	agent := a.RemoteAddress.Data
	if agent == "" {
		agent = "local"
	}
	return "arista.eos.snmpUser/" + agent + "/" + a.Group.Data + "/" + a.Name.Data, nil
}

func newMqlSnmpUser(runtime *plugin.Runtime, u eos.SnmpUser) (*mqlAristaEosSnmpUser, error) {
	res, err := CreateResource(runtime, "arista.eos.snmpUser", map[string]*llx.RawData{
		"name":          llx.StringData(u.Name),
		"group":         llx.StringData(u.Group),
		"version":       llx.StringData(u.Version),
		"securityLevel": llx.StringData(u.SecurityLevel()),
		"authAlgorithm": llx.StringData(u.AuthAlgorithm),
		"privAlgorithm": llx.StringData(u.PrivAlgorithm),
		"localized":     llx.BoolData(u.Localized),
		"remoteAddress": llx.StringData(u.RemoteAddress),
		"remotePort":    llx.IntData(int64(u.RemotePort)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosSnmpUser), nil
}

func (a *mqlAristaEos) snmpUsers() ([]any, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(cfg.Users))
	for _, u := range cfg.Users {
		mqlUser, err := newMqlSnmpUser(a.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// id keys a group on the version as well as the name, since one group name
// may be declared separately for v1, v2c, and v3.
func (a *mqlAristaEosSnmpGroup) id() (string, error) {
	if a.Name.Error != nil {
		return "", a.Name.Error
	}
	if a.Version.Error != nil {
		return "", a.Version.Error
	}
	if a.SecurityLevel.Error != nil {
		return "", a.SecurityLevel.Error
	}
	if a.Context.Error != nil {
		return "", a.Context.Error
	}
	// A v3 group repeats under one name at each security level, and each
	// definition carries its own read and write views. Keying on name and
	// version alone collapses them onto the first, so a group granting write
	// at priv disappears behind a read-only one at noauth. Context qualifies
	// the same statement and is included for the same reason.
	return "arista.eos.snmpGroup/" + a.Version.Data + "/" + a.Name.Data +
		"/" + a.SecurityLevel.Data + "/" + a.Context.Data, nil
}

func newMqlSnmpGroup(runtime *plugin.Runtime, g eos.SnmpGroup) (*mqlAristaEosSnmpGroup, error) {
	res, err := CreateResource(runtime, "arista.eos.snmpGroup", map[string]*llx.RawData{
		"name":          llx.StringData(g.Name),
		"version":       llx.StringData(g.Version),
		"securityLevel": llx.StringData(g.SecurityLevel),
		"context":       llx.StringData(g.Context),
		"readView":      llx.StringData(g.ReadView),
		"writeView":     llx.StringData(g.WriteView),
		"notifyView":    llx.StringData(g.NotifyView),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosSnmpGroup), nil
}

func (a *mqlAristaEos) snmpGroups() ([]any, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		mqlGroup, err := newMqlSnmpGroup(a.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// id keys a view entry on the subtree as well as the name, since a view is
// assembled from one line per subtree and every line is its own entry.
func (a *mqlAristaEosSnmpView) id() (string, error) {
	if a.Name.Error != nil {
		return "", a.Name.Error
	}
	if a.MibFamily.Error != nil {
		return "", a.MibFamily.Error
	}
	return "arista.eos.snmpView/" + a.Name.Data + "/" + a.MibFamily.Data, nil
}

func newMqlSnmpView(runtime *plugin.Runtime, v eos.SnmpView) (*mqlAristaEosSnmpView, error) {
	res, err := CreateResource(runtime, "arista.eos.snmpView", map[string]*llx.RawData{
		"name":      llx.StringData(v.Name),
		"mibFamily": llx.StringData(v.MibFamily),
		"included":  llx.BoolData(v.Included),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosSnmpView), nil
}

func (a *mqlAristaEos) snmpViews() ([]any, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(cfg.Views))
	for _, v := range cfg.Views {
		mqlView, err := newMqlSnmpView(a.MqlRuntime, v)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlView)
	}
	return res, nil
}

// groupRef resolves a user's group against the groups the device declares.
// The user's version selects among same-named groups declared for more than
// one protocol version.
func (a *mqlAristaEosSnmpUser) groupRef() (*mqlAristaEosSnmpGroup, error) {
	if a.Group.Error != nil {
		return nil, a.Group.Error
	}
	if a.Version.Error != nil {
		return nil, a.Version.Error
	}
	if a.Group.Data == "" {
		a.GroupRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	for _, g := range cfg.Groups {
		if g.Name != a.Group.Data || g.Version != a.Version.Data {
			continue
		}
		return newMqlSnmpGroup(a.MqlRuntime, g)
	}

	a.GroupRef.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// viewByName resolves a view name against the entries the device declares. A
// view is assembled from one line per subtree, so the first entry is the one
// returned; the full set is on arista.eos.snmpViews.
func viewByName(runtime *plugin.Runtime, name string) (*mqlAristaEosSnmpView, error) {
	if name == "" {
		return nil, nil
	}
	cfg, err := snmpConfig(runtime)
	if err != nil {
		return nil, err
	}
	for _, v := range cfg.Views {
		if v.Name == name {
			return newMqlSnmpView(runtime, v)
		}
	}
	return nil, nil
}

func (a *mqlAristaEosSnmpGroup) readViewRef() (*mqlAristaEosSnmpView, error) {
	if a.ReadView.Error != nil {
		return nil, a.ReadView.Error
	}
	mqlView, err := viewByName(a.MqlRuntime, a.ReadView.Data)
	if err != nil {
		return nil, err
	}
	if mqlView == nil {
		a.ReadViewRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlView, nil
}

func (a *mqlAristaEosSnmpGroup) writeViewRef() (*mqlAristaEosSnmpView, error) {
	if a.WriteView.Error != nil {
		return nil, a.WriteView.Error
	}
	mqlView, err := viewByName(a.MqlRuntime, a.WriteView.Data)
	if err != nil {
		return nil, err
	}
	if mqlView == nil {
		a.WriteViewRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlView, nil
}

// mqlAristaEosSnmpHostInternal holds the trailing token of the host line. It
// is a community string under v1 and v2c, so it is never published as a
// field; it exists only so the destination can be resolved to the community
// or user it names.
type mqlAristaEosSnmpHostInternal struct {
	cacheCredential string
}

// id keys a destination on every dimension along which one repeats: the same
// collector is commonly configured twice, once for traps and once for
// informs, and a device may reach it through more than one routing instance,
// protocol version, or port.
func (a *mqlAristaEosSnmpHost) id() (string, error) {
	for _, e := range []error{
		a.Host.Error, a.Vrf.Error, a.Version.Error,
		a.NotificationType.Error, a.Port.Error, a.SecurityLevel.Error,
	} {
		if e != nil {
			return "", e
		}
	}
	// A v3 destination repeats to one collector at each security level, so
	// the level belongs in the key for the same reason it does on
	// arista.eos.snmpGroup: without it a noauth destination hides behind an
	// authPriv one, and the unauthenticated path is the one worth finding.
	return "arista.eos.snmpHost/" + a.Vrf.Data + "/" + a.Host.Data + "/" +
		strconv.FormatInt(a.Port.Data, 10) + "/" + a.Version.Data + "/" +
		a.NotificationType.Data + "/" + a.SecurityLevel.Data, nil
}

func (a *mqlAristaEosSnmpSetting) hosts() ([]any, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		mqlHost, err := CreateResource(a.MqlRuntime, "arista.eos.snmpHost", map[string]*llx.RawData{
			"host":             llx.StringData(h.Host),
			"vrf":              llx.StringData(h.Vrf),
			"version":          llx.StringData(h.Version),
			"securityLevel":    llx.StringData(h.SecurityLevel),
			"notificationType": llx.StringData(h.NotificationType),
			"port":             llx.IntData(int64(h.Port)),
		})
		if err != nil {
			return nil, err
		}
		mqlHost.(*mqlAristaEosSnmpHost).cacheCredential = h.Credential
		res = append(res, mqlHost)
	}
	return res, nil
}

func (a *mqlAristaEosSnmpHost) community() (*mqlAristaEosSnmpCommunity, error) {
	if a.Version.Error != nil {
		return nil, a.Version.Error
	}
	// A v3 destination names a user, not a community.
	if a.Version.Data == "v3" || a.cacheCredential == "" {
		a.Community.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	for _, c := range eos.ParseSnmpCommunities(rc) {
		if c.Name != a.cacheCredential {
			continue
		}
		// The same field set, and therefore the same id, as the entries
		// built by arista.eos.snmpCommunities, so both paths share one
		// cached resource.
		mqlC, err := CreateResource(a.MqlRuntime, "arista.eos.snmpCommunity", map[string]*llx.RawData{
			"name":   llx.StringData(c.Name),
			"access": llx.StringData(c.Access),
			"acl":    llx.StringData(c.ACL),
			"ipv6":   llx.BoolData(c.IPv6),
		})
		if err != nil {
			return nil, err
		}
		mqlC.(*mqlAristaEosSnmpCommunity).cacheAcl = c.ACL
		return mqlC.(*mqlAristaEosSnmpCommunity), nil
	}

	a.Community.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAristaEosSnmpHost) user() (*mqlAristaEosSnmpUser, error) {
	if a.Version.Error != nil {
		return nil, a.Version.Error
	}
	// A v1 or v2c destination names a community, not a user.
	if a.Version.Data != "v3" || a.cacheCredential == "" {
		a.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	for _, u := range cfg.Users {
		// Destinations name a local security name, so a user defined
		// against a remote agent is not a candidate.
		if u.Name != a.cacheCredential || u.RemoteAddress != "" {
			continue
		}
		return newMqlSnmpUser(a.MqlRuntime, u)
	}

	a.User.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// =====================================================================
// arista.eos.snmpSetting global identity
// =====================================================================

func (a *mqlAristaEosSnmpSetting) vrfs() ([]any, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return stringSliceToAny(cfg.Vrfs), nil
}

func (a *mqlAristaEosSnmpSetting) localInterface() (string, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return cfg.LocalInterface, nil
}

func (a *mqlAristaEosSnmpSetting) location() (string, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return cfg.Location, nil
}

func (a *mqlAristaEosSnmpSetting) contact() (string, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return cfg.Contact, nil
}

func (a *mqlAristaEosSnmpSetting) chassisId() (string, error) {
	cfg, err := snmpConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return cfg.ChassisID, nil
}

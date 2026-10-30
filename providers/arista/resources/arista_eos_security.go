// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// fetchRunningConfig returns the device's running-config with banner bodies
// blanked out. Banner text is operator-authored prose that routinely quotes
// configuration, and every parser here scans the same namespace it sits in, so
// command parsers must not see it. Use fetchRawRunningConfig for the banners
// themselves and for anything that reports the config verbatim.
//
// Both go through the cached arista.eos.runningConfig resource, so the device
// is asked for its configuration once however many resources are queried.
func fetchRunningConfig(runtime *plugin.Runtime) (string, error) {
	rc, err := runningConfigResource(runtime)
	if err != nil {
		return "", err
	}
	return rc.fetchStrippedContent()
}

// fetchRawRunningConfig returns the running-config exactly as the device
// rendered it, banners included.
func fetchRawRunningConfig(runtime *plugin.Runtime) (string, error) {
	rc, err := runningConfigResource(runtime)
	if err != nil {
		return "", err
	}
	return rc.fetchContent()
}

// runningConfigResource returns the device's running-config resource, which the
// runtime caches under a single id. Reach for this over fetchRunningConfig when
// you want one of its memoized parses rather than the raw text.
func runningConfigResource(runtime *plugin.Runtime) (*mqlAristaEosRunningConfig, error) {
	rc, err := CreateResource(runtime, "arista.eos.runningConfig", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return rc.(*mqlAristaEosRunningConfig), nil
}

// stringSliceToAny converts []string to []any for llx.ArrayData.
func stringSliceToAny(s []string) []any {
	res := make([]any, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}

// methodMapToDict converts map[string][]string to a map[string]any whose
// values are []any of strings, suitable for llx.MapData with the value type
// types.Array(types.String).
func methodMapToDict(m map[string][]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = stringSliceToAny(v)
	}
	return out
}

// =====================================================================
// arista.eos.aaa
// =====================================================================

func (a *mqlAristaEosAaa) id() (string, error) {
	return "arista.eos.aaa", nil
}

func (a *mqlAristaEos) aaa() (*mqlAristaEosAaa, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cfg := eos.ParseAaaConfig(rc)
	root := eos.ParseRootAccount(rc)
	enable := eos.ParseEnableSecret(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.aaa", map[string]*llx.RawData{
		"authenticationLogin":          llx.MapData(methodMapToDict(cfg.AuthenticationLogin), types.Array(types.String)),
		"authenticationEnable":         llx.MapData(methodMapToDict(cfg.AuthenticationEnable), types.Array(types.String)),
		"authorizationCommands":        llx.MapData(methodMapToDict(cfg.AuthorizationCommands), types.Array(types.String)),
		"authorizationConsoleCommands": llx.MapData(methodMapToDict(cfg.AuthorizationConsoleCommands), types.Array(types.String)),
		"serialConsoleAuthorization":   llx.BoolData(cfg.SerialConsoleAuthorization),
		"authorizationExec":            llx.MapData(methodMapToDict(cfg.AuthorizationExec), types.Array(types.String)),
		"accountingCommands":           llx.MapData(methodMapToDict(cfg.AccountingCommands), types.Array(types.String)),
		"accountingExec":               llx.MapData(methodMapToDict(cfg.AccountingExec), types.Array(types.String)),
		"rootAccountEnabled":           llx.BoolData(root.Enabled),
		"rootAccountNoPassword":        llx.BoolData(root.NoPassword),
		"rootSecretFormat":             llx.StringData(root.SecretFormat),
		"defaultLoginPermitsLocalOnly": llx.BoolData(cfg.DefaultLoginPermitsLocalOnly),
		"enableSecretConfigured":       llx.BoolData(enable.Configured),
		"enableSecretFormat":           llx.StringData(enable.Format),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosAaa), nil
}

// =====================================================================
// arista.eos.sshSettings
// =====================================================================

func (a *mqlAristaEosSshSettings) id() (string, error) {
	return "arista.eos.sshSettings", nil
}

// sshSettingsArgs maps a parsed `management ssh` block onto the resource's
// fields. It is a named function so a test can assert it covers every field
// the schema declares: codegen accepts a declared field with no population
// path, and the eight containment fields were declared and parsed for a
// release without ever being mapped here.
func sshSettingsArgs(s *eos.SshSettings) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"enabled":                llx.BoolData(s.Enabled),
		"protocolVersion":        llx.StringData(s.ProtocolVersion),
		"idleTimeout":            llx.IntData(int64(s.IdleTimeout)),
		"serverPort":             llx.IntData(int64(s.ServerPort)),
		"authenticationMode":     llx.StringData(s.AuthenticationMode),
		"ciphers":                llx.ArrayData(stringSliceToAny(s.Ciphers), types.String),
		"keyExchange":            llx.ArrayData(stringSliceToAny(s.KeyExchange), types.String),
		"macs":                   llx.ArrayData(stringSliceToAny(s.Macs), types.String),
		"hostkeyAlgorithms":      llx.ArrayData(stringSliceToAny(s.HostkeyAlgorithms), types.String),
		"fipsRestrictions":       llx.BoolData(s.FipsRestrictions),
		"vrfs":                   llx.ArrayData(stringSliceToAny(s.Vrfs), types.String),
		"loginTimeout":           llx.IntData(int64(s.LoginTimeout)),
		"connectionLimit":        llx.IntData(int64(s.ConnectionLimit)),
		"connectionPerHostLimit": llx.IntData(int64(s.ConnectionPerHostLimit)),
		"emptyPasswords":         llx.StringData(s.EmptyPasswords),
		"logLevel":               llx.StringData(s.LogLevel),
		"clientAliveInterval":    llx.IntData(int64(s.ClientAliveInterval)),
		"clientAliveCountMax":    llx.IntData(int64(s.ClientAliveCountMax)),
	}
}

func (a *mqlAristaEos) sshSettings() (*mqlAristaEosSshSettings, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	s := eos.ParseSshSettings(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.sshSettings", sshSettingsArgs(s))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosSshSettings), nil
}

// =====================================================================
// arista.eos.snmpCommunity (list)
// =====================================================================

type mqlAristaEosSnmpCommunityInternal struct {
	cacheAcl string
}

func (a *mqlAristaEosSnmpCommunity) id() (string, error) {
	if a.Name.Error != nil {
		return "", a.Name.Error
	}
	if a.Ipv6.Error != nil {
		return "", a.Ipv6.Error
	}
	// One community is commonly declared twice, once per address family, to
	// bind an IPv4 access-list and an IPv6 one. Keying on the name alone
	// collapses the pair onto whichever was parsed first, so the second
	// line's access-list disappears and the surviving row resolves its
	// typed ACL in the wrong namespace.
	family := "ipv4"
	if a.Ipv6.Data {
		family = "ipv6"
	}
	return "arista.eos.snmpCommunity/" + family + "/" + a.Name.Data, nil
}

func (a *mqlAristaEos) snmpCommunities() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	communities := eos.ParseSnmpCommunities(rc)
	res := make([]any, 0, len(communities))
	for _, c := range communities {
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
		res = append(res, mqlC)
	}
	return res, nil
}

func (a *mqlAristaEosSnmpCommunity) aclResource() (*mqlAristaEosAcl, error) {
	if a.Ipv6.Error != nil {
		return nil, a.Ipv6.Error
	}
	// The community line's `ipv6` keyword says which namespace its ACL is in.
	family := "ipv4"
	if a.Ipv6.Data {
		family = "ipv6"
	}
	mqlAcl, err := resolveAcl(a.MqlRuntime, a.cacheAcl, family)
	if err != nil {
		return nil, err
	}
	if mqlAcl == nil {
		a.AclResource.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlAcl, nil
}

// =====================================================================
// arista.eos.telnetService
// =====================================================================

func (a *mqlAristaEosTelnetService) id() (string, error) {
	return "arista.eos.telnetService", nil
}

func (a *mqlAristaEos) telnetService() (*mqlAristaEosTelnetService, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	t := eos.ParseTelnetService(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.telnetService", map[string]*llx.RawData{
		"configured":    llx.BoolData(t.Configured),
		"enabled":       llx.BoolData(t.Enabled),
		"idleTimeout":   llx.IntData(int64(t.IdleTimeout)),
		"sessionLimit":  llx.IntData(int64(t.SessionLimit)),
		"perHostLimit":  llx.IntData(int64(t.PerHostLimit)),
		"ipAccessGroup": llx.StringData(t.IPAccessGroup),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosTelnetService), nil
}

// =====================================================================
// arista.eos.passwordPolicy
// =====================================================================

func (a *mqlAristaEosPasswordPolicy) id() (string, error) {
	return "arista.eos.passwordPolicy", nil
}

func (a *mqlAristaEos) passwordPolicy() (*mqlAristaEosPasswordPolicy, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	p := eos.ParsePasswordPolicy(rc)

	res, err := CreateResource(a.MqlRuntime, "arista.eos.passwordPolicy", map[string]*llx.RawData{
		"lockoutFailure":             llx.IntData(int64(p.LockoutFailure)),
		"lockoutWindowSeconds":       llx.IntData(int64(p.LockoutWindowSeconds)),
		"lockoutDurationSeconds":     llx.IntData(int64(p.LockoutDurationSeconds)),
		"allowNopasswordRemoteLogin": llx.BoolData(p.AllowNopasswordRemoteLogin),
		"logOnFailure":               llx.BoolData(p.LogOnFailure),
		"logOnSuccess":               llx.BoolData(p.LogOnSuccess),
		"policyName":                 llx.StringData(p.PolicyName),
		"minimumLength":              llx.IntData(int64(p.MinimumLength)),
		"minimumDigits":              llx.IntData(int64(p.MinimumDigits)),
		"minimumUppercase":           llx.IntData(int64(p.MinimumUppercase)),
		"minimumLowercase":           llx.IntData(int64(p.MinimumLowercase)),
		"minimumSpecial":             llx.IntData(int64(p.MinimumSpecial)),
		"maximumRepetitive":          llx.IntData(int64(p.MaximumRepetitive)),
		"maximumSequential":          llx.IntData(int64(p.MaximumSequential)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAristaEosPasswordPolicy), nil
}

// =====================================================================
// arista.eos.ntp.authKeys (list) + arista.eos.ntp.authenticationEnabled
// =====================================================================

func (a *mqlAristaEosNtpAuthKey) id() (string, error) {
	if a.Id.Error != nil {
		return "", a.Id.Error
	}
	return "arista.eos.ntpAuthKey/" + strconv.FormatInt(a.Id.Data, 10), nil
}

func (a *mqlAristaEosNtp) authKeys() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	state := eos.ParseNtpAuth(rc)
	res := make([]any, 0, len(state.Keys))
	for _, k := range state.Keys {
		mqlK, err := CreateResource(a.MqlRuntime, "arista.eos.ntpAuthKey", map[string]*llx.RawData{
			"id":       llx.IntData(int64(k.ID)),
			"hashAlgo": llx.StringData(k.HashAlgo),
			"trusted":  llx.BoolData(k.Trusted),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlK)
	}
	return res, nil
}

func (a *mqlAristaEosNtp) authenticationEnabled() (bool, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	state := eos.ParseNtpAuth(rc)
	return state.AuthenticationEnabled, nil
}

// =====================================================================
// arista.eos.ntp.server (list) + serve state
// =====================================================================

type mqlAristaEosNtpServerInternal struct {
	cacheKeyID int
}

// id keys a server on VRF plus address, since the same time source can be
// reached through more than one routing instance.
func (a *mqlAristaEosNtpServer) id() (string, error) {
	if a.Address.Error != nil {
		return "", a.Address.Error
	}
	if a.Vrf.Error != nil {
		return "", a.Vrf.Error
	}
	return "arista.eos.ntp.server/" + a.Vrf.Data + "/" + a.Address.Data, nil
}

func (a *mqlAristaEosNtp) servers() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	servers := eos.ParseNtpServers(rc)

	res := make([]any, 0, len(servers))
	for _, s := range servers {
		mqlServer, err := CreateResource(a.MqlRuntime, "arista.eos.ntp.server", map[string]*llx.RawData{
			"address":        llx.StringData(s.Address),
			"vrf":            llx.StringData(s.VRF),
			"prefer":         llx.BoolData(s.Prefer),
			"iburst":         llx.BoolData(s.IBurst),
			"version":        llx.IntData(int64(s.Version)),
			"minPoll":        llx.IntData(int64(s.MinPoll)),
			"maxPoll":        llx.IntData(int64(s.MaxPoll)),
			"localInterface": llx.StringData(s.LocalInterface),
			"keyId":          llx.IntData(int64(s.KeyID)),
		})
		if err != nil {
			return nil, err
		}
		mqlServer.(*mqlAristaEosNtpServer).cacheKeyID = s.KeyID
		res = append(res, mqlServer)
	}
	return res, nil
}

// authKey resolves the server's key ID against the keys defined on the device.
// A server referencing a key ID with no matching `ntp authentication-key` line
// is a real misconfiguration, so that case is reported as a null key rather
// than an error, leaving keyId to show which key was asked for.
func (a *mqlAristaEosNtpServer) authKey() (*mqlAristaEosNtpAuthKey, error) {
	if a.cacheKeyID == 0 {
		a.AuthKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	state := eos.ParseNtpAuth(rc)

	for _, k := range state.Keys {
		if k.ID != a.cacheKeyID {
			continue
		}
		// Same field set and therefore the same __id as the entries built by
		// arista.eos.ntp.authKeys, so both paths share one cached resource.
		mqlKey, err := CreateResource(a.MqlRuntime, "arista.eos.ntpAuthKey", map[string]*llx.RawData{
			"id":       llx.IntData(int64(k.ID)),
			"hashAlgo": llx.StringData(k.HashAlgo),
			"trusted":  llx.BoolData(k.Trusted),
		})
		if err != nil {
			return nil, err
		}
		return mqlKey.(*mqlAristaEosNtpAuthKey), nil
	}

	a.AuthKey.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAristaEosNtp) serveEnabled() (bool, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	return eos.ParseNtpServeState(rc).Enabled, nil
}

func (a *mqlAristaEosNtp) serveAccessGroup() (string, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return "", err
	}
	return eos.ParseNtpServeState(rc).AccessGroup, nil
}

func (a *mqlAristaEosNtp) serveAccessGroupAcl() (*mqlAristaEosAcl, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// The serve access-group is reported without its address-family
	// qualifier, so the reference matches a list of either family by name.
	mqlAcl, err := resolveAcl(a.MqlRuntime, eos.ParseNtpServeState(rc).AccessGroup, "")
	if err != nil {
		return nil, err
	}
	if mqlAcl == nil {
		a.ServeAccessGroupAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlAcl, nil
}

// =====================================================================
// arista.eos.controlPlanePolicer
// =====================================================================

type mqlAristaEosControlPlanePolicerInternal struct {
	cacheIpAccessGroup  string
	cacheIp6AccessGroup string
}

func (a *mqlAristaEosControlPlanePolicer) id() (string, error) {
	return "arista.eos.controlPlanePolicer", nil
}

func (a *mqlAristaEos) controlPlanePolicer() (*mqlAristaEosControlPlanePolicer, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	c := eos.ParseControlPlanePolicer(rc)
	res, err := CreateResource(a.MqlRuntime, "arista.eos.controlPlanePolicer", map[string]*llx.RawData{
		"configured":     llx.BoolData(c.Configured),
		"policyApplied":  llx.BoolData(c.PolicyApplied),
		"policyName":     llx.StringData(c.PolicyName),
		"ipAccessGroup":  llx.StringData(c.IPAccessGroup),
		"ip6AccessGroup": llx.StringData(c.IP6AccessGroup),
	})
	if err != nil {
		return nil, err
	}
	mqlPolicer := res.(*mqlAristaEosControlPlanePolicer)
	mqlPolicer.cacheIpAccessGroup = c.IPAccessGroup
	mqlPolicer.cacheIp6AccessGroup = c.IP6AccessGroup
	return mqlPolicer, nil
}

func (a *mqlAristaEosControlPlanePolicer) ipAccessGroupAcl() (*mqlAristaEosAcl, error) {
	mqlAcl, err := resolveAcl(a.MqlRuntime, a.cacheIpAccessGroup, "ipv4")
	if err != nil {
		return nil, err
	}
	if mqlAcl == nil {
		a.IpAccessGroupAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlAcl, nil
}

func (a *mqlAristaEosControlPlanePolicer) ip6AccessGroupAcl() (*mqlAristaEosAcl, error) {
	mqlAcl, err := resolveAcl(a.MqlRuntime, a.cacheIp6AccessGroup, "ipv6")
	if err != nil {
		return nil, err
	}
	if mqlAcl == nil {
		a.Ip6AccessGroupAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlAcl, nil
}

// =====================================================================
// arista.eos.portSecurity (list)
// =====================================================================

func (a *mqlAristaEosPortSecurity) id() (string, error) {
	return "arista.eos.portSecurity/" + a.Interface.Data, a.Interface.Error
}

func (a *mqlAristaEos) portSecurity() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	configs := eos.ParsePortSecurity(rc)
	res := make([]any, 0, len(configs))
	for _, c := range configs {
		mqlC, err := CreateResource(a.MqlRuntime, "arista.eos.portSecurity", map[string]*llx.RawData{
			"interface":           llx.StringData(c.Interface),
			"enabled":             llx.BoolData(c.Enabled),
			"maximumMacAddresses": llx.IntData(int64(c.MaximumMacAddresses)),
			"violationAction":     llx.StringData(c.ViolationAction),
			"stickyLearning":      llx.BoolData(c.StickyLearning),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlC)
	}
	return res, nil
}

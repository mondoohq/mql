// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations backing the SMB server (LanmanServer) and client
// (LanmanWorkstation) configuration. For each role a value enforced through
// Group Policy (the policy path) overrides the value configured under the
// service's Parameters key; when neither is present the value is reported as
// null so an explicit 0 is distinguishable from "not configured".
const (
	smbServerParamsPath = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	smbServerPolicyPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer`
	smbServerServiceKey = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer`

	smbClientParamsPath = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`
	smbClientPolicyPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation`
	smbClientServiceKey = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation`

	smbV1DriverKey = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10`
)

// smbServiceDisabled is the registry Start value that marks a Windows service
// (here mrxsmb10 / LanmanServer / LanmanWorkstation) as disabled.
const smbServiceDisabled = 4

// smbStdout runs a PowerShell command and returns its stdout reader, failing
// on a non-zero exit status.
func smbStdout(conn shared.Connection, command string) (io.Reader, error) {
	executedCmd, err := conn.RunCommand(powershell.Encode(command))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to query SMB information: " + string(stderr))
	}
	return executedCmd.Stdout, nil
}

func (w *mqlWindowsSmb) shares() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	stdout, err := smbStdout(conn, windows.SMB_SHARES)
	if err != nil {
		return nil, err
	}
	shares, err := windows.ParseWindowsSmbShares(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(shares))
	for _, s := range shares {
		r, err := CreateResource(w.MqlRuntime, "windows.smb.share", map[string]*llx.RawData{
			"__id":        llx.StringData("windows.smb.share/" + s.ScopeName + "/" + s.Name),
			"name":        llx.StringData(s.Name),
			"path":        llx.StringData(s.Path),
			"description": llx.StringData(s.Description),
			"scopeName":   llx.StringData(s.ScopeName),
			"shareType":   llx.StringData(s.ShareType),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (w *mqlWindowsSmb) sessions() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	stdout, err := smbStdout(conn, windows.SMB_SESSIONS)
	if err != nil {
		return nil, err
	}
	sessions, err := windows.ParseWindowsSmbSessions(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(sessions))
	for _, s := range sessions {
		r, err := CreateResource(w.MqlRuntime, "windows.smb.session", map[string]*llx.RawData{
			// SessionId keeps concurrent sessions from the same client+user distinct.
			"__id":               llx.StringData(fmt.Sprintf("windows.smb.session/%s/%s/%d", s.ClientComputerName, s.ClientUserName, s.SessionId)),
			"clientComputerName": llx.StringData(s.ClientComputerName),
			"clientUserName":     llx.StringData(s.ClientUserName),
			"dialect":            llx.StringData(s.Dialect),
			"numOpens":           llx.IntData(s.NumOpens),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (w *mqlWindowsSmb) id() (string, error) {
	return "windows.smb", nil
}

func (c *mqlWindowsSmbServerConfiguration) id() (string, error) {
	return "windows.smb.serverConfiguration", nil
}

func (c *mqlWindowsSmbClientConfiguration) id() (string, error) {
	return "windows.smb.clientConfiguration", nil
}

// readSmbRegistryKey reads a single registry key and returns its values keyed
// by the lower-cased value name. A missing key yields an empty map rather than
// an error, so resolution can fall through to the next source (e.g. no Group
// Policy configured).
func (w *mqlWindowsSmb) readSmbRegistryKey(path string) (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, nil
		}
		return nil, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// smbResolveInt applies policy-wins-then-parameters precedence and returns a
// pointer to the effective DWORD, or nil when the value is configured nowhere.
// A nil result is rendered as MQL null so an explicit 0 stays distinguishable
// from "not configured".
func smbResolveInt(policy, params map[string]registry.RegistryKeyItem, name string) *int64 {
	key := strings.ToLower(name)
	if it, ok := policy[key]; ok {
		v := it.Value.Number
		return &v
	}
	if it, ok := params[key]; ok {
		v := it.Value.Number
		return &v
	}
	return nil
}

// smbResolveBool resolves a DWORD that toggles on the value 1 and returns a
// pointer to the boolean, or nil when the value is configured nowhere.
func smbResolveBool(policy, params map[string]registry.RegistryKeyItem, name string) *bool {
	v := smbResolveInt(policy, params, name)
	if v == nil {
		return nil
	}
	b := *v == 1
	return &b
}

// smbResolveMultiString resolves a REG_MULTI_SZ value with policy-wins-then-
// parameters precedence, returning an empty slice when neither key sets it.
func smbResolveMultiString(policy, params map[string]registry.RegistryKeyItem, name string) []string {
	key := strings.ToLower(name)
	if it, ok := policy[key]; ok {
		return it.Value.MultiString
	}
	if it, ok := params[key]; ok {
		return it.Value.MultiString
	}
	return []string{}
}

// smbServerConfig holds the resolved SMB server settings. Pointer fields are
// nil when the underlying registry value is not configured anywhere; this maps
// directly onto MQL null so an explicit 0 can be told apart from absent.
type smbServerConfig struct {
	requireSecuritySignature            *bool
	enableSecuritySignature             *bool
	smb1Enabled                         *bool
	restrictNullSessionAccess           *bool
	nullSessionPipes                    []string
	nullSessionShares                   []string
	autoDisconnectMinutes               *int64
	enableForcedLogoff                  *bool
	serverNameHardeningLevel            *int64
	enableAuthRateLimiter               *bool
	invalidAuthenticationDelayMs        *int64
	auditClientDoesNotSupportSigning    *bool
	auditClientDoesNotSupportEncryption *bool
	serviceStart                        *int64
}

// computeSmbServerConfig derives the effective SMB server configuration from the
// policy key, the service Parameters key, and the service root key. Policy
// values win over Parameters values. It is a pure function so the precedence and
// nullable behavior can be unit tested without a live registry.
func computeSmbServerConfig(policy, params, service map[string]registry.RegistryKeyItem) smbServerConfig {
	return smbServerConfig{
		requireSecuritySignature:            smbResolveBool(policy, params, "RequireSecuritySignature"),
		enableSecuritySignature:             smbResolveBool(policy, params, "EnableSecuritySignature"),
		smb1Enabled:                         smbResolveBool(policy, params, "SMB1"),
		restrictNullSessionAccess:           smbResolveBool(policy, params, "RestrictNullSessAccess"),
		nullSessionPipes:                    smbResolveMultiString(policy, params, "NullSessionPipes"),
		nullSessionShares:                   smbResolveMultiString(policy, params, "NullSessionShares"),
		autoDisconnectMinutes:               smbResolveInt(policy, params, "AutoDisconnect"),
		enableForcedLogoff:                  smbResolveBool(policy, params, "enableforcedlogoff"),
		serverNameHardeningLevel:            smbResolveInt(policy, params, "SMBServerNameHardeningLevel"),
		enableAuthRateLimiter:               smbResolveBool(policy, params, "EnableAuthRateLimiter"),
		invalidAuthenticationDelayMs:        smbResolveInt(policy, params, "InvalidAuthenticationDelayTimeInMs"),
		auditClientDoesNotSupportSigning:    smbResolveBool(policy, params, "AuditClientDoesNotSupportSigning"),
		auditClientDoesNotSupportEncryption: smbResolveBool(policy, params, "AuditClientDoesNotSupportEncryption"),
		// the service Start value lives only under the service root, never the
		// policy or Parameters key, so resolve it from a single source.
		serviceStart: smbResolveInt(service, service, "Start"),
	}
}

// smbClientConfig holds the resolved SMB client settings. Pointer fields are nil
// when the underlying registry value is not configured anywhere.
type smbClientConfig struct {
	requireSecuritySignature            *bool
	enableSecuritySignature             *bool
	enablePlainTextPassword             *bool
	allowInsecureGuestAuth              *bool
	requireEncryption                   *bool
	minSmb2Dialect                      *int64
	auditInsecureGuestLogon             *bool
	auditServerDoesNotSupportSigning    *bool
	auditServerDoesNotSupportEncryption *bool
	serviceStart                        *int64
}

// computeSmbClientConfig derives the effective SMB client configuration. Policy
// values win over Parameters values. Pure function for unit testing.
func computeSmbClientConfig(policy, params, service map[string]registry.RegistryKeyItem) smbClientConfig {
	return smbClientConfig{
		requireSecuritySignature:            smbResolveBool(policy, params, "RequireSecuritySignature"),
		enableSecuritySignature:             smbResolveBool(policy, params, "EnableSecuritySignature"),
		enablePlainTextPassword:             smbResolveBool(policy, params, "EnablePlainTextPassword"),
		allowInsecureGuestAuth:              smbResolveBool(policy, params, "AllowInsecureGuestAuth"),
		requireEncryption:                   smbResolveBool(policy, params, "RequireEncryption"),
		minSmb2Dialect:                      smbResolveInt(policy, params, "MinSmb2Dialect"),
		auditInsecureGuestLogon:             smbResolveBool(policy, params, "AuditInsecureGuestLogon"),
		auditServerDoesNotSupportSigning:    smbResolveBool(policy, params, "AuditServerDoesNotSupportSigning"),
		auditServerDoesNotSupportEncryption: smbResolveBool(policy, params, "AuditServerDoesNotSupportEncryption"),
		serviceStart:                        smbResolveInt(service, service, "Start"),
	}
}

// computeSmbV1Enabled reports whether the SMBv1 client driver (mrxsmb10) is
// enabled.
//
// The driver is enabled when its Start value is present and is anything other
// than 4 (disabled). An absent Start value means the driver is not installed:
// removing the SMB1Protocol optional feature deletes the mrxsmb10 service key
// outright, which is exactly the state a host that has had SMBv1 removed is
// in. Server 2019, 2022 and 2025 all ship that way, and all three report
// Get-WindowsOptionalFeature -FeatureName SMB1Protocol as Disabled while the
// key is gone; Server 2016 still carries the key with Start 2 and reports the
// feature as Enabled.
//
// Treating the absent key as enabled reported SMBv1 as on for every host that
// had properly removed it, so the field could not return false on any
// supported Windows Server and an audit requiring SMBv1 to be disabled failed
// on hosts that had disabled it.
func computeSmbV1Enabled(driver map[string]registry.RegistryKeyItem) bool {
	it, ok := driver["start"]
	if !ok {
		return false
	}
	return it.Value.Number != smbServiceDisabled
}

func (w *mqlWindowsSmb) serverConfiguration() (*mqlWindowsSmbServerConfiguration, error) {
	policy, err := w.readSmbRegistryKey(smbServerPolicyPath)
	if err != nil {
		return nil, err
	}
	params, err := w.readSmbRegistryKey(smbServerParamsPath)
	if err != nil {
		return nil, err
	}
	service, err := w.readSmbRegistryKey(smbServerServiceKey)
	if err != nil {
		return nil, err
	}

	cfg := computeSmbServerConfig(policy, params, service)

	o, err := CreateResource(w.MqlRuntime, "windows.smb.serverConfiguration", map[string]*llx.RawData{
		"__id":                                llx.StringData("windows.smb.serverConfiguration"),
		"requireSecuritySignature":            llx.BoolDataPtr(cfg.requireSecuritySignature),
		"enableSecuritySignature":             llx.BoolDataPtr(cfg.enableSecuritySignature),
		"smb1Enabled":                         llx.BoolDataPtr(cfg.smb1Enabled),
		"restrictNullSessionAccess":           llx.BoolDataPtr(cfg.restrictNullSessionAccess),
		"nullSessionPipes":                    llx.ArrayData(strSliceToAny(cfg.nullSessionPipes), types.String),
		"nullSessionShares":                   llx.ArrayData(strSliceToAny(cfg.nullSessionShares), types.String),
		"autoDisconnectMinutes":               llx.IntDataPtr(cfg.autoDisconnectMinutes),
		"enableForcedLogoff":                  llx.BoolDataPtr(cfg.enableForcedLogoff),
		"serverNameHardeningLevel":            llx.IntDataPtr(cfg.serverNameHardeningLevel),
		"enableAuthRateLimiter":               llx.BoolDataPtr(cfg.enableAuthRateLimiter),
		"invalidAuthenticationDelayMs":        llx.IntDataPtr(cfg.invalidAuthenticationDelayMs),
		"auditClientDoesNotSupportSigning":    llx.BoolDataPtr(cfg.auditClientDoesNotSupportSigning),
		"auditClientDoesNotSupportEncryption": llx.BoolDataPtr(cfg.auditClientDoesNotSupportEncryption),
		"serviceStart":                        llx.IntDataPtr(cfg.serviceStart),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsSmbServerConfiguration), nil
}

func (w *mqlWindowsSmb) clientConfiguration() (*mqlWindowsSmbClientConfiguration, error) {
	policy, err := w.readSmbRegistryKey(smbClientPolicyPath)
	if err != nil {
		return nil, err
	}
	params, err := w.readSmbRegistryKey(smbClientParamsPath)
	if err != nil {
		return nil, err
	}
	service, err := w.readSmbRegistryKey(smbClientServiceKey)
	if err != nil {
		return nil, err
	}

	cfg := computeSmbClientConfig(policy, params, service)

	o, err := CreateResource(w.MqlRuntime, "windows.smb.clientConfiguration", map[string]*llx.RawData{
		"__id":                                llx.StringData("windows.smb.clientConfiguration"),
		"requireSecuritySignature":            llx.BoolDataPtr(cfg.requireSecuritySignature),
		"enableSecuritySignature":             llx.BoolDataPtr(cfg.enableSecuritySignature),
		"enablePlainTextPassword":             llx.BoolDataPtr(cfg.enablePlainTextPassword),
		"allowInsecureGuestAuth":              llx.BoolDataPtr(cfg.allowInsecureGuestAuth),
		"requireEncryption":                   llx.BoolDataPtr(cfg.requireEncryption),
		"minSmb2Dialect":                      llx.IntDataPtr(cfg.minSmb2Dialect),
		"auditInsecureGuestLogon":             llx.BoolDataPtr(cfg.auditInsecureGuestLogon),
		"auditServerDoesNotSupportSigning":    llx.BoolDataPtr(cfg.auditServerDoesNotSupportSigning),
		"auditServerDoesNotSupportEncryption": llx.BoolDataPtr(cfg.auditServerDoesNotSupportEncryption),
		"serviceStart":                        llx.IntDataPtr(cfg.serviceStart),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsSmbClientConfiguration), nil
}

func (w *mqlWindowsSmb) smbv1Enabled() (bool, error) {
	driver, err := w.readSmbRegistryKey(smbV1DriverKey)
	if err != nil {
		return false, err
	}
	return computeSmbV1Enabled(driver), nil
}

func (w *mqlWindowsSmb) connections() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	stdout, err := smbStdout(conn, windows.SMB_CONNECTIONS)
	if err != nil {
		return nil, err
	}
	connections, err := windows.ParseWindowsSmbConnections(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(connections))
	for _, c := range connections {
		r, err := CreateResource(w.MqlRuntime, "windows.smb.connection", map[string]*llx.RawData{
			// Get-SmbConnection exposes no unique per-connection id, so key on the
			// stable connection attributes (server + share + user + dialect)
			// rather than the list index — identity then survives output-order
			// changes between refreshes. These four fields together identify a
			// distinct client->server SMB connection in practice.
			"__id":       llx.StringData(fmt.Sprintf("windows.smb.connection/%s/%s/%s/%s", c.ServerName, c.ShareName, c.UserName, c.Dialect)),
			"serverName": llx.StringData(c.ServerName),
			"shareName":  llx.StringData(c.ShareName),
			"userName":   llx.StringData(c.UserName),
			"dialect":    llx.StringData(c.Dialect),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// windows.smb.serverConfiguration and windows.smb.clientConfiguration are both
// a field path on windows.smb and a resource name in their own right. The
// compiler resolves the longest matching resource name before it considers a
// field, so the dotted form instantiates the sub-resource directly and the
// parent's accessor never runs. Every field on these resources is a plain
// schema field that only the parent populates, so none is ever set: the query
// reports null for each one with "provider returned no data and no error", and
// the values convert as primitives carrying no type information.
//
// That is worse than an error, because a check reading "SMB signing is
// required" off a null does not fail on a host that does not require it.
//
// Delegating to the parent's accessor fills the resource in. The block form
// `windows.smb { serverConfiguration { ... } }` binds the field instead of
// resolving a resource name and was never affected. When the resource is
// created normally by the parent it carries an __id and this is a no-op.
func initWindowsSmbChild[T plugin.Resource](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	get func(*mqlWindowsSmb) *plugin.TValue[T],
) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "windows.smb", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := get(parent.(*mqlWindowsSmb))
	if v.Error != nil {
		return nil, nil, v.Error
	}
	return args, v.Data, nil
}

func initWindowsSmbServerConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSmbChild(runtime, args, (*mqlWindowsSmb).GetServerConfiguration)
}

func initWindowsSmbClientConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsSmbChild(runtime, args, (*mqlWindowsSmb).GetClientConfiguration)
}

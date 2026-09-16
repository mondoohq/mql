// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

func (r *mqlWindowsRdp) id() (string, error) {
	return "windows.rdp", nil
}

// Registry locations that back the Remote Desktop / Terminal Services policy.
// A value enforced through Group Policy (the policy path) overrides the value
// configured on the per-listener connection; when neither is present the
// documented Windows default applies.
const (
	rdpPolicyPath         = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
	rdpPolicyClientPath   = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client`
	rdpWinStationsPath    = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	rdpTerminalServerPath = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server`
)

// rdpSource selects which non-policy key holds the effective value for a
// setting. Most Terminal Services settings are per-listener and live under
// WinStations\RDP-Tcp; a few are machine-wide and live directly under the
// Terminal Server key.
type rdpSource int

const (
	rdpWinStations rdpSource = iota
	rdpTerminalServer
)

type mqlWindowsRdpInternal struct {
	lock   sync.Mutex
	loaded bool
	// each map is name (lower-cased) -> DWORD value for one registry key
	policy       map[string]int64
	policyClient map[string]int64
	winSta       map[string]int64
	tsRoot       map[string]int64
	loadErr      error
}

// readRdpKey reads a single registry key and returns its numeric values keyed
// by the lower-cased value name. A missing key yields an empty map rather than
// an error, so the resolution can fall through to the next source.
func (r *mqlWindowsRdp) readRdpKey(path string) (map[string]int64, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. no Group Policy configured); treat it
		// as empty so resolution falls through to the next source or the default
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]int64{}, nil
		}
		return nil, err
	}

	res := make(map[string]int64, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i].Value.Number
	}
	return res, nil
}

// load reads the policy and effective registry keys exactly once and caches
// them so every field shares a single set of registry reads.
func (r *mqlWindowsRdp) load() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.loaded || r.loadErr != nil {
		return r.loadErr
	}

	policy, err := r.readRdpKey(rdpPolicyPath)
	if err != nil {
		r.loadErr = err
		return err
	}
	policyClient, err := r.readRdpKey(rdpPolicyClientPath)
	if err != nil {
		r.loadErr = err
		return err
	}
	winSta, err := r.readRdpKey(rdpWinStationsPath)
	if err != nil {
		r.loadErr = err
		return err
	}
	tsRoot, err := r.readRdpKey(rdpTerminalServerPath)
	if err != nil {
		r.loadErr = err
		return err
	}

	r.policy = policy
	r.policyClient = policyClient
	r.winSta = winSta
	r.tsRoot = tsRoot
	r.loaded = true
	return nil
}

// resolveRdpValue applies the policy-wins-then-default precedence to a single
// setting. It is split out from the resource so the precedence can be unit
// tested without a live registry.
func resolveRdpValue(policy, effective map[string]int64, name string, def int64) int64 {
	key := strings.ToLower(name)
	if v, ok := policy[key]; ok {
		return v
	}
	if v, ok := effective[key]; ok {
		return v
	}
	return def
}

// resolve returns the effective DWORD for a setting: the Group Policy value if
// set, otherwise the per-listener / machine-wide value, otherwise the default.
func (r *mqlWindowsRdp) resolve(name string, src rdpSource, def int64) (int64, error) {
	if err := r.load(); err != nil {
		return 0, err
	}

	effective := r.winSta
	if src == rdpTerminalServer {
		effective = r.tsRoot
	}
	return resolveRdpValue(r.policy, effective, name, def), nil
}

// resolveBool resolves a DWORD setting that toggles on the value 1.
func (r *mqlWindowsRdp) resolveBool(name string, src rdpSource, def int64) (bool, error) {
	v, err := r.resolve(name, src, def)
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

func (r *mqlWindowsRdp) networkLevelAuthentication() (bool, error) {
	// modern Windows requires NLA by default
	return r.resolveBool("UserAuthentication", rdpWinStations, 1)
}

func (r *mqlWindowsRdp) alwaysPromptForPassword() (bool, error) {
	return r.resolveBool("fPromptForPassword", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) driveRedirectionDisabled() (bool, error) {
	return r.resolveBool("fDisableCdm", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) comPortRedirectionDisabled() (bool, error) {
	return r.resolveBool("fDisableCcm", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) lptPortRedirectionDisabled() (bool, error) {
	return r.resolveBool("fDisableLPT", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) pnpDeviceRedirectionDisabled() (bool, error) {
	return r.resolveBool("fDisablePNPRedir", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) passwordSavingDisabled() (bool, error) {
	// Policy-only setting. Microsoft documents the unconfigured behavior as
	// "the user will be able to save passwords using Remote Desktop
	// Connection", so saving is allowed and this reports false. Defaulting to
	// true claimed the hardened state on every host that had not set the
	// policy, which is the direction that makes a check pass without reading
	// anything.
	return r.resolveBool("DisablePasswordSaving", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) deleteTempDirsOnExit() (bool, error) {
	// per-session temporary folders are deleted on exit by default
	return r.resolveBool("DeleteTempDirsOnExit", rdpTerminalServer, 1)
}

func (r *mqlWindowsRdp) secureRpcRequired() (bool, error) {
	// RPC traffic is encrypted by default
	return r.resolveBool("fEncryptRPCTraffic", rdpWinStations, 1)
}

func (r *mqlWindowsRdp) securityLayer() (int64, error) {
	// 1 == Negotiate, the Windows default
	return r.resolve("SecurityLayer", rdpWinStations, 1)
}

func (r *mqlWindowsRdp) minEncryptionLevel() (int64, error) {
	// 2 == Client Compatible, the Windows default
	return r.resolve("MinEncryptionLevel", rdpWinStations, 2)
}

func (r *mqlWindowsRdp) maxIdleTimeMs() (int64, error) {
	// 0 == no idle time limit
	return r.resolve("MaxIdleTime", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) maxDisconnectionTimeMs() (int64, error) {
	// 0 == disconnected sessions are never ended
	return r.resolve("MaxDisconnectionTime", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) connectionsDenied() (bool, error) {
	// Remote Desktop is denied by default until an administrator enables it
	return r.resolveBool("fDenyTSConnections", rdpTerminalServer, 1)
}

func (r *mqlWindowsRdp) singleSessionPerUser() (bool, error) {
	// each user is restricted to a single session by default
	return r.resolveBool("fSingleSessionPerUser", rdpTerminalServer, 1)
}

func (r *mqlWindowsRdp) perSessionTempDirsUsed() (bool, error) {
	// per-session temporary folders are used by default
	return r.resolveBool("PerSessionTempDir", rdpTerminalServer, 1)
}

func (r *mqlWindowsRdp) solicitedRemoteAssistanceAllowed() (bool, error) {
	// Remote Assistance is machine-wide, not per-listener: the policy writes
	// fAllowToGetHelp under the Terminal Services policy key and enabling it
	// locally writes it under the Terminal Server key. Neither is under
	// WinStations\RDP-Tcp, so looking there missed a host that had turned
	// Remote Assistance on outside Group Policy and reported it as off.
	return r.resolveBool("fAllowToGetHelp", rdpTerminalServer, 0)
}

func (r *mqlWindowsRdp) offerRemoteAssistanceAllowed() (bool, error) {
	// machine-wide for the same reason as fAllowToGetHelp; off when nothing
	// sets it
	return r.resolveBool("fAllowUnsolicited", rdpTerminalServer, 0)
}

func (r *mqlWindowsRdp) webAuthnRedirectionDisabled() (bool, error) {
	// WebAuthn redirection is allowed (not disabled) when not configured
	return r.resolveBool("fDisableWebAuthn", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) locationRedirectionDisabled() (bool, error) {
	// location redirection is allowed (not disabled) when not configured
	return r.resolveBool("fDisableLocationRedir", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) uiAutomationRedirectionEnabled() (bool, error) {
	// UI Automation redirection is off when not configured
	return r.resolveBool("EnableUiaRedirection", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) clipboardServerToClientLevel() (int64, error) {
	// 3 == unrestricted server-to-client clipboard, the behavior when the
	// "Restrict clipboard transfer from server to client" policy is not set
	return r.resolve("SCClipLevel", rdpWinStations, 3)
}

func (r *mqlWindowsRdp) endSessionWhenTimeLimitReached() (bool, error) {
	// when not configured, a session that hits a time limit is disconnected
	// rather than ended, so the setting defaults to off
	return r.resolveBool("fResetBroken", rdpWinStations, 0)
}

func (r *mqlWindowsRdp) cloudClipboardIntegrationDisabled() (bool, error) {
	if err := r.load(); err != nil {
		return false, err
	}
	// Group Policy-only setting under the Terminal Services\Client subkey; cloud
	// clipboard integration is enabled (not disabled) when it is not configured
	return resolveRdpValue(r.policyClient, nil, "DisableCloudClipboardIntegration", 0) == 1, nil
}

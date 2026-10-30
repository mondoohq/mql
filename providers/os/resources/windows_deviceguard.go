// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry location that backs windows.deviceGuard. These are GPO-only DWORD
// values; every one is optional, so an absent value means "not configured"
// rather than 0.
const deviceGuardPolicyKey = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`

func (r *mqlWindowsDeviceGuard) id() (string, error) {
	return "windows.deviceGuard", nil
}

// readDeviceGuardKey reads the Device Guard policy key and returns its values as
// a name->item map (lower-cased keys). A missing key yields an empty map rather
// than an error, so every field falls through to null ("not configured").
func (w *mqlWindows) readDeviceGuardKey(path string) (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(w.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. no Group Policy configured); treat it
		// as empty so every value resolves to null
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

// regIntPtr returns a pointer to the numeric value of a registry item, or nil
// when the value name is absent. The pointer makes "not configured" (nil)
// distinguishable from an explicit 0.
func regIntPtr(items map[string]registry.RegistryKeyItem, name string) *int64 {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.Number
		return &v
	}
	return nil
}

// deviceGuardValues holds the extracted Device Guard DWORDs as nullable
// pointers. A nil pointer means the value name was absent from the registry
// ("not configured"), which the resource surfaces as a null field rather than
// 0. On/off settings are bools; graded settings are int64s.
type deviceGuardValues struct {
	virtualizationBasedSecurityEnabled *bool
	requirePlatformSecurityFeatures    *int64
	hypervisorEnforcedCodeIntegrity    *int64
	hvciMatRequired                    *bool
	credentialGuardConfig              *int64
	systemGuardLaunch                  *bool
	kernelShadowStacksLaunch           *int64
}

// computeDeviceGuard extracts the Device Guard policy values from the raw
// registry items. Each field is nil when its value name is absent, so callers
// can tell "not configured" from an explicit 0. Pure function for unit testing.
func computeDeviceGuard(items map[string]registry.RegistryKeyItem) deviceGuardValues {
	return deviceGuardValues{
		virtualizationBasedSecurityEnabled: regBoolPtr(items, "EnableVirtualizationBasedSecurity"),
		requirePlatformSecurityFeatures:    regIntPtr(items, "RequirePlatformSecurityFeatures"),
		hypervisorEnforcedCodeIntegrity:    regIntPtr(items, "HypervisorEnforcedCodeIntegrity"),
		hvciMatRequired:                    regBoolPtr(items, "HVCIMATRequired"),
		credentialGuardConfig:              regIntPtr(items, "LsaCfgFlags"),
		// ConfigureSystemGuardLaunch is an enumeration, not a toggle: 0 leaves
		// Secure Launch unmanaged, 1 enables it, 2 disables it. A non-zero test
		// read the disabling value as enabled.
		systemGuardLaunch:        regEnumBoolPtr(items, "ConfigureSystemGuardLaunch", 1, 2),
		kernelShadowStacksLaunch: regIntPtr(items, "ConfigureKernelShadowStacksLaunch"),
	}
}

func (w *mqlWindows) deviceGuard() (*mqlWindowsDeviceGuard, error) {
	items, err := w.readDeviceGuardKey(deviceGuardPolicyKey)
	if err != nil {
		return nil, err
	}

	v := computeDeviceGuard(items)

	o, err := CreateResource(w.MqlRuntime, "windows.deviceGuard", map[string]*llx.RawData{
		"__id":                               llx.StringData("windows.deviceGuard"),
		"virtualizationBasedSecurityEnabled": llx.BoolDataPtr(v.virtualizationBasedSecurityEnabled),
		"requirePlatformSecurityFeatures":    llx.IntDataPtr(v.requirePlatformSecurityFeatures),
		"hypervisorEnforcedCodeIntegrity":    llx.IntDataPtr(v.hypervisorEnforcedCodeIntegrity),
		"hvciMatRequired":                    llx.BoolDataPtr(v.hvciMatRequired),
		"credentialGuardConfig":              llx.IntDataPtr(v.credentialGuardConfig),
		"systemGuardLaunch":                  llx.BoolDataPtr(v.systemGuardLaunch),
		"kernelShadowStacksLaunch":           llx.IntDataPtr(v.kernelShadowStacksLaunch),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDeviceGuard), nil
}

// mqlWindowsDeviceGuardInternal memoizes the Win32_DeviceGuard read. Six
// fields are backed by it, and without the memo a policy that reads the
// configured services and the running services and the VBS status would pay
// three PowerShell processes on the remote host to answer one question.
type mqlWindowsDeviceGuardInternal struct {
	wmiLock    sync.Mutex
	wmiFetched bool
	wmiData    *windows.DeviceGuardStatus
	wmiErr     error
}

// deviceGuardStatus returns the Win32_DeviceGuard reading, running the
// collection at most once per resource. The error is memoized alongside the
// data so a host that cannot answer (no elevation, or a build without the
// class) reports the same failure to every field instead of retrying per
// accessor.
func (r *mqlWindowsDeviceGuard) deviceGuardStatus() (*windows.DeviceGuardStatus, error) {
	// The guard is read under the lock, never before it: a fast path that
	// tests the flag first has no happens-before edge to the write, so a
	// racing accessor could observe the flag set and the pointer still nil.
	r.wmiLock.Lock()
	defer r.wmiLock.Unlock()
	if r.wmiFetched {
		return r.wmiData, r.wmiErr
	}
	r.wmiFetched = true

	r.wmiData, r.wmiErr = readDeviceGuardWMI(r.MqlRuntime.Connection)
	return r.wmiData, r.wmiErr
}

// readDeviceGuardWMI runs the Win32_DeviceGuard collection script. A host that
// cannot be asked yields an error rather than a zero reading: an empty
// SecurityServicesRunning is the answer a host with nothing running gives, so
// letting a failure produce one would report Credential Guard as absent on a
// machine running it.
func readDeviceGuardWMI(connection any) (*windows.DeviceGuardStatus, error) {
	conn, ok := connection.(shared.Connection)
	if !ok {
		return nil, errors.New("windows.deviceGuard running state is not supported on this connection")
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("windows.deviceGuard running state requires a connection that can run commands")
	}

	executedCmd, err := conn.RunCommand(powershell.Encode(windows.PSGetDeviceGuard))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to read Win32_DeviceGuard, an elevated session is required: " + string(stderr))
	}
	return windows.ParseDeviceGuardStatus(executedCmd.Stdout)
}

// intList converts a Win32_DeviceGuard value list for MQL. A nil list means
// the property was absent, which has to reach the runtime as null: returning
// (nil, nil) renders an empty array, and an empty array reads as a real "no
// services" answer.
func intList(values windows.PSInt64Array, field *plugin.TValue[[]any]) ([]any, error) {
	if values == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := make([]any, 0, len(values))
	for _, v := range values {
		res = append(res, v)
	}
	return res, nil
}

func (r *mqlWindowsDeviceGuard) securityServicesConfigured() ([]any, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return nil, err
	}
	return intList(dg.SecurityServicesConfigured, &r.SecurityServicesConfigured)
}

func (r *mqlWindowsDeviceGuard) securityServicesRunning() ([]any, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return nil, err
	}
	return intList(dg.SecurityServicesRunning, &r.SecurityServicesRunning)
}

func (r *mqlWindowsDeviceGuard) availableSecurityProperties() ([]any, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return nil, err
	}
	return intList(dg.AvailableSecurityProperties, &r.AvailableSecurityProperties)
}

// intValue returns a nullable Win32_DeviceGuard scalar. A nil pointer means
// the property was absent, so the field reads null rather than 0, which would
// claim "off" on a host that never reported a status.
func intValue(value *int64, field *plugin.TValue[int64]) (int64, error) {
	if value == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *value, nil
}

func (r *mqlWindowsDeviceGuard) codeIntegrityPolicyEnforcementStatus() (int64, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return 0, err
	}
	return intValue(dg.CodeIntegrityPolicyEnforcementStatus, &r.CodeIntegrityPolicyEnforcementStatus)
}

func (r *mqlWindowsDeviceGuard) usermodeCodeIntegrityPolicyEnforcementStatus() (int64, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return 0, err
	}
	return intValue(dg.UsermodeCodeIntegrityPolicyEnforcementStatus, &r.UsermodeCodeIntegrityPolicyEnforcementStatus)
}

func (r *mqlWindowsDeviceGuard) virtualizationBasedSecurityStatus() (int64, error) {
	dg, err := r.deviceGuardStatus()
	if err != nil {
		return 0, err
	}
	return intValue(dg.VirtualizationBasedSecurityStatus, &r.VirtualizationBasedSecurityStatus)
}

// windows.deviceGuard is reachable by a dotted path that is also its own
// registered resource name: the field `deviceGuard` on `windows` and the
// resource `windows.deviceGuard` occupy the same path. The compiler resolves
// the longest matching resource name before it considers a field, so
// `windows.deviceGuard.credentialGuardConfig` instantiates the resource
// directly and the parent's deviceGuard() accessor never runs. The policy
// fields are plain schema fields that only that accessor populates, so every
// one stays unset, reports "provider returned no data and no error", and then
// converts as a primitive carrying no type information.
//
// The result reads null, which is worse than an error: `null && null`
// evaluates to true in MQL, so a check written in the dotted form passes on a
// host that was never hardened.
//
// Delegating to the parent's accessor fills the resource in. The block form
// `windows { deviceGuard { ... } }` binds the field rather than resolving a
// resource name and was never affected. When the parent creates the resource
// normally it carries an __id and this is a no-op.
func initWindowsDeviceGuard(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}

	parent, err := CreateResource(runtime, "windows", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlWindows).GetDeviceGuard()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	return args, v.Data, nil
}

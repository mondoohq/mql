// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// This implements the Windows Security Center API
// PowerShell does not offer a native method to gather this information, therefore we need
// to write a C# script that is encapsulated in PowerShell
//
// https://learn.microsoft.com/en-us/windows/win32/api/Wscapi/ne-wscapi-wsc_security_provider
// https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/WebSecurityCenter

// https://learn.microsoft.com/en-us/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider_health
var securityHealthStatusValues = map[int64]string{
	0: "GOOD",
	1: "NOT_MONITORED",
	2: "POOR",
	3: "SNOOZE",
}

// securityHealthUnknown is the name reported for a WSC_SECURITY_PROVIDER_HEALTH
// value outside the documented set. It is deliberately distinct from "GOOD" so
// a value Windows adds later cannot be read as an all-clear.
const securityHealthUnknown = "UNKNOWN"

// The available security provider are documented in
// https://learn.microsoft.com/en-us/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider
//
// Every failure exits non-zero rather than emitting a partial object. The
// health values are an enum whose zero value is GOOD, so an object that is
// missing a provider decodes to a clean bill of health for it, and an empty
// object decodes to a clean bill of health for the whole machine. Windows
// Server has no Security Center at all (wscapi.dll is not present), which is
// exactly the case that has to report a failure rather than GOOD.
//
// The C# wrapper checks the HRESULT before returning outValue for the same
// reason: WscGetSecurityProviderHealth leaves outValue untouched when it
// fails, and the caller cannot tell that from a real reading.
const windowsSecurityHealthScript = `
$ErrorActionPreference = 'Stop'

$MethodDefinition = @"
[DllImport("wscapi.dll",CharSet = CharSet.Unicode, SetLastError = true)]
private static extern int WscGetSecurityProviderHealth(int inValue, ref int outValue);

public static int GetSecurityProviderHealth(int inValue)
{
  int outValue = -1;
  int result = WscGetSecurityProviderHealth(inValue, ref outValue);
  if (result != 0)
  {
    throw new System.Exception("WscGetSecurityProviderHealth returned 0x" + result.ToString("X8"));
  }
  return outValue;
}
"@

try {
  $mondoo_wscapi = Add-Type -MemberDefinition $MethodDefinition -Name 'mondoo_wscapi' -Namespace 'Win32' -PassThru
} catch {
  [Console]::Error.WriteLine("could not compile the Windows Security Center wrapper: " + $_.Exception.Message)
  exit 1
}

$WSC_SECURITY_PROVIDER_FIREWALL = 1
$WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 2
$WSC_SECURITY_PROVIDER_ANTIVIRUS = 4
$WSC_SECURITY_PROVIDER_ANTISPYWARE = 8
$WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 16
$WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 32
$WSC_SECURITY_PROVIDER_SERVICE = 64

try {
  $securityProviderHealth = [PSCustomObject]@{
    firewall              = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_FIREWALL)
    autoUpdate            = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS)
    antiVirus             = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_ANTIVIRUS)
    antiSpyware           = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_ANTISPYWARE)
    internetSettings      = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_INTERNET_SETTINGS)
    uac                   = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL)
    securityCenterService = $mondoo_wscapi::GetSecurityProviderHealth($WSC_SECURITY_PROVIDER_SERVICE)
  }
} catch {
  [Console]::Error.WriteLine("could not read the Windows Security Center provider health: " + $_.Exception.Message)
  exit 1
}

ConvertTo-Json -Depth 3 -Compress $securityProviderHealth
`

// powershellSecurityHealthStatus is the raw reading. Every provider is a
// pointer so a property the script did not emit stays distinguishable from an
// explicit 0, which is the GOOD status.
type powershellSecurityHealthStatus struct {
	Firewall              *int64 `json:"firewall"`
	AutoUpdate            *int64 `json:"autoUpdate"`
	AntiVirus             *int64 `json:"antiVirus"`
	AntiSpyware           *int64 `json:"antiSpyware"`
	InternetSettings      *int64 `json:"internetSettings"`
	Uac                   *int64 `json:"uac"`
	SecurityCenterService *int64 `json:"securityCenterService"`
}

type windowsSecurityHealth struct {
	Firewall              statusCode
	AutoUpdate            statusCode
	AntiVirus             statusCode
	AntiSpyware           statusCode
	InternetSettings      statusCode
	Uac                   statusCode
	SecurityCenterService statusCode
}

func GetSecurityProviderHealth(p shared.Connection) (*windowsSecurityHealth, error) {
	c, err := p.RunCommand(powershell.Encode(windowsSecurityHealthScript))
	if err != nil {
		return nil, err
	}

	if c.ExitStatus != 0 {
		stderr, err := io.ReadAll(c.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve security health: " + strings.TrimSpace(string(stderr)))
	}

	return ParseSecurityProviderHealth(c.Stdout)
}

// securityHealthStatus pairs a raw WSC_SECURITY_PROVIDER_HEALTH value with its
// name. A code outside the documented set reads UNKNOWN rather than the empty
// string, so an unrecognized reading is visible in a query result.
func securityHealthStatus(code int64) statusCode {
	text, ok := securityHealthStatusValues[code]
	if !ok {
		text = securityHealthUnknown
	}
	return statusCode{Code: code, Text: text}
}

// ParseSecurityProviderHealth decodes the JSON emitted by
// windowsSecurityHealthScript. Output that is empty, or that omits any of the
// seven providers, is an error rather than a partial reading: the zero value
// of the health enum is GOOD, so a missing provider would otherwise be
// reported as healthy on a host where nothing was read at all.
func ParseSecurityProviderHealth(r io.Reader) (*windowsSecurityHealth, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("the Windows Security Center API returned no data; it is not available on this host")
	}

	var status powershellSecurityHealthStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}

	// Ordered so the error message is stable.
	providers := []struct {
		name  string
		value *int64
	}{
		{"firewall", status.Firewall},
		{"autoUpdate", status.AutoUpdate},
		{"antiVirus", status.AntiVirus},
		{"antiSpyware", status.AntiSpyware},
		{"internetSettings", status.InternetSettings},
		{"uac", status.Uac},
		{"securityCenterService", status.SecurityCenterService},
	}

	var missing []string
	for _, p := range providers {
		if p.value == nil {
			missing = append(missing, p.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the Windows Security Center API did not report %s; the reading cannot be trusted",
			strings.Join(missing, ", "))
	}

	return &windowsSecurityHealth{
		Firewall:              securityHealthStatus(*status.Firewall),
		AutoUpdate:            securityHealthStatus(*status.AutoUpdate),
		AntiVirus:             securityHealthStatus(*status.AntiVirus),
		AntiSpyware:           securityHealthStatus(*status.AntiSpyware),
		InternetSettings:      securityHealthStatus(*status.InternetSettings),
		Uac:                   securityHealthStatus(*status.Uac),
		SecurityCenterService: securityHealthStatus(*status.SecurityCenterService),
	}, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windowsadsid

import (
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// adSidScript resolves the AD computer object's SID for the current Windows host.
//
// It deliberately uses Win32_ComputerSystem.Domain (set by the host's domain join
// state) rather than $env:USERDOMAIN, because the cnspec service runs as
// LocalSystem and $env:USERDOMAIN can be unset or report the local computer name
// in that context. The PartOfDomain check short-circuits non-domain-joined hosts
// (workgroup, standalone) so the detector returns an empty string instead of
// translating a name that does not resolve and raising an exception.
const adSidScript = `
$ErrorActionPreference = 'SilentlyContinue'
$sys = Get-CimInstance Win32_ComputerSystem
if ($null -eq $sys -or -not $sys.PartOfDomain) { return }
$account = $sys.Domain + '\' + $env:COMPUTERNAME + '$'
try {
  (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
  return
}
`

// sidPattern validates a SID of the form S-R-I-S[-S...] (uppercase, dash separated).
// AD computer SIDs are typically S-1-5-21-<sub1>-<sub2>-<sub3>-<RID>.
var sidPattern = regexp.MustCompile(`^S-\d+-\d+(?:-\d+)+$`)

// WindowsADSID returns the AD computer object SID for a domain-joined Windows host.
// Returns ("", nil) on non-Windows platforms, on workgroup/standalone Windows
// hosts, or when the SID cannot be resolved — the detector is best-effort and
// callers should fall through to other detectors when the result is empty.
func WindowsADSID(conn shared.Connection, pf *inventory.Platform) (string, error) {
	if pf == nil || !pf.IsFamily(inventory.FAMILY_WINDOWS) {
		return "", nil
	}

	cmd, err := conn.RunCommand(powershell.Encode(adSidScript))
	if err != nil {
		return "", err
	}

	if cmd.ExitStatus != 0 {
		// non-zero exit is treated as "not detected"; cnspec falls through to other detectors.
		return "", nil
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return parseSIDOutput(string(data)), nil
}

// parseSIDOutput trims whitespace from the PowerShell stdout and validates that
// the result is a SID. Returns the SID on success or an empty string when the
// output is empty, only whitespace, or not a SID (e.g. an error message that
// reached stdout). Exposed for tests.
func parseSIDOutput(out string) string {
	sid := strings.TrimSpace(out)
	if sid == "" {
		return ""
	}
	if !sidPattern.MatchString(sid) {
		return ""
	}
	return sid
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// ActiveDirectoryInfo is the machine's Active Directory domain membership, as
// the local security authority reports it.
type ActiveDirectoryInfo struct {
	// Member is whether the machine is a member of an Active Directory domain,
	// which includes a domain controller.
	Member bool
	// Domain is the DNS name of the domain, or its NetBIOS name for a domain
	// that has no DNS name.
	Domain string
	// Forest is the DNS name of the forest the domain belongs to, "" when it
	// was not read.
	Forest string
}

// DSROLE_MACHINE_ROLE values of a domain member, as returned by
// DsRoleGetPrimaryDomainInformation and Win32_ComputerSystem.DomainRole alike.
// 0 and 2 are a standalone workstation and server.
// https://learn.microsoft.com/en-us/windows/win32/api/dsrole/ne-dsrole-dsrole_machine_role
const (
	dsRoleMemberWorkstation       = 1
	dsRoleMemberServer            = 3
	dsRoleBackupDomainController  = 4
	dsRolePrimaryDomainController = 5
)

// domainMemberRole reports whether a DSROLE_MACHINE_ROLE value means the
// machine belongs to a domain. Domain controllers belong to the domain they
// serve. A value outside the documented range is not a membership.
func domainMemberRole(role int) bool {
	switch role {
	case dsRoleMemberWorkstation, dsRoleMemberServer, dsRoleBackupDomainController, dsRolePrimaryDomainController:
		return true
	}
	return false
}

// activeDirectoryInfoFromRole builds the membership from the fields of
// DSROLE_PRIMARY_DOMAIN_INFO_BASIC. The names are only reported for a member:
// a workgroup machine reports its workgroup as the flat name, which is not a
// domain.
func activeDirectoryInfoFromRole(role int, flat string, dns string, forest string) *ActiveDirectoryInfo {
	if !domainMemberRole(role) {
		return &ActiveDirectoryInfo{}
	}
	domain := strings.TrimSpace(dns)
	if domain == "" {
		domain = strings.TrimSpace(flat)
	}
	return &ActiveDirectoryInfo{
		Member: true,
		Domain: strings.ToLower(domain),
		Forest: strings.ToLower(strings.TrimSpace(forest)),
	}
}

// activeDirectoryRaw is the output of activeDirectoryScript.
type activeDirectoryRaw struct {
	DomainRole *int    `json:"DomainRole"`
	Flat       *string `json:"Flat"`
	Dns        *string `json:"Dns"`
	Forest     *string `json:"Forest"`
}

// ParseActiveDirectoryInfo parses the output of the Active Directory query.
// Output without a machine role is an error, not a non-member: the query did
// not answer, so membership is unknown.
func ParseActiveDirectoryInfo(r io.Reader) (*ActiveDirectoryInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("no Active Directory membership information returned")
	}
	var raw activeDirectoryRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.DomainRole == nil {
		return nil, errors.New("no machine role in the Active Directory membership information")
	}
	str := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	return activeDirectoryInfoFromRole(*raw.DomainRole, str(raw.Flat), str(raw.Dns), str(raw.Forest)), nil
}

// activeDirectoryScript reads the machine's domain membership. It asks
// Win32_ComputerSystem for the machine role and domain, which is answered
// from the local security authority without contacting a domain controller.
// Only a domain member then asks DsRoleGetPrimaryDomainInformation for the
// forest name, which WMI does not expose; that call is local too. It needs a
// compiled P/Invoke wrapper, so a machine that is not a member never pays for
// it, and a host where compiling is not allowed still reports the domain, only
// without the forest.
const activeDirectoryScript = `$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$r = [ordered]@{ DomainRole = [int]$cs.DomainRole; Flat = $null; Dns = $null; Forest = $null }
if ($cs.PartOfDomain) {
  $r.Dns = [string]$cs.Domain
  try {
    $d = Add-Type -Name DsRole -Namespace MqlIdp -PassThru -MemberDefinition '[DllImport("netapi32.dll")] public static extern int DsRoleGetPrimaryDomainInformation(IntPtr server, int level, out IntPtr buffer); [DllImport("netapi32.dll")] public static extern void DsRoleFreeMemory(IntPtr buffer);'
    $b = [IntPtr]::Zero
    if ($d::DsRoleGetPrimaryDomainInformation([IntPtr]::Zero, 1, [ref]$b) -eq 0) {
      try {
        $m = [Runtime.InteropServices.Marshal]; $p = [IntPtr]::Size
        $r.DomainRole = $m::ReadInt32($b, 0)
        $r.Flat = $m::PtrToStringUni($m::ReadIntPtr($b, 8))
        $dns = $m::PtrToStringUni($m::ReadIntPtr($b, 8 + $p)); if ($dns) { $r.Dns = $dns }
        $r.Forest = $m::PtrToStringUni($m::ReadIntPtr($b, 8 + 2 * $p))
      } finally { $d::DsRoleFreeMemory($b) }
    }
  } catch { }
}
[PSCustomObject]$r | ConvertTo-Json -Compress`

// ActiveDirectoryInfoCommand returns the encoded PowerShell command that reads
// the machine's Active Directory domain membership.
func ActiveDirectoryInfoCommand() string {
	return powershell.Encode(activeDirectoryScript)
}

// powershellGetActiveDirectoryInfo reads the membership with one PowerShell
// command. A command that fails or answers nothing leaves the membership
// unknown and returns an error, never a non-member.
func powershellGetActiveDirectoryInfo(conn shared.Connection) (*ActiveDirectoryInfo, error) {
	cmd, err := conn.RunCommand(ActiveDirectoryInfoCommand())
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		log.Debug().Str("stderr", string(stderr)).Msg("could not read the Active Directory domain membership")
		return nil, errors.New("could not read the Active Directory domain membership")
	}
	return ParseActiveDirectoryInfo(cmd.Stdout)
}

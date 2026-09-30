// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"io"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type WindowsSID struct {
	BinaryLength     int
	AccountDomainSid *string
	Value            string
}

// WindowsGroupMember is one member of a local group: its SID and its name as
// DOMAIN\name (HOST\name for a local account). A member whose account was
// deleted has no resolvable name; its name is then the SID.
type WindowsGroupMember struct {
	Sid  string
	Name string
}

// WindowsGroupMembers accepts a JSON array or a single object, so a PowerShell
// that unwraps a one-element array still parses.
type WindowsGroupMembers []WindowsGroupMember

func (m *WindowsGroupMembers) UnmarshalJSON(data []byte) error {
	list, err := powershell.UnmarshalList[WindowsGroupMember](data)
	if err != nil {
		return err
	}
	*m = list
	return nil
}

type WindowsLocalGroup struct {
	Name            string
	Description     string
	PrincipalSource int
	SID             WindowsSID
	ObjectClass     string
	Members         WindowsGroupMembers
	// MembersError is set when the group's members could not be read.
	MembersError bool
}

// getLocalGroupsScript lists the local groups with their members in one
// PowerShell process. Get-LocalGroupMember is fast, but it fails for the whole
// group when one member is an orphaned SID (an account that was deleted), and
// that is exactly the kind of entry a privileged-group audit has to see. Such a
// group is read again through ADSI, which lists every member's SID; the name
// then comes from the member's ADsPath (WinNT://DOMAIN/name, or just the SID
// for an orphaned member), never from a name lookup that could reach a domain
// controller. A member of which neither the SID nor the ADsPath can be read is
// left out and the group's members marked as unreadable, rather than listed as
// an empty entry. A member with an ADsPath but no readable SID is kept with an
// empty SID, and group.members resolves it by name. ADSI is only the fallback: its first member property read
// binds the computer by name, which takes seconds.
const getLocalGroupsScript = `
$out = foreach ($g in @(Get-LocalGroup)) {
    $members = @()
    $failed = $false
    try {
        foreach ($m in @(Get-LocalGroupMember -Group $g -ErrorAction Stop)) {
            $name = if ($m.Name) { $m.Name } else { $m.SID.Value }
            $members += [PSCustomObject]@{ Sid = $m.SID.Value; Name = $name }
        }
    } catch {
        $members = @()
        try {
            $adsi = [ADSI]('WinNT://./' + $g.Name + ',group')
            foreach ($m in @($adsi.psbase.Invoke('Members'))) {
                $t = $m.GetType()
                $sid = $null
                $path = $null
                try { $sid = (New-Object System.Security.Principal.SecurityIdentifier($t.InvokeMember('objectSid', 'GetProperty', $null, $m, $null), 0)).Value } catch { }
                try { $path = [string]$t.InvokeMember('ADsPath', 'GetProperty', $null, $m, $null) } catch { }
                if (-not $sid -and -not $path) { $failed = $true; continue }
                $parts = @(($path -replace '^WinNT://', '').Split('/') | Where-Object { $_ })
                if ($parts.Count -ge 2) { $name = $parts[-2] + '\' + $parts[-1] }
                elseif ($parts.Count -eq 1) { $name = $parts[0] }
                else { $name = $sid }
                $members += [PSCustomObject]@{ Sid = $sid; Name = $name }
            }
        } catch { $failed = $true }
    }
    [PSCustomObject]@{
        Name            = $g.Name
        Description     = $g.Description
        PrincipalSource = [int]$g.PrincipalSource
        ObjectClass     = $g.ObjectClass
        SID             = [PSCustomObject]@{
            BinaryLength     = [int]$g.SID.BinaryLength
            AccountDomainSid = if ($g.SID.AccountDomainSid) { $g.SID.AccountDomainSid.Value } else { $null }
            Value            = $g.SID.Value
        }
        Members         = $members
        MembersError    = $failed
    }
}
ConvertTo-Json -InputObject @($out) -Depth 4
`

// GetLocalGroupsCommand is the command that lists the local groups and their
// members over PowerShell. Exported so tests can file recorded output under it.
func GetLocalGroupsCommand() string {
	return powershell.Encode(getLocalGroupsScript)
}

func ParseWindowsLocalGroups(r io.Reader) ([]WindowsLocalGroup, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	localGroups, err := powershell.UnmarshalList[WindowsLocalGroup](data)
	if err != nil {
		return nil, err
	}

	return localGroups, nil
}

type WindowsGroupManager struct {
	conn shared.Connection
}

func (s *WindowsGroupManager) Name() string {
	return "Windows Group Manager"
}

func (s *WindowsGroupManager) Group(id string) (*Group, error) {
	groups, err := s.List()
	if err != nil {
		return nil, err
	}

	return findGroup(groups, id)
}

func (s *WindowsGroupManager) List() ([]*Group, error) {
	c, err := s.conn.RunCommand(GetLocalGroupsCommand())
	if err != nil {
		return nil, err
	}
	winGroups, err := ParseWindowsLocalGroups(c.Stdout)
	if err != nil {
		return nil, err
	}

	res := []*Group{}
	for i := range winGroups {
		res = append(res, winToGroup(winGroups[i]))
	}
	return res, nil
}

func winToGroup(g WindowsLocalGroup) *Group {
	members := make([]string, 0, len(g.Members))
	sids := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		name := m.Name
		if name == "" {
			name = m.Sid
		}
		members = append(members, name)
		sids = append(sids, m.Sid)
	}
	return &Group{
		ID:             g.SID.Value,
		Sid:            g.SID.Value,
		Gid:            -1, // TODO: not its suboptimal, but lets make sure to avoid runtime conflicts for now
		Name:           g.Name,
		Members:        members,
		MemberSids:     sids,
		MembersUnknown: g.MembersError,
	}
}

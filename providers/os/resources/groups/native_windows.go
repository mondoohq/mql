// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package groups

import (
	"errors"

	"go.mondoo.com/mql/providers/os/resources/netapi"
)

// nativeWindowsLocalGroups reads what getLocalGroupsScript reads, through
// netapi32: the local groups, their SIDs, and their members with SID and
// DOMAIN\name. Get-LocalGroup reports PrincipalSource Local and ObjectClass
// Group for every local group, and so does this.
func nativeWindowsLocalGroups() ([]WindowsLocalGroup, error) {
	if netapi.IsDomainController() {
		// On a domain controller the local groups are the domain's; leave
		// them to the PowerShell path, which does not enumerate the domain.
		return nil, errors.New("domain controller")
	}
	groups, err := netapi.Groups()
	if err != nil {
		return nil, err
	}
	res := make([]WindowsLocalGroup, 0, len(groups))
	for _, g := range groups {
		sid, err := netapi.AccountSid(g.Name)
		if err != nil {
			return nil, err
		}
		wg := WindowsLocalGroup{
			Name:            g.Name,
			Description:     g.Comment,
			PrincipalSource: 1,
			ObjectClass:     "Group",
			SID:             WindowsSID{Value: sid},
			Members:         []WindowsGroupMember{},
		}
		// On an error members is nil, so the loop below adds nothing and the
		// group keeps an empty member list, marked as unreadable.
		members, err := netapi.Members(g.Name)
		if err != nil {
			wg.MembersError = true
		}
		for _, m := range members {
			name := m.Name
			if name == "" {
				name = m.Sid
			}
			wg.Members = append(wg.Members, WindowsGroupMember{Sid: m.Sid, Name: name})
		}
		res = append(res, wg)
	}
	return res, nil
}

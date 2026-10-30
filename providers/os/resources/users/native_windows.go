// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package users

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/netapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// nativeWindowsLocalUsers reads what getLocalUsersScript reads, without
// PowerShell: the local accounts (NetUserEnum), unioned with the profiles in
// ProfileList, and AAD display names from the IdentityStore cache. The fields
// winToUser consumes (name, SID, home, enabled) come out the same as the
// script's; the synthesized entries for profile-only SIDs follow the script's
// rules exactly.
func nativeWindowsLocalUsers() ([]WindowsLocalUser, error) {
	if netapi.IsDomainController() {
		return nil, errors.New("domain controller")
	}
	accounts, err := netapi.Users()
	if err != nil {
		return nil, err
	}
	machineSid, err := netapi.MachineSid()
	if err != nil {
		return nil, err
	}
	profiles, err := profileList()
	if err != nil {
		return nil, err
	}

	res := []WindowsLocalUser{}
	seen := map[string]bool{}
	for _, a := range accounts {
		sid := machineSid + "-" + strconv.FormatUint(uint64(a.RID), 10)
		seen[sid] = true
		domain := machineSid
		res = append(res, WindowsLocalUser{
			Name:            a.Name,
			Description:     a.Comment,
			PrincipalSource: 1,
			ObjectClass:     "User",
			Enabled:         !a.Disabled,
			FullName:        a.FullName,
			SID:             WindowsSID{Value: sid, AccountDomainSid: &domain},
			LocalPath:       profiles[sid],
		})
	}

	for sid, path := range profiles {
		if seen[sid] {
			continue
		}
		name := aadCachedName(sid)
		if name == "" {
			name = leafName(path)
		}
		if name == "" {
			name = sid
		}
		var accountDomain *string
		principalSource := 2
		if s, err := windows.StringToSid(sid); err == nil {
			if d := accountDomainSid(s); d != "" {
				accountDomain = &d
				if strings.EqualFold(d, machineSid) {
					principalSource = 1
				}
			}
		}
		if strings.HasPrefix(sid, "S-1-12-1-") {
			principalSource = 3
		}
		res = append(res, WindowsLocalUser{
			Name:            name,
			PrincipalSource: principalSource,
			ObjectClass:     "User",
			// As in the script: a profile on disk implies the account logged in;
			// its AD or AAD state is not read.
			Enabled:   true,
			SID:       WindowsSID{Value: sid, AccountDomainSid: accountDomain},
			LocalPath: path,
		})
	}
	return res, nil
}

// serviceSids are the profiles of LocalSystem, LocalService and
// NetworkService, which the script skips.
var serviceSids = map[string]bool{"S-1-5-18": true, "S-1-5-19": true, "S-1-5-20": true}

// profileList maps each profile's SID to its ProfileImagePath, as the script
// reads HKLM\...\ProfileList. The path is kept as stored (the script does not
// expand it either).
func profileList() (map[string]string, error) {
	res := map[string]string{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return res, nil
		}
		return nil, err
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	for _, sid := range sids {
		if serviceSids[sid] {
			continue
		}
		sub, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		path, _, err := sub.GetStringValue("ProfileImagePath")
		sub.Close()
		if err == nil && path != "" {
			res[sid] = path
		}
	}
	return res, nil
}

// aadCachedName returns the UPN the IdentityStore cache holds for an AAD
// (S-1-12-1-*) SID, as the script's Get-AadCachedName does.
func aadCachedName(sid string) string {
	if !strings.HasPrefix(sid, "S-1-12-1-") {
		return ""
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\IdentityStore\Cache\`+sid+`\IdentityCache\`+sid, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	name, _, err := k.GetStringValue("UserName")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

// leafName is the last element of a profile path, as the script's
// Get-LeafName computes it.
func leafName(path string) string {
	path = strings.TrimSpace(strings.TrimRight(path, `\/`))
	if path == "" {
		return ""
	}
	return strings.TrimSpace(filepath.Base(strings.ReplaceAll(path, "/", `\`)))
}

// accountDomainSid is SecurityIdentifier.AccountDomainSid: for an S-1-5-21
// account SID, the SID without its last sub-authority; empty otherwise.
func accountDomainSid(s *windows.SID) string {
	str := s.String()
	if !strings.HasPrefix(str, "S-1-5-21-") {
		return ""
	}
	parts := strings.Split(str, "-")
	if len(parts) < 8 {
		return ""
	}
	return strings.Join(parts[:7], "-")
}

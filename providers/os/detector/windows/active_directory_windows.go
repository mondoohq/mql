// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows"
)

var (
	netapi32                              = windows.NewLazySystemDLL("netapi32.dll")
	procDsRoleGetPrimaryDomainInformation = netapi32.NewProc("DsRoleGetPrimaryDomainInformation")
	procDsRoleFreeMemory                  = netapi32.NewProc("DsRoleFreeMemory")
)

// dsRolePrimaryDomainInfoBasic is DsRolePrimaryDomainInfoBasic, the
// DSROLE_PRIMARY_DOMAIN_INFO_LEVEL that returns
// DSROLE_PRIMARY_DOMAIN_INFO_BASIC.
const dsRolePrimaryDomainInfoBasic = 1

// dsrolePrimaryDomainInfoBasic mirrors DSROLE_PRIMARY_DOMAIN_INFO_BASIC.
// https://learn.microsoft.com/en-us/windows/win32/api/dsrole/ns-dsrole-dsrole_primary_domain_info_basic
type dsrolePrimaryDomainInfoBasic struct {
	MachineRole      uint32
	Flags            uint32
	DomainNameFlat   *uint16
	DomainNameDns    *uint16
	DomainForestName *uint16
	DomainGuid       windows.GUID
}

// GetActiveDirectoryInfo returns the Active Directory domain membership.
// Locally on Windows it calls DsRoleGetPrimaryDomainInformation, which the
// local security authority answers without contacting a domain controller and
// which returns the domain and forest names together. Every other connection
// uses PowerShell.
func GetActiveDirectoryInfo(conn shared.Connection) (*ActiveDirectoryInfo, error) {
	if conn.Type() != shared.Type_Local {
		return powershellGetActiveDirectoryInfo(conn)
	}

	var buf *dsrolePrimaryDomainInfoBasic
	ret, _, _ := procDsRoleGetPrimaryDomainInformation.Call(
		0,
		uintptr(dsRolePrimaryDomainInfoBasic),
		uintptr(unsafe.Pointer(&buf)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("DsRoleGetPrimaryDomainInformation failed: %w", windows.Errno(ret))
	}
	if buf == nil {
		return nil, fmt.Errorf("DsRoleGetPrimaryDomainInformation returned no information")
	}
	defer procDsRoleFreeMemory.Call(uintptr(unsafe.Pointer(buf))) //nolint:errcheck

	return activeDirectoryInfoFromRole(
		int(buf.MachineRole),
		windows.UTF16PtrToString(buf.DomainNameFlat),
		windows.UTF16PtrToString(buf.DomainNameDns),
		windows.UTF16PtrToString(buf.DomainForestName),
	), nil
}

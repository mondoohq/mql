// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

// Package netapi reads local users, local groups and group members through
// netapi32, for the native Windows paths of the users and groups resources.
// It only runs on the machine the provider runs on; callers gate it with
// shared.WindowsNative.
package netapi

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum             = modnetapi32.NewProc("NetUserEnum")
	procNetLocalGroupEnum       = modnetapi32.NewProc("NetLocalGroupEnum")
	procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")
)

const (
	nerrSuccess         = 0
	errorMoreData       = 234 // ERROR_MORE_DATA
	maxPreferredLength  = 0xFFFFFFFF
	filterNormalAccount = 0x0002 // FILTER_NORMAL_ACCOUNT
	ufAccountDisable    = 0x0002 // UF_ACCOUNTDISABLE
)

// userInfo20 is USER_INFO_20 (lmaccess.h).
type userInfo20 struct {
	Name     *uint16
	FullName *uint16
	Comment  *uint16
	Flags    uint32
	UserID   uint32
}

// localGroupInfo1 is LOCALGROUP_INFO_1 (lmaccess.h).
type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

// localGroupMembersInfo2 is LOCALGROUP_MEMBERS_INFO_2 (lmaccess.h).
type localGroupMembersInfo2 struct {
	Sid           *windows.SID
	SidUsage      uint32
	DomainAndName *uint16
}

// User is a local account as NetUserEnum reports it.
type User struct {
	Name     string
	FullName string
	Comment  string
	RID      uint32
	Disabled bool
}

// Group is a local group as NetLocalGroupEnum reports it.
type Group struct {
	Name    string
	Comment string
}

// Member is a member of a local group. Name is DOMAIN\name; for an account
// that no longer exists it is empty and only the SID is known.
type Member struct {
	Sid   string
	Name  string
	Usage uint32 // SID_NAME_USE
}

// ErrAccessDenied is returned when the caller may not enumerate the accounts.
// The list is then unknown, not empty.
var ErrAccessDenied = errors.New("access denied enumerating local accounts")

func apiError(fn string, ret uintptr) error {
	if ret == uintptr(windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%s: %w", fn, ErrAccessDenied)
	}
	return fmt.Errorf("%s failed: %w", fn, windows.Errno(ret))
}

// Users lists the local normal accounts (NetUserEnum level 20). The resume
// handle of NetUserEnum is a DWORD.
func Users() ([]User, error) {
	var res []User
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		// The return value, not LazyProc.Call's error (a stale GetLastError),
		// decides success.
		ret, _, _ := procNetUserEnum.Call(0, 20, filterNormalAccount,
			uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		if ret != nerrSuccess && ret != errorMoreData {
			return nil, apiError("NetUserEnum", ret)
		}
		if buf != nil {
			entries := unsafe.Slice((*userInfo20)(unsafe.Pointer(buf)), read)
			for _, e := range entries {
				res = append(res, User{
					Name:     windows.UTF16PtrToString(e.Name),
					FullName: windows.UTF16PtrToString(e.FullName),
					Comment:  windows.UTF16PtrToString(e.Comment),
					RID:      e.UserID,
					Disabled: e.Flags&ufAccountDisable != 0,
				})
			}
			windows.NetApiBufferFree(buf)
		}
		if ret != errorMoreData {
			return res, nil
		}
	}
}

// Groups lists the local groups (NetLocalGroupEnum level 1). Its resume
// handle is a DWORD_PTR: pointer-sized, unlike NetUserEnum's.
func Groups() ([]Group, error) {
	var res []Group
	var resume uintptr
	for {
		var buf *byte
		var read, total uint32
		ret, _, _ := procNetLocalGroupEnum.Call(0, 1,
			uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		if ret != nerrSuccess && ret != errorMoreData {
			return nil, apiError("NetLocalGroupEnum", ret)
		}
		if buf != nil {
			entries := unsafe.Slice((*localGroupInfo1)(unsafe.Pointer(buf)), read)
			for _, e := range entries {
				res = append(res, Group{
					Name:    windows.UTF16PtrToString(e.Name),
					Comment: windows.UTF16PtrToString(e.Comment),
				})
			}
			windows.NetApiBufferFree(buf)
		}
		if ret != errorMoreData {
			return res, nil
		}
	}
}

// Members lists the members of a local group (NetLocalGroupGetMembers level
// 2: SID, SID usage and DOMAIN\name in one call). The resume handle is a
// DWORD_PTR. Access denied wraps ErrAccessDenied; any other failure, such as
// a group deleted after Groups listed it (NERR_GroupNotFound), wraps the
// status as a windows.Errno.
func Members(group string) ([]Member, error) {
	name, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, err
	}
	var res []Member
	var resume uintptr
	for {
		var buf *byte
		var read, total uint32
		ret, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(name)), 2,
			uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)))
		if ret != nerrSuccess && ret != errorMoreData {
			return nil, apiError("NetLocalGroupGetMembers", ret)
		}
		if buf != nil {
			entries := unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), read)
			for _, e := range entries {
				m := Member{Usage: e.SidUsage}
				if e.Sid != nil {
					m.Sid = e.Sid.String()
				}
				// A deleted account (SidTypeDeletedAccount) or one that
				// cannot be resolved (SidTypeUnknown) has no usable name.
				if e.SidUsage != uint32(windows.SidTypeDeletedAccount) && e.SidUsage != uint32(windows.SidTypeUnknown) {
					m.Name = windows.UTF16PtrToString(e.DomainAndName)
				}
				res = append(res, m)
			}
			windows.NetApiBufferFree(buf)
		}
		if ret != errorMoreData {
			return res, nil
		}
	}
}

// AccountSid resolves a local account or group name to its SID on this
// machine (LookupAccountName with no system name, so it never leaves the
// machine for a local name).
func AccountSid(name string) (string, error) {
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

// MachineSid returns the SID of this machine's account domain, the prefix of
// every local account's SID.
func MachineSid() (string, error) {
	host, err := windows.ComputerName()
	if err != nil {
		return "", err
	}
	sid, _, use, err := windows.LookupSID("", host)
	if err != nil {
		return "", err
	}
	if use != windows.SidTypeDomain {
		return "", fmt.Errorf("%s resolved to a SID of type %d, not a domain", host, use)
	}
	return sid.String(), nil
}

// IsDomainController reports whether this machine is a domain controller
// (ProductOptions ProductType LanmanNT). On a domain controller the local
// accounts are the domain's, so the native paths leave them to PowerShell. An
// error reading the value counts as a domain controller, so a native path
// never enumerates a domain by mistake.
func IsDomainController() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ProductType")
	if err != nil {
		return true
	}
	return v == "LanmanNT"
}

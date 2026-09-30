// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modnetapi32 = windows.NewLazySystemDLL("netapi32.dll")
	modsamlib   = windows.NewLazySystemDLL("samlib.dll")

	procLsaOpenPolicy                     = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaClose                          = modadvapi32.NewProc("LsaClose")
	procLsaFreeMemory                     = modadvapi32.NewProc("LsaFreeMemory")
	procLsaQueryInformationPolicy         = modadvapi32.NewProc("LsaQueryInformationPolicy")
	procLsaEnumerateAccountsWithUserRight = modadvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaNtStatusToWinError             = modadvapi32.NewProc("LsaNtStatusToWinError")
	procLsaQuerySecurityObject            = modadvapi32.NewProc("LsaQuerySecurityObject")

	procNetUserModalsGet = modnetapi32.NewProc("NetUserModalsGet")

	procSamConnect                = modsamlib.NewProc("SamConnect")
	procSamOpenDomain             = modsamlib.NewProc("SamOpenDomain")
	procSamQueryInformationDomain = modsamlib.NewProc("SamQueryInformationDomain")
	procSamFreeMemory             = modsamlib.NewProc("SamFreeMemory")
	procSamCloseHandle            = modsamlib.NewProc("SamCloseHandle")
)

const (
	policyViewLocalInformation = 0x0001
	policyViewAuditInformation = 0x0002
	policyLookupNames          = 0x0800
	readControl                = 0x00020000

	policyAuditEventsInformation   = 2 // POLICY_INFORMATION_CLASS
	policyAccountDomainInformation = 5

	samServerConnect             = 0x0001
	samServerLookupDomain        = 0x0020
	domainReadPasswordParameters = 0x0001
	domainPasswordInformation    = 1 // DOMAIN_INFORMATION_CLASS

	statusSuccess            = 0x00000000
	statusNoMoreEntries      = 0x8000001A
	statusObjectNameNotFound = 0xC0000034
	statusNoSuchPrivilege    = 0xC0000060

	ufAccountDisable = 0x0002
)

// lsaUnicodeString is LSA_UNICODE_STRING (and UNICODE_STRING).
type lsaUnicodeString = windows.NTUnicodeString

// policyAuditEventsInfo is POLICY_AUDIT_EVENTS_INFO.
type policyAuditEventsInfo struct {
	AuditingMode           uint8
	EventAuditingOptions   *uint32
	MaximumAuditEventCount uint32
}

// policyAccountDomainInfo is POLICY_ACCOUNT_DOMAIN_INFO.
type policyAccountDomainInfo struct {
	DomainName lsaUnicodeString
	DomainSid  *windows.SID
}

// lsaEnumerationInformation is LSA_ENUMERATION_INFORMATION.
type lsaEnumerationInformation struct {
	Sid *windows.SID
}

// userModalsInfo0 is USER_MODALS_INFO_0.
type userModalsInfo0 struct {
	MinPasswdLen    uint32
	MaxPasswdAge    uint32
	MinPasswdAge    uint32
	ForceLogoff     uint32
	PasswordHistLen uint32
}

// userModalsInfo3 is USER_MODALS_INFO_3.
type userModalsInfo3 struct {
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
}

// domainPasswordInfo is DOMAIN_PASSWORD_INFORMATION (MS-SAMR 2.2.3.5).
type domainPasswordInfo struct {
	MinPasswordLength     uint16
	PasswordHistoryLength uint16
	PasswordProperties    uint32
	MaxPasswordAge        int64
	MinPasswordAge        int64
}

// userInfo1 is USER_INFO_1.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// privilegeRightNames are the rights secedit exports: every privilege and
// logon right of the local security policy (winnt.h, ntsecapi.h).
var privilegeRightNames = []string{
	"SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
	"SeBatchLogonRight", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
	"SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
	"SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege",
	"SeDenyBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyNetworkLogonRight",
	"SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight", "SeEnableDelegationPrivilege",
	"SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
	"SeIncreaseWorkingSetPrivilege", "SeInteractiveLogonRight", "SeLoadDriverPrivilege",
	"SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
	"SeNetworkLogonRight", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege",
	"SeRemoteInteractiveLogonRight", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
	"SeSecurityPrivilege", "SeServiceLogonRight", "SeShutdownPrivilege",
	"SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
	"SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege",
	"SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege",
	"SeUnsolicitedInputPrivilege",
}

// NativeSecpolExport reads the local security policy through the APIs and
// renders it as `secedit /export` does. It needs the rights secedit needs
// (an administrator or SYSTEM).
func NativeSecpolExport() (string, error) {
	for _, p := range []*windows.LazyProc{
		procLsaOpenPolicy, procLsaQueryInformationPolicy, procLsaEnumerateAccountsWithUserRight, procLsaQuerySecurityObject,
		procNetUserModalsGet, procSamConnect, procSamOpenDomain, procSamQueryInformationDomain,
	} {
		if err := p.Find(); err != nil {
			return "", err
		}
	}

	policy, err := lsaOpenPolicy(policyViewLocalInformation | policyViewAuditInformation | policyLookupNames | readControl)
	if err != nil {
		return "", err
	}
	defer procLsaClose.Call(policy)

	domainSid, err := accountDomainSid(policy)
	if err != nil {
		return "", err
	}

	sa, err := systemAccess(domainSid)
	if err != nil {
		return "", err
	}
	if sa.AnonymousNameLookup, err = anonymousNameLookup(policy); err != nil {
		return "", err
	}
	auditingMode, options, err := auditEvents(policy)
	if err != nil {
		return "", err
	}
	regValues, err := registryValues()
	if err != nil {
		return "", err
	}
	rights, err := privilegeRights(policy)
	if err != nil {
		return "", err
	}

	return RenderSecpol(RenderSystemAccess(sa), RenderEventAudit(auditingMode, options), regValues, RenderPrivilegeRights(rights)), nil
}

func ntStatusError(call string, status uintptr) error {
	code, _, _ := procLsaNtStatusToWinError.Call(status)
	return fmt.Errorf("%s: %w (NTSTATUS 0x%08X)", call, windows.Errno(code), uint32(status))
}

func lsaOpenPolicy(access uint32) (uintptr, error) {
	var attrs windows.OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle uintptr
	r, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), uintptr(access), uintptr(unsafe.Pointer(&handle)))
	if r != statusSuccess {
		return 0, ntStatusError("LsaOpenPolicy", r)
	}
	return handle, nil
}

// accountDomainSid returns a copy of the account domain's SID: the machine's.
func accountDomainSid(policy uintptr) (*windows.SID, error) {
	var buf unsafe.Pointer
	r, _, _ := procLsaQueryInformationPolicy.Call(policy, policyAccountDomainInformation, uintptr(unsafe.Pointer(&buf)))
	if r != statusSuccess {
		return nil, ntStatusError("LsaQueryInformationPolicy(PolicyAccountDomainInformation)", r)
	}
	defer procLsaFreeMemory.Call(uintptr(buf))
	info := (*policyAccountDomainInfo)(buf)
	if info.DomainSid == nil {
		return nil, errors.New("the account domain has no SID")
	}
	return info.DomainSid.Copy()
}

func systemAccess(domainSid *windows.SID) (SecpolSystemAccess, error) {
	var sa SecpolSystemAccess

	var buf *byte
	if r, _, _ := procNetUserModalsGet.Call(0, 0, uintptr(unsafe.Pointer(&buf))); r != 0 {
		return sa, fmt.Errorf("NetUserModalsGet(0): %w", windows.Errno(r))
	}
	m0 := *(*userModalsInfo0)(unsafe.Pointer(buf))
	windows.NetApiBufferFree(buf)
	sa.MinPasswordLen, sa.MaxPasswordAge, sa.MinPasswordAge = m0.MinPasswdLen, m0.MaxPasswdAge, m0.MinPasswdAge
	sa.ForceLogoff, sa.PasswordHistoryLen = m0.ForceLogoff, m0.PasswordHistLen

	buf = nil
	if r, _, _ := procNetUserModalsGet.Call(0, 3, uintptr(unsafe.Pointer(&buf))); r != 0 {
		return sa, fmt.Errorf("NetUserModalsGet(3): %w", windows.Errno(r))
	}
	m3 := *(*userModalsInfo3)(unsafe.Pointer(buf))
	windows.NetApiBufferFree(buf)
	sa.LockoutDuration, sa.LockoutObservationWindow, sa.LockoutThreshold = m3.LockoutDuration, m3.LockoutObservationWindow, m3.LockoutThreshold

	props, err := passwordProperties(domainSid)
	if err != nil {
		return sa, err
	}
	sa.PasswordProperties = props

	admin, err := wellKnownAccount(domainSid, 500)
	if err != nil {
		return sa, err
	}
	guest, err := wellKnownAccount(domainSid, 501)
	if err != nil {
		return sa, err
	}
	sa.Accounts = SecpolAccounts{
		AdministratorName: admin.name, AdminEnabled: admin.enabled,
		GuestName: guest.name, GuestEnabled: guest.enabled,
	}
	return sa, nil
}

// anonymousNameLookup reads "Network access: Allow anonymous SID/Name
// translation" as secedit does: it is not a registry value but an ACE in the
// LSA policy object's DACL.
func anonymousNameLookup(policy uintptr) (bool, error) {
	var sd *windows.SECURITY_DESCRIPTOR
	r, _, _ := procLsaQuerySecurityObject.Call(policy, uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(&sd)))
	if r != statusSuccess {
		return false, ntStatusError("LsaQuerySecurityObject", r)
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(sd)))
	return grantsAnonymousLookupNames(sd)
}

// grantsAnonymousLookupNames reports whether the DACL has the ACE the policy
// sets: one for ANONYMOUS LOGON (S-1-5-7) with POLICY_LOOKUP_NAMES alone,
// (A;;0x800;;;AN) when enabled and (D;;0x800;;;AN) when disabled, in front of
// the ACE that always allows ANONYMOUS LOGON 0x801. The first such ACE
// decides; without one, the policy is not enabled.
func grantsAnonymousLookupNames(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	dacl, _, err := sd.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			// no DACL: nothing is granted explicitly
			return false, nil
		}
		return false, err
	}
	if dacl == nil {
		return false, nil
	}
	anonymous, err := windows.CreateWellKnownSid(windows.WinAnonymousSid)
	if err != nil {
		return false, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		// ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share this layout
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		t := ace.Header.AceType
		if (t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE) || ace.Mask != policyLookupNames {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(anonymous) {
			return t == windows.ACCESS_ALLOWED_ACE_TYPE, nil
		}
	}
	return false, nil
}

// passwordProperties reads DOMAIN_PASSWORD_INFORMATION.PasswordProperties of
// the account domain from SAM (MS-SAMR SamrQueryInformationDomain, which
// samlib exports): password complexity, reversible encryption, logon to change
// the password and administrator lockout have no other API.
func passwordProperties(domainSid *windows.SID) (uint32, error) {
	var attrs windows.OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var server uintptr
	if r, _, _ := procSamConnect.Call(0, uintptr(unsafe.Pointer(&server)), samServerConnect|samServerLookupDomain, uintptr(unsafe.Pointer(&attrs))); r != statusSuccess {
		return 0, ntStatusError("SamConnect", r)
	}
	defer procSamCloseHandle.Call(server)

	var domain uintptr
	if r, _, _ := procSamOpenDomain.Call(server, domainReadPasswordParameters, uintptr(unsafe.Pointer(domainSid)), uintptr(unsafe.Pointer(&domain))); r != statusSuccess {
		return 0, ntStatusError("SamOpenDomain", r)
	}
	defer procSamCloseHandle.Call(domain)

	var buf unsafe.Pointer
	if r, _, _ := procSamQueryInformationDomain.Call(domain, domainPasswordInformation, uintptr(unsafe.Pointer(&buf))); r != statusSuccess {
		return 0, ntStatusError("SamQueryInformationDomain(DomainPasswordInformation)", r)
	}
	defer procSamFreeMemory.Call(uintptr(buf))
	return (*domainPasswordInfo)(buf).PasswordProperties, nil
}

type account struct {
	name    string
	enabled bool
}

func wellKnownAccount(domainSid *windows.SID, rid uint32) (account, error) {
	sid, err := windows.StringToSid(fmt.Sprintf("%s-%d", domainSid.String(), rid))
	if err != nil {
		return account{}, err
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return account{}, fmt.Errorf("could not look up RID %d: %w", rid, err)
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return account{}, err
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, namePtr, 1, &buf); err != nil {
		return account{}, fmt.Errorf("NetUserGetInfo(%s): %w", name, err)
	}
	defer windows.NetApiBufferFree(buf)
	info := (*userInfo1)(unsafe.Pointer(buf))
	return account{name: name, enabled: info.Flags&ufAccountDisable == 0}, nil
}

func auditEvents(policy uintptr) (bool, []uint32, error) {
	var buf unsafe.Pointer
	r, _, _ := procLsaQueryInformationPolicy.Call(policy, policyAuditEventsInformation, uintptr(unsafe.Pointer(&buf)))
	if r != statusSuccess {
		return false, nil, ntStatusError("LsaQueryInformationPolicy(PolicyAuditEventsInformation)", r)
	}
	defer procLsaFreeMemory.Call(uintptr(buf))
	info := (*policyAuditEventsInfo)(buf)
	// Only the first len(eventAuditNames) options are rendered; never read
	// more than that from the LSA buffer.
	n := min(int(info.MaximumAuditEventCount), len(eventAuditNames))
	options := make([]uint32, n)
	if n > 0 && info.EventAuditingOptions != nil {
		copy(options, unsafe.Slice(info.EventAuditingOptions, n))
	}
	return info.AuditingMode != 0, options, nil
}

// privilegeRights returns the holders of every right as SID strings.
func privilegeRights(policy uintptr) (map[string][]string, error) {
	res := map[string][]string{}
	for _, name := range privilegeRightNames {
		sids, err := accountsWithRight(policy, name)
		if err != nil {
			return nil, err
		}
		if len(sids) > 0 {
			res[name] = sids
		}
	}
	return res, nil
}

func accountsWithRight(policy uintptr, right string) ([]string, error) {
	u16, err := windows.UTF16FromString(right)
	if err != nil {
		return nil, err
	}
	name := lsaUnicodeString{
		Length:        uint16((len(u16) - 1) * 2),
		MaximumLength: uint16(len(u16) * 2),
		Buffer:        &u16[0],
	}
	var buf unsafe.Pointer
	var count uint32
	r, _, _ := procLsaEnumerateAccountsWithUserRight.Call(policy, uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&count)))
	switch uint32(r) {
	case statusSuccess:
	case statusNoMoreEntries, statusObjectNameNotFound, statusNoSuchPrivilege:
		// no holders, or a right this OS doesn't know: secedit leaves both out
		return nil, nil
	default:
		return nil, ntStatusError("LsaEnumerateAccountsWithUserRight("+right+")", r)
	}
	defer procLsaFreeMemory.Call(uintptr(buf))
	entries := unsafe.Slice((*lsaEnumerationInformation)(buf), count)
	sids := make([]string, 0, count)
	for _, e := range entries {
		if e.Sid != nil {
			sids = append(sids, e.Sid.String())
		}
	}
	return sids, nil
}

// secEditRegValues lists the registry values the security template knows;
// secedit exports each one that exists. Its subkeys are the value paths with
// "/" for "\" (MACHINE/System/.../Value).
const secEditRegValues = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SeCEdit\Reg Values`

func registryValues() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, secEditRegValues, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", secEditRegValues, err)
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, n := range names {
		path := strings.ReplaceAll(n, "/", `\`)
		root, rest, ok := strings.Cut(path, `\`)
		if !ok || !strings.EqualFold(root, "MACHINE") {
			continue
		}
		i := strings.LastIndex(rest, `\`)
		if i < 0 {
			continue
		}
		v, ok := readRegistryValue(rest[:i], rest[i+1:], declaredType(n))
		if !ok {
			continue
		}
		v.Path = path
		if line, ok := RenderRegistryValue(v); ok {
			lines = append(lines, line)
		} else {
			log.Debug().Str("value", path).Uint32("type", v.Type).Msg("secpol: registry value type secedit does not export")
		}
	}
	return lines, nil
}

// readRegistryValue reads a value as secedit exports it: in the type its
// Reg Values entry declares, which can differ from the stored type (Windows
// stores LegalNoticeText as REG_SZ, secedit declares and writes it as
// REG_MULTI_SZ). Without a declared type the stored one is used. REG_EXPAND_SZ
// is written as stored, not expanded.
func readRegistryValue(keyPath, name string, declared uint32) (SecpolRegistryValue, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return SecpolRegistryValue{}, false
	}
	defer k.Close()
	n, typ, err := k.GetValue(name, nil)
	if err != nil {
		return SecpolRegistryValue{}, false
	}
	buf := make([]byte, n)
	// The value can grow between the size query and the read; GetValue then
	// fails with ERROR_MORE_DATA and reports the new size. Retry a few times.
	for attempt := 0; n > 0 && attempt < 3; attempt++ {
		n, typ, err = k.GetValue(name, buf)
		if err == nil {
			buf = buf[:n]
			break
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return SecpolRegistryValue{}, false
		}
		buf = make([]byte, n)
	}
	if err != nil {
		return SecpolRegistryValue{}, false
	}
	if declared == 0 {
		declared = typ
	}
	return decodeRegistryValue(declared, buf), true
}

// decodeRegistryValue interprets raw registry data as the given type.
func decodeRegistryValue(typ uint32, buf []byte) SecpolRegistryValue {
	v := SecpolRegistryValue{Type: typ}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		v.String = windows.UTF16ToString(utf16Of(buf))
	case registry.MULTI_SZ:
		u := utf16Of(buf)
		for len(u) > 0 {
			i := 0
			for i < len(u) && u[i] != 0 {
				i++
			}
			if i == 0 {
				break
			}
			v.Strings = append(v.Strings, string(utf16.Decode(u[:i])))
			if i == len(u) {
				break
			}
			u = u[i+1:]
		}
	case registry.DWORD:
		var b [4]byte
		copy(b[:], buf)
		v.Number = uint64(binary.LittleEndian.Uint32(b[:]))
	case registry.BINARY:
		v.Binary = buf
	}
	return v
}

func utf16Of(buf []byte) []uint16 {
	u := make([]uint16, len(buf)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(buf[2*i:])
	}
	return u
}

// declaredType is the ValueType of a Reg Values entry, 0 if it has none.
func declaredType(entry string) uint32 {
	return uint32(registryDword(registry.LOCAL_MACHINE, secEditRegValues+`\`+entry, "ValueType"))
}

func registryDword(root registry.Key, path, name string) uint64 {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0
	}
	defer k.Close()
	n, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return n
}

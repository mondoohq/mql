// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The native secpol reads the local security policy through the APIs secedit
// itself uses (SAM, LSA, NetUserModals, the registry) and renders the same INF
// text `secedit /export` writes. ParseSecpol then reads it like the PowerShell
// output, so both paths share one parser and every quirk of it.

// timeqForever is TIMEQ_FOREVER: a NetUserModals duration without limit.
const timeqForever = 0xFFFFFFFF

// SAM domain password properties (MS-SAMR 2.2.1.8).
const (
	domainPasswordComplex      = 0x01
	domainPasswordNoAnonChange = 0x02
	domainLockoutAdmins        = 0x08
	domainPasswordStoreClear   = 0x10
)

// SecpolAccounts is what [System Access] reports about accounts.
type SecpolAccounts struct {
	// AdministratorName and GuestName are the names of the accounts with RID
	// 500 and 501 of the account domain.
	AdministratorName string
	GuestName         string
	AdminEnabled      bool
	GuestEnabled      bool
}

// SecpolSystemAccess holds the raw values [System Access] is made of.
type SecpolSystemAccess struct {
	// USER_MODALS_INFO_0, in seconds
	MinPasswordLen     uint32
	MaxPasswordAge     uint32
	MinPasswordAge     uint32
	ForceLogoff        uint32
	PasswordHistoryLen uint32
	// USER_MODALS_INFO_3, in seconds
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
	// DOMAIN_PASSWORD_INFORMATION.PasswordProperties
	PasswordProperties uint32
	// anonymous SID/name translation: the LSA policy object's DACL grants
	// ANONYMOUS LOGON POLICY_LOOKUP_NAMES
	AnonymousNameLookup bool
	Accounts            SecpolAccounts
}

// RenderSystemAccess writes [System Access] in secedit's order and format.
func RenderSystemAccess(sa SecpolSystemAccess) []string {
	// Ages and durations are truncated to whole days or minutes, as secedit
	// writes them: a minimum age of one hour is "0".
	lines := []string{
		"MinimumPasswordAge = " + strconv.FormatUint(uint64(sa.MinPasswordAge/86400), 10),
		"MaximumPasswordAge = " + daysOrUnlimited(sa.MaxPasswordAge, 86400),
		"MinimumPasswordLength = " + strconv.FormatUint(uint64(sa.MinPasswordLen), 10),
		"PasswordComplexity = " + flag(sa.PasswordProperties&domainPasswordComplex != 0),
		"PasswordHistorySize = " + strconv.FormatUint(uint64(sa.PasswordHistoryLen), 10),
		"LockoutBadCount = " + strconv.FormatUint(uint64(sa.LockoutThreshold), 10),
	}
	// secedit omits the lockout window and duration while lockout is off.
	if sa.LockoutThreshold > 0 {
		lines = append(lines,
			"ResetLockoutCount = "+strconv.FormatUint(uint64(sa.LockoutObservationWindow/60), 10),
			"LockoutDuration = "+daysOrUnlimited(sa.LockoutDuration, 60),
			// Windows added this policy to every supported release with the
			// October 2022 updates; secedit lists it with the lockout settings.
			"AllowAdministratorLockout = "+flag(sa.PasswordProperties&domainLockoutAdmins != 0),
		)
	}
	lines = append(lines,
		"RequireLogonToChangePassword = "+flag(sa.PasswordProperties&domainPasswordNoAnonChange != 0),
		"ForceLogoffWhenHourExpire = "+flag(sa.ForceLogoff != timeqForever),
		`NewAdministratorName = "`+sa.Accounts.AdministratorName+`"`,
		`NewGuestName = "`+sa.Accounts.GuestName+`"`,
		"ClearTextPassword = "+flag(sa.PasswordProperties&domainPasswordStoreClear != 0),
		"LSAAnonymousNameLookup = "+flag(sa.AnonymousNameLookup),
		"EnableAdminAccount = "+flag(sa.Accounts.AdminEnabled),
		"EnableGuestAccount = "+flag(sa.Accounts.GuestEnabled),
	)
	return lines
}

// daysOrUnlimited converts seconds into the unit (a day or a minute), with -1
// for TIMEQ_FOREVER, as secedit reports "never".
func daysOrUnlimited(seconds uint32, unit uint32) string {
	if seconds == timeqForever {
		return "-1"
	}
	return strconv.FormatUint(uint64(seconds/unit), 10)
}

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Audit event options (POLICY_AUDIT_EVENT_*).
const (
	auditEventSuccess = 0x1
	auditEventFailure = 0x2
)

// eventAuditNames are the [Event Audit] keys, in POLICY_AUDIT_EVENT_TYPE order.
var eventAuditNames = []string{
	"AuditSystemEvents",
	"AuditLogonEvents",
	"AuditObjectAccess",
	"AuditPrivilegeUse",
	"AuditProcessTracking",
	"AuditPolicyChange",
	"AuditAccountManage",
	"AuditDSAccess",
	"AuditAccountLogon",
}

// eventAuditOrder is secedit's order of the [Event Audit] keys.
var eventAuditOrder = []string{
	"AuditSystemEvents",
	"AuditLogonEvents",
	"AuditObjectAccess",
	"AuditPrivilegeUse",
	"AuditPolicyChange",
	"AuditAccountManage",
	"AuditProcessTracking",
	"AuditDSAccess",
	"AuditAccountLogon",
}

// RenderEventAudit writes [Event Audit] from POLICY_AUDIT_EVENTS_INFO: the
// options per category in POLICY_AUDIT_EVENT_TYPE order, all 0 while auditing
// is off. 1 is success, 2 failure, 3 both.
func RenderEventAudit(auditingMode bool, options []uint32) []string {
	values := map[string]uint32{}
	for i, name := range eventAuditNames {
		if auditingMode && i < len(options) {
			values[name] = options[i] & (auditEventSuccess | auditEventFailure)
		}
	}
	lines := make([]string, 0, len(eventAuditOrder))
	for _, name := range eventAuditOrder {
		lines = append(lines, name+" = "+strconv.FormatUint(uint64(values[name]), 10))
	}
	return lines
}

// Registry value types, as secedit writes them.
const (
	regSZ       = 1
	regExpandSZ = 2
	regBinary   = 3
	regDWORD    = 4
	regMultiSZ  = 7
)

// SecpolRegistryValue is one value of [Registry Values]: its path as secedit
// writes it (MACHINE\...) and what the registry holds.
type SecpolRegistryValue struct {
	Path    string
	Type    uint32
	String  string
	Strings []string
	Number  uint64
	Binary  []byte
}

// RenderRegistryValue writes one [Registry Values] line: <path>=<type>,<data>.
func RenderRegistryValue(v SecpolRegistryValue) (string, bool) {
	var data string
	switch v.Type {
	case regSZ, regExpandSZ:
		data = `"` + v.String + `"`
	case regMultiSZ:
		data = strings.Join(v.Strings, ",")
	case regDWORD:
		data = strconv.FormatUint(v.Number, 10)
	case regBinary:
		parts := make([]string, len(v.Binary))
		for i, b := range v.Binary {
			parts[i] = strconv.Itoa(int(b))
		}
		data = strings.Join(parts, ",")
	default:
		return "", false
	}
	return fmt.Sprintf("%s=%d,%s", v.Path, v.Type, data), true
}

// RenderPrivilegeRights writes [Privilege Rights]: each right that has holders,
// with its SIDs as secedit writes them (*S-1-...). A right nobody holds is not
// listed, as secedit leaves it out.
func RenderPrivilegeRights(rights map[string][]string) []string {
	names := make([]string, 0, len(rights))
	for name, sids := range rights {
		if len(sids) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		sids := make([]string, len(rights[name]))
		for i, sid := range rights[name] {
			sids[i] = "*" + sid
		}
		lines = append(lines, name+" = "+strings.Join(sids, ","))
	}
	return lines
}

// RenderSecpol writes a secedit export from its sections.
func RenderSecpol(systemAccess, eventAudit, registryValues, privilegeRights []string) string {
	var b strings.Builder
	b.WriteString("[Unicode]\nUnicode=yes\n")
	b.WriteString("[System Access]\n")
	for _, l := range systemAccess {
		b.WriteString(l + "\n")
	}
	b.WriteString("[Event Audit]\n")
	for _, l := range eventAudit {
		b.WriteString(l + "\n")
	}
	b.WriteString("[Registry Values]\n")
	for _, l := range registryValues {
		b.WriteString(l + "\n")
	}
	b.WriteString("[Privilege Rights]\n")
	for _, l := range privilegeRights {
		b.WriteString(l + "\n")
	}
	b.WriteString("[Version]\nsignature=\"$CHICAGO$\"\nRevision=1\n")
	return b.String()
}

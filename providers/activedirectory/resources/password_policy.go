// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/types"
)

// durationToDays converts an AD duration value (negative 100ns intervals) to days.
// A value of 0 means "none" / no limit (e.g., maxPasswordAge = 0 → passwords never expire).
func durationToDays(raw int64) int64 {
	if raw == 0 {
		return 0
	}
	ticks := raw
	if ticks < 0 {
		ticks = -ticks
	}
	const ticksPerDay = 864_000_000_000 // 24h * 60m * 60s * 10^7
	return ticks / ticksPerDay
}

// durationToMinutes converts an AD duration value (negative 100ns intervals) to minutes.
// A value of 0 means "until admin unlocks" for lockoutDuration.
func durationToMinutes(raw int64) int64 {
	if raw == 0 {
		return 0
	}
	ticks := raw
	if ticks < 0 {
		ticks = -ticks
	}
	const ticksPerMinute = 600_000_000 // 60s * 10^7
	return ticks / ticksPerMinute
}

// parseInt64Attr parses a string LDAP attribute into int64. Returns 0 on empty or parse error.
func parseInt64Attr(s string) int64 {
	s = strings.TrimSpace(strings.TrimRight(s, "\x00"))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		log.Warn().Str("value", s).Err(err).Msg("parseInt64Attr: non-numeric LDAP attribute value, defaulting to 0")
		return 0
	}
	return v
}

func (a *mqlActivedirectoryDomainPasswordPolicy) id() (string, error) {
	return "activedirectory/domainPasswordPolicy", nil
}

func (a *mqlActivedirectory) passwordPolicy() (*mqlActivedirectoryDomainPasswordPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	attrs := []string{
		"minPwdLength",
		"maxPwdAge",
		"minPwdAge",
		"pwdHistoryLength",
		"pwdProperties",
		"lockoutThreshold",
		"lockoutDuration",
		"lockOutObservationWindow",
	}

	result, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=domain)",
		attrs,
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to query domain password policy: %w", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no domain object found at %s", baseDN)
	}

	entry := result[0]

	minPwdLength := parseInt64Attr(entry.GetAttributeValue("minPwdLength"))
	maxPwdAge := durationToDays(parseInt64Attr(entry.GetAttributeValue("maxPwdAge")))
	minPwdAge := durationToDays(parseInt64Attr(entry.GetAttributeValue("minPwdAge")))
	pwdHistoryLength := parseInt64Attr(entry.GetAttributeValue("pwdHistoryLength"))
	pwdProperties := parseInt64Attr(entry.GetAttributeValue("pwdProperties"))
	lockoutThreshold := parseInt64Attr(entry.GetAttributeValue("lockoutThreshold"))
	lockoutDuration := durationToMinutes(parseInt64Attr(entry.GetAttributeValue("lockoutDuration")))
	lockoutObservationWindow := durationToMinutes(parseInt64Attr(entry.GetAttributeValue("lockOutObservationWindow")))

	// pwdProperties bitmask:
	//   bit 0 (0x01): DOMAIN_PASSWORD_COMPLEX — password complexity required
	//   bit 4 (0x10): DOMAIN_PASSWORD_STORE_CLEARTEXT — reversible encryption enabled
	complexityEnabled := (pwdProperties & 1) != 0
	reversibleEncryption := (pwdProperties & 16) != 0

	resource, err := CreateResource(a.MqlRuntime, "activedirectory.domainPasswordPolicy",
		map[string]*llx.RawData{
			"minPasswordLength":        llx.IntData(minPwdLength),
			"maxPasswordAge":           llx.IntData(maxPwdAge),
			"minPasswordAge":           llx.IntData(minPwdAge),
			"passwordHistoryCount":     llx.IntData(pwdHistoryLength),
			"complexityEnabled":        llx.BoolData(complexityEnabled),
			"reversibleEncryption":     llx.BoolData(reversibleEncryption),
			"lockoutThreshold":         llx.IntData(lockoutThreshold),
			"lockoutDuration":          llx.IntData(lockoutDuration),
			"lockoutObservationWindow": llx.IntData(lockoutObservationWindow),
		})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlActivedirectoryDomainPasswordPolicy), nil
}

func (a *mqlActivedirectoryFineGrainedPasswordPolicy) id() (string, error) {
	return a.DistinguishedName.Data, nil
}

func (a *mqlActivedirectory) fineGrainedPasswordPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.ActiveDirectoryConnection)
	baseDN := conn.BaseDN()

	searchBase := "CN=Password Settings Container,CN=System," + baseDN
	attrs := []string{
		"cn",
		"distinguishedName",
		"msDS-PasswordSettingsPrecedence",
		"msDS-MinimumPasswordLength",
		"msDS-MaximumPasswordAge",
		"msDS-MinimumPasswordAge",
		"msDS-PasswordHistoryLength",
		"msDS-PasswordComplexityEnabled",
		"msDS-PasswordReversibleEncryptionEnabled",
		"msDS-LockoutThreshold",
		"msDS-LockoutDuration",
		"msDS-PSOAppliesTo",
	}

	result, err := connection.PagedSearch(conn.LDAPConn(), ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDS-PasswordSettings)",
		attrs,
		nil,
	))
	if err != nil {
		// The Password Settings Container may not exist if no FGPPs are defined.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to query fine-grained password policies: %w", err)
	}

	res := make([]any, 0, len(result))
	for _, entry := range result {
		name := entry.GetAttributeValue("cn")
		dn := entry.GetAttributeValue("distinguishedName")
		precedence := parseInt64Attr(entry.GetAttributeValue("msDS-PasswordSettingsPrecedence"))
		minPwdLength := parseInt64Attr(entry.GetAttributeValue("msDS-MinimumPasswordLength"))
		maxPwdAge := durationToDays(parseInt64Attr(entry.GetAttributeValue("msDS-MaximumPasswordAge")))
		minPwdAge := durationToDays(parseInt64Attr(entry.GetAttributeValue("msDS-MinimumPasswordAge")))
		pwdHistoryLength := parseInt64Attr(entry.GetAttributeValue("msDS-PasswordHistoryLength"))
		lockoutThreshold := parseInt64Attr(entry.GetAttributeValue("msDS-LockoutThreshold"))
		lockoutDuration := durationToMinutes(parseInt64Attr(entry.GetAttributeValue("msDS-LockoutDuration")))

		// FGPP stores boolean attributes as string "TRUE"/"FALSE"
		complexityEnabled := strings.EqualFold(entry.GetAttributeValue("msDS-PasswordComplexityEnabled"), "TRUE")
		reversibleEncryption := strings.EqualFold(entry.GetAttributeValue("msDS-PasswordReversibleEncryptionEnabled"), "TRUE")

		appliesTo := entry.GetAttributeValues("msDS-PSOAppliesTo")
		appliesToRaw := make([]any, len(appliesTo))
		for i, v := range appliesTo {
			appliesToRaw[i] = v
		}

		resource, err := CreateResource(a.MqlRuntime, "activedirectory.fineGrainedPasswordPolicy",
			map[string]*llx.RawData{
				"name":                 llx.StringData(name),
				"distinguishedName":    llx.StringData(dn),
				"precedence":           llx.IntData(precedence),
				"minPasswordLength":    llx.IntData(minPwdLength),
				"maxPasswordAge":       llx.IntData(maxPwdAge),
				"minPasswordAge":       llx.IntData(minPwdAge),
				"passwordHistoryCount": llx.IntData(pwdHistoryLength),
				"complexityEnabled":    llx.BoolData(complexityEnabled),
				"reversibleEncryption": llx.BoolData(reversibleEncryption),
				"lockoutThreshold":     llx.IntData(lockoutThreshold),
				"lockoutDuration":      llx.IntData(lockoutDuration),
				"appliesTo":            llx.ArrayData(appliesToRaw, types.String),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, resource)
	}

	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations that back the Windows LSA (Local Security Authority)
// security policy. The Lsa key holds the bulk of the "Network access" /
// "Network security" security options; MSV1_0 and the WDigest provider hold the
// NTLM settings; and Netlogon\Parameters holds the secure-channel settings for
// domain members. BlockNetbiosDiscovery lives in the GPO policy hive rather
// than the Services hive, so it is read from its own key.
const (
	lsaPath               = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
	lsaMSV10Path          = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`
	lsaPKU2UPath          = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u`
	lsaWDigestPath        = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
	lsaNetlogonPath       = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
	lsaNetlogonPolicyPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Netlogon\Parameters`
)

// Registry locations of the hardening controls that live outside the Lsa key
// itself.
//
// FipsAlgorithmPolicy is a subkey of Lsa holding a single Enabled DWORD.
//
// The Kerberos supported encryption types are written by the "Network
// security: Configure encryption types allowed for Kerberos" policy to the
// Policies hive, which is the location Windows honors. The identically named
// value under Lsa\Kerberos\Parameters is the legacy location: it is still
// effective up to Windows Server 2022, so it is consulted as a fallback when
// the policy value is absent, but Windows Server 2025 (build 26100) no longer
// reads it at all, so on that release and later the fallback is skipped and an
// absent policy value resolves to null.
//
// The two LDAP server settings live under the NTDS service, which is installed
// only on a domain controller. On a member server or a standalone host the key
// does not exist at all, which is why an absent value has to resolve to null
// rather than to 0: the setting does not apply, it is not turned off. The LDAP
// client signing requirement is a separate service key present on every host.
const (
	lsaFipsPath           = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`
	lsaKerberosPath       = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
	lsaKerberosPolicyPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`
	lsaNtdsPath           = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
	lsaLdapClientPath     = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP`
)

// lsaSamPath is the Security Accounts Manager key. The SAM runs inside the LSA
// process (lsass.exe), and its password-policy switches such as
// RelaxMinimumPasswordLengthLimits live here rather than under Lsa.
const lsaSamPath = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SAM`

// Bits of the Kerberos SupportedEncryptionTypes bitmask. Only the well-known
// encryption types are decoded; the remaining high bits are reserved for future
// encryption types and are deliberately ignored, so a value that sets them
// (0x7FFFFFF8 is a common hardened setting) still decodes the known bits
// correctly.
const (
	kerberosEtypeDesCbcCrc int64 = 0x1
	kerberosEtypeDesCbcMd5 int64 = 0x2
	kerberosEtypeRc4Hmac   int64 = 0x4
	kerberosEtypeAes128    int64 = 0x8
	kerberosEtypeAes256    int64 = 0x10
)

func (r *mqlWindowsLsa) id() (string, error) {
	return "windows.lsa", nil
}

func (r *mqlWindowsLsaNtlm) id() (string, error) {
	return "windows.lsa.ntlm", nil
}

func (r *mqlWindowsLsaSecureChannel) id() (string, error) {
	return "windows.lsa.secureChannel", nil
}

// readLsaKey reads a single registry key and returns its values as a name->item
// map (lower-cased keys). A missing key yields an empty map rather than an
// error, so an absent value resolves to null (distinguishable from an explicit
// 0). A genuine read failure is surfaced to the caller.
func (r *mqlWindowsLsa) readLsaKey(path string) (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. the value was never configured); treat
		// it as empty so the corresponding fields resolve to null
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, nil
		}
		return nil, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// regStringPtr returns a pointer to the string value of a registry value, or
// nil when the value is absent. Used for REG_SZ values such as the
// restrictremotesam SDDL string and the vulnerable channel allow list.
func regStringPtr(items map[string]registry.RegistryKeyItem, name string) *string {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.String
		return &v
	}
	return nil
}

// regBoolPtr returns a pointer to the boolean interpretation of a registry
// DWORD (true for any non-zero value), or nil when the value is absent. Used
// for the on/off LSA settings whose registry value is a 0/1 DWORD.
func regBoolPtr(items map[string]registry.RegistryKeyItem, name string) *bool {
	if it, ok := items[strings.ToLower(name)]; ok {
		v := it.Value.Number != 0
		return &v
	}
	return nil
}

// lsaValues holds the extracted top-level Lsa values as nullable pointers.
// On/off settings are bools; graded settings are int64s.
type lsaValues struct {
	CrashOnAuditFail            *int64
	DisableDomainCreds          *bool
	EveryoneIncludesAnonymous   *bool
	ForceGuest                  *bool
	LimitBlankPasswordUse       *bool
	LmCompatibilityLevel        *int64
	NoLmHash                    *bool
	RestrictAnonymous           *int64
	RestrictAnonymousSam        *bool
	RestrictRemoteSam           *string
	RunAsPpl                    *int64
	SceNoApplyLegacyAuditPolicy *bool
	SubmitControl               *bool
	UseMachineId                *bool
}

// computeLsa extracts the top-level Lsa values from the raw registry items.
// Pure function for unit testing.
func computeLsa(items map[string]registry.RegistryKeyItem) lsaValues {
	return lsaValues{
		CrashOnAuditFail:            regIntPtr(items, "CrashOnAuditFail"),
		DisableDomainCreds:          regBoolPtr(items, "DisableDomainCreds"),
		EveryoneIncludesAnonymous:   regBoolPtr(items, "EveryoneIncludesAnonymous"),
		ForceGuest:                  regBoolPtr(items, "ForceGuest"),
		LimitBlankPasswordUse:       regBoolPtr(items, "LimitBlankPasswordUse"),
		LmCompatibilityLevel:        regIntPtr(items, "LmCompatibilityLevel"),
		NoLmHash:                    regBoolPtr(items, "NoLMHash"),
		RestrictAnonymous:           regIntPtr(items, "RestrictAnonymous"),
		RestrictAnonymousSam:        regBoolPtr(items, "RestrictAnonymousSAM"),
		RestrictRemoteSam:           regStringPtr(items, "restrictremotesam"),
		RunAsPpl:                    regIntPtr(items, "RunAsPPL"),
		SceNoApplyLegacyAuditPolicy: regBoolPtr(items, "SCENoApplyLegacyAuditPolicy"),
		SubmitControl:               regBoolPtr(items, "SubmitControl"),
		UseMachineId:                regBoolPtr(items, "UseMachineId"),
	}
}

// lsaNtlmValues holds the extracted NTLM (MSV1_0 + WDigest + pku2u) values as
// nullable pointers.
type lsaNtlmValues struct {
	AllowNullSessionFallback   *bool
	AuditReceivingNtlmTraffic  *int64
	NtlmMinClientSec           *int64
	NtlmMinServerSec           *int64
	RestrictSendingNtlmTraffic *int64
	UseLogonCredential         *bool
	AllowOnlineId              *bool
}

// computeLsaNtlm extracts the NTLM settings from the MSV1_0, WDigest, and pku2u
// registry items. Pure function for unit testing.
func computeLsaNtlm(msv10, wdigest, pku2u map[string]registry.RegistryKeyItem) lsaNtlmValues {
	return lsaNtlmValues{
		AllowNullSessionFallback:   regBoolPtr(msv10, "AllowNullSessionFallback"),
		AuditReceivingNtlmTraffic:  regIntPtr(msv10, "AuditReceivingNTLMTraffic"),
		NtlmMinClientSec:           regIntPtr(msv10, "NTLMMinClientSec"),
		NtlmMinServerSec:           regIntPtr(msv10, "NTLMMinServerSec"),
		RestrictSendingNtlmTraffic: regIntPtr(msv10, "RestrictSendingNTLMTraffic"),
		UseLogonCredential:         regBoolPtr(wdigest, "UseLogonCredential"),
		AllowOnlineId:              regBoolPtr(pku2u, "AllowOnlineID"),
	}
}

// lsaSecureChannelValues holds the extracted Netlogon secure-channel values as
// nullable pointers.
type lsaSecureChannelValues struct {
	AuditNtlmInDomain          *int64
	BlockNetbiosDiscovery      *bool
	DisablePasswordChange      *bool
	MaximumPasswordAge         *int64
	RefusePasswordChange       *bool
	RequireSignOrSeal          *bool
	RequireStrongKey           *bool
	SealSecureChannel          *bool
	SignSecureChannel          *bool
	VulnerableChannelAllowList *string
}

// computeLsaSecureChannel extracts the Netlogon secure-channel settings.
// BlockNetbiosDiscovery is sourced from the GPO policy hive while the remaining
// values come from the Services\Netlogon\Parameters key. Pure function for unit
// testing.
func computeLsaSecureChannel(netlogon, netlogonPolicy map[string]registry.RegistryKeyItem) lsaSecureChannelValues {
	return lsaSecureChannelValues{
		AuditNtlmInDomain:          regIntPtr(netlogon, "AuditNTLMInDomain"),
		BlockNetbiosDiscovery:      regBoolPtr(netlogonPolicy, "BlockNetbiosDiscovery"),
		DisablePasswordChange:      regBoolPtr(netlogon, "DisablePasswordChange"),
		MaximumPasswordAge:         regIntPtr(netlogon, "MaximumPasswordAge"),
		RefusePasswordChange:       regBoolPtr(netlogon, "RefusePasswordChange"),
		RequireSignOrSeal:          regBoolPtr(netlogon, "RequireSignOrSeal"),
		RequireStrongKey:           regBoolPtr(netlogon, "RequireStrongKey"),
		SealSecureChannel:          regBoolPtr(netlogon, "SealSecureChannel"),
		SignSecureChannel:          regBoolPtr(netlogon, "SignSecureChannel"),
		VulnerableChannelAllowList: regStringPtr(netlogon, "vulnerablechannelallowlist"),
	}
}

func (r *mqlWindowsLsa) crashOnAuditFail() (int64, error)           { return 0, r.populate() }
func (r *mqlWindowsLsa) disableDomainCreds() (bool, error)          { return false, r.populate() }
func (r *mqlWindowsLsa) everyoneIncludesAnonymous() (bool, error)   { return false, r.populate() }
func (r *mqlWindowsLsa) forceGuest() (bool, error)                  { return false, r.populate() }
func (r *mqlWindowsLsa) limitBlankPasswordUse() (bool, error)       { return false, r.populate() }
func (r *mqlWindowsLsa) lmCompatibilityLevel() (int64, error)       { return 0, r.populate() }
func (r *mqlWindowsLsa) noLmHash() (bool, error)                    { return false, r.populate() }
func (r *mqlWindowsLsa) restrictAnonymous() (int64, error)          { return 0, r.populate() }
func (r *mqlWindowsLsa) restrictAnonymousSam() (bool, error)        { return false, r.populate() }
func (r *mqlWindowsLsa) restrictRemoteSam() (string, error)         { return "", r.populate() }
func (r *mqlWindowsLsa) runAsPpl() (int64, error)                   { return 0, r.populate() }
func (r *mqlWindowsLsa) sceNoApplyLegacyAuditPolicy() (bool, error) { return false, r.populate() }
func (r *mqlWindowsLsa) submitControl() (bool, error)               { return false, r.populate() }
func (r *mqlWindowsLsa) useMachineId() (bool, error)                { return false, r.populate() }

// populate reads the Lsa key once and fills every top-level field. Each field
// accessor delegates here; the lazy-field machinery caches the results so the
// registry is read a single time regardless of how many fields are queried.
func (r *mqlWindowsLsa) populate() error {
	items, err := r.readLsaKey(lsaPath)
	if err != nil {
		return err
	}
	v := computeLsa(items)

	r.CrashOnAuditFail = intFieldPtr(v.CrashOnAuditFail)
	r.DisableDomainCreds = boolFieldPtr(v.DisableDomainCreds)
	r.EveryoneIncludesAnonymous = boolFieldPtr(v.EveryoneIncludesAnonymous)
	r.ForceGuest = boolFieldPtr(v.ForceGuest)
	r.LimitBlankPasswordUse = boolFieldPtr(v.LimitBlankPasswordUse)
	r.LmCompatibilityLevel = intFieldPtr(v.LmCompatibilityLevel)
	r.NoLmHash = boolFieldPtr(v.NoLmHash)
	r.RestrictAnonymous = intFieldPtr(v.RestrictAnonymous)
	r.RestrictAnonymousSam = boolFieldPtr(v.RestrictAnonymousSam)
	r.RestrictRemoteSam = stringFieldPtr(v.RestrictRemoteSam)
	r.RunAsPpl = intFieldPtr(v.RunAsPpl)
	r.SceNoApplyLegacyAuditPolicy = boolFieldPtr(v.SceNoApplyLegacyAuditPolicy)
	r.SubmitControl = boolFieldPtr(v.SubmitControl)
	r.UseMachineId = boolFieldPtr(v.UseMachineId)
	return nil
}

func (r *mqlWindowsLsa) ntlm() (*mqlWindowsLsaNtlm, error) {
	msv10, err := r.readLsaKey(lsaMSV10Path)
	if err != nil {
		return nil, err
	}
	wdigest, err := r.readLsaKey(lsaWDigestPath)
	if err != nil {
		return nil, err
	}
	pku2u, err := r.readLsaKey(lsaPKU2UPath)
	if err != nil {
		return nil, err
	}

	v := computeLsaNtlm(msv10, wdigest, pku2u)

	o, err := CreateResource(r.MqlRuntime, "windows.lsa.ntlm", map[string]*llx.RawData{
		"__id":                       llx.StringData("windows.lsa.ntlm"),
		"allowNullSessionFallback":   llx.BoolDataPtr(v.AllowNullSessionFallback),
		"auditReceivingNtlmTraffic":  llx.IntDataPtr(v.AuditReceivingNtlmTraffic),
		"ntlmMinClientSec":           llx.IntDataPtr(v.NtlmMinClientSec),
		"ntlmMinServerSec":           llx.IntDataPtr(v.NtlmMinServerSec),
		"restrictSendingNtlmTraffic": llx.IntDataPtr(v.RestrictSendingNtlmTraffic),
		"useLogonCredential":         llx.BoolDataPtr(v.UseLogonCredential),
		"allowOnlineId":              llx.BoolDataPtr(v.AllowOnlineId),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsLsaNtlm), nil
}

func (r *mqlWindowsLsa) secureChannel() (*mqlWindowsLsaSecureChannel, error) {
	netlogon, err := r.readLsaKey(lsaNetlogonPath)
	if err != nil {
		return nil, err
	}
	netlogonPolicy, err := r.readLsaKey(lsaNetlogonPolicyPath)
	if err != nil {
		return nil, err
	}

	v := computeLsaSecureChannel(netlogon, netlogonPolicy)

	o, err := CreateResource(r.MqlRuntime, "windows.lsa.secureChannel", map[string]*llx.RawData{
		"__id":                       llx.StringData("windows.lsa.secureChannel"),
		"auditNtlmInDomain":          llx.IntDataPtr(v.AuditNtlmInDomain),
		"blockNetbiosDiscovery":      llx.BoolDataPtr(v.BlockNetbiosDiscovery),
		"disablePasswordChange":      llx.BoolDataPtr(v.DisablePasswordChange),
		"maximumPasswordAge":         llx.IntDataPtr(v.MaximumPasswordAge),
		"refusePasswordChange":       llx.BoolDataPtr(v.RefusePasswordChange),
		"requireSignOrSeal":          llx.BoolDataPtr(v.RequireSignOrSeal),
		"requireStrongKey":           llx.BoolDataPtr(v.RequireStrongKey),
		"sealSecureChannel":          llx.BoolDataPtr(v.SealSecureChannel),
		"signSecureChannel":          llx.BoolDataPtr(v.SignSecureChannel),
		"vulnerableChannelAllowList": llx.StringDataPtr(v.VulnerableChannelAllowList),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsLsaSecureChannel), nil
}

// lsaKerberosValues holds the Kerberos encryption-type settings: the raw
// bitmask plus the decoded well-known bits, all nullable.
type lsaKerberosValues struct {
	SupportedEncryptionTypes *int64
	AllowsDesCbcCrc          *bool
	AllowsDesCbcMd5          *bool
	AllowsRc4Hmac            *bool
	AllowsAes128             *bool
	AllowsAes256             *bool
}

// kerberosLegacyEtypeLastBuild is the highest Windows build that still honors
// the legacy Lsa\Kerberos\Parameters\SupportedEncryptionTypes value. Windows
// Server 2025 is build 26100 and no longer reads it, so anything from that
// build on must not fall back to it.
const kerberosLegacyEtypeLastBuild = 26100

// computeLsaKerberos extracts the Kerberos supported encryption types and
// decodes the well-known bits. The policy hive wins over the legacy
// Lsa\Kerberos\Parameters location, matching how Windows resolves the setting.
//
// legacyHonored says whether this release still reads the legacy location.
// When it does not, a value left there by a pre-2025 hardening script is inert:
// reporting it would describe a configuration Windows is not applying, and
// would do so in the unsafe direction, since a leftover AES-only mask reads as
// "RC4 is not allowed" on a host whose built-in default set does allow it.
//
// When no location carries an honored value every field stays null: an absent
// value means Windows uses its built-in default set, which is not the same as a
// configured mask of 0. Pure function for unit testing.
func computeLsaKerberos(policy, legacy map[string]registry.RegistryKeyItem, legacyHonored bool) lsaKerberosValues {
	mask := regIntPtr(policy, "SupportedEncryptionTypes")
	if mask == nil && legacyHonored {
		mask = regIntPtr(legacy, "SupportedEncryptionTypes")
	}
	if mask == nil {
		return lsaKerberosValues{}
	}

	// bit reports whether one encryption type is permitted. Masking a single bit
	// keeps unknown high bits from leaking into any of the answers.
	bit := func(b int64) *bool {
		v := *mask&b != 0
		return &v
	}

	return lsaKerberosValues{
		SupportedEncryptionTypes: mask,
		AllowsDesCbcCrc:          bit(kerberosEtypeDesCbcCrc),
		AllowsDesCbcMd5:          bit(kerberosEtypeDesCbcMd5),
		AllowsRc4Hmac:            bit(kerberosEtypeRc4Hmac),
		AllowsAes128:             bit(kerberosEtypeAes128),
		AllowsAes256:             bit(kerberosEtypeAes256),
	}
}

// lsaLdapValues holds the LDAP signing and channel-binding requirements as
// nullable pointers.
type lsaLdapValues struct {
	ClientIntegrity       *int64
	EnforceChannelBinding *int64
	ServerIntegrity       *int64
}

// computeLsaLdap extracts the LDAP settings. The two server-side values come
// from the NTDS service key, which exists only on a domain controller, and the
// client-side value from the LDAP service key. Pure function for unit testing.
func computeLsaLdap(ntds, ldapClient map[string]registry.RegistryKeyItem) lsaLdapValues {
	return lsaLdapValues{
		ClientIntegrity:       regIntPtr(ldapClient, "LDAPClientIntegrity"),
		EnforceChannelBinding: regIntPtr(ntds, "LdapEnforceChannelBinding"),
		ServerIntegrity:       regIntPtr(ntds, "LDAPServerIntegrity"),
	}
}

// computeLsaFips extracts the FIPS algorithm policy from the
// Lsa\FipsAlgorithmPolicy key. Nil when the Enabled value is absent, which is
// the state of a host that never configured FIPS mode. Pure function for unit
// testing.
func computeLsaFips(fips map[string]registry.RegistryKeyItem) *bool {
	return regBoolPtr(fips, "Enabled")
}

func (r *mqlWindowsLsa) fipsAlgorithmPolicyEnabled() (bool, error) {
	items, err := r.readLsaKey(lsaFipsPath)
	if err != nil {
		return false, err
	}
	r.FipsAlgorithmPolicyEnabled = boolFieldPtr(computeLsaFips(items))
	return false, nil
}

// computeLsaSam extracts the RelaxMinimumPasswordLengthLimits switch from the
// Control\SAM key. Nil when the value is absent, which is the state of a host
// that never enabled the setting, so the 14-character cap applies. Pure
// function for unit testing.
func computeLsaSam(sam map[string]registry.RegistryKeyItem) *bool {
	return regBoolPtr(sam, "RelaxMinimumPasswordLengthLimits")
}

func (r *mqlWindowsLsa) relaxMinimumPasswordLengthLimits() (bool, error) {
	items, err := r.readLsaKey(lsaSamPath)
	if err != nil {
		return false, err
	}
	r.RelaxMinimumPasswordLengthLimits = boolFieldPtr(computeLsaSam(items))
	return false, nil
}

func (r *mqlWindowsLsa) kerberosAllowsAes128() (bool, error)    { return false, r.populateKerberos() }
func (r *mqlWindowsLsa) kerberosAllowsAes256() (bool, error)    { return false, r.populateKerberos() }
func (r *mqlWindowsLsa) kerberosAllowsDesCbcCrc() (bool, error) { return false, r.populateKerberos() }
func (r *mqlWindowsLsa) kerberosAllowsDesCbcMd5() (bool, error) { return false, r.populateKerberos() }
func (r *mqlWindowsLsa) kerberosAllowsRc4Hmac() (bool, error)   { return false, r.populateKerberos() }

func (r *mqlWindowsLsa) kerberosSupportedEncryptionTypes() (int64, error) {
	return 0, r.populateKerberos()
}

// populateKerberos reads the Kerberos encryption-type setting once and fills
// the raw bitmask together with every decoded field, so a query touching
// several of them reads the registry a single time and the answers cannot
// disagree with the mask they came from.
func (r *mqlWindowsLsa) populateKerberos() error {
	policy, err := r.readLsaKey(lsaKerberosPolicyPath)
	if err != nil {
		return err
	}
	legacy, err := r.readLsaKey(lsaKerberosPath)
	if err != nil {
		return err
	}
	v := computeLsaKerberos(policy, legacy, r.legacyKerberosEtypeHonored())

	r.KerberosSupportedEncryptionTypes = intFieldPtr(v.SupportedEncryptionTypes)
	r.KerberosAllowsAes128 = boolFieldPtr(v.AllowsAes128)
	r.KerberosAllowsAes256 = boolFieldPtr(v.AllowsAes256)
	r.KerberosAllowsDesCbcCrc = boolFieldPtr(v.AllowsDesCbcCrc)
	r.KerberosAllowsDesCbcMd5 = boolFieldPtr(v.AllowsDesCbcMd5)
	r.KerberosAllowsRc4Hmac = boolFieldPtr(v.AllowsRc4Hmac)
	return nil
}

func (r *mqlWindowsLsa) ldapClientIntegrity() (int64, error)       { return 0, r.populateLdap() }
func (r *mqlWindowsLsa) ldapEnforceChannelBinding() (int64, error) { return 0, r.populateLdap() }
func (r *mqlWindowsLsa) ldapServerIntegrity() (int64, error)       { return 0, r.populateLdap() }

// populateLdap reads the NTDS and LDAP service keys once and fills all three
// LDAP fields. On a host that is not a domain controller the NTDS key is
// missing, which readLsaKey turns into an empty map, leaving the two
// server-side fields null.
func (r *mqlWindowsLsa) populateLdap() error {
	ntds, err := r.readLsaKey(lsaNtdsPath)
	if err != nil {
		return err
	}
	ldapClient, err := r.readLsaKey(lsaLdapClientPath)
	if err != nil {
		return err
	}
	v := computeLsaLdap(ntds, ldapClient)

	r.LdapClientIntegrity = intFieldPtr(v.ClientIntegrity)
	r.LdapEnforceChannelBinding = intFieldPtr(v.EnforceChannelBinding)
	r.LdapServerIntegrity = intFieldPtr(v.ServerIntegrity)
	return nil
}

// intFieldPtr converts a nullable *int64 into the generated plugin.TValue[int64]
// field representation, marking the field null when the source pointer is nil.
func intFieldPtr(v *int64) plugin.TValue[int64] {
	if v == nil {
		return plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[int64]{Data: *v, State: plugin.StateIsSet}
}

// boolFieldPtr converts a nullable *bool into the generated plugin.TValue[bool]
// field representation, marking the field null when the source pointer is nil.
func boolFieldPtr(v *bool) plugin.TValue[bool] {
	if v == nil {
		return plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[bool]{Data: *v, State: plugin.StateIsSet}
}

// stringFieldPtr converts a nullable *string into the generated
// plugin.TValue[string] field representation, marking the field null when the
// source pointer is nil.
func stringFieldPtr(v *string) plugin.TValue[string] {
	if v == nil {
		return plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[string]{Data: *v, State: plugin.StateIsSet}
}

// initWindowsLsaNtlm resolves a bare windows.lsa.ntlm to the one the parent
// builds. The resource shares its name with the field path that reaches it, so
// `windows.lsa.ntlm.useLogonCredential` creates it directly rather than through
// windows.lsa. Its fields are plain schema fields with no accessor of their own,
// so without this the dotted form returned null for every field (and logged
// "provider returned no data and no error for a field") while the block form
// `windows.lsa { ntlm { useLogonCredential } }` returned the real values.
func initWindowsLsaNtlm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// the parent populates every field through CreateResource, which skips
	// this init; only a bare creation reaches here
	if len(args) > 0 {
		return args, nil, nil
	}

	o, err := CreateResource(runtime, "windows.lsa", nil)
	if err != nil {
		return nil, nil, err
	}
	ntlm := o.(*mqlWindowsLsa).GetNtlm()
	if ntlm.Error != nil {
		return nil, nil, ntlm.Error
	}
	if ntlm.Data == nil {
		return nil, nil, errors.New("could not read the NTLM settings from windows.lsa")
	}
	return nil, ntlm.Data, nil
}

// initWindowsLsaSecureChannel resolves a bare windows.lsa.secureChannel to the
// one the parent builds, for the same reason as initWindowsLsaNtlm.
func initWindowsLsaSecureChannel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	o, err := CreateResource(runtime, "windows.lsa", nil)
	if err != nil {
		return nil, nil, err
	}
	sc := o.(*mqlWindowsLsa).GetSecureChannel()
	if sc.Error != nil {
		return nil, nil, sc.Error
	}
	if sc.Data == nil {
		return nil, nil, errors.New("could not read the Netlogon secure-channel settings from windows.lsa")
	}
	return nil, sc.Data, nil
}

// legacyKerberosEtypeHonored reports whether this Windows release still reads
// Lsa\Kerberos\Parameters\SupportedEncryptionTypes. Windows reports its build
// as the platform version, so the test is a numeric comparison against the
// Windows Server 2025 build. An unreadable or unparseable version keeps the
// fallback, which is the behavior every release up to Windows Server 2022 needs.
func (r *mqlWindowsLsa) legacyKerberosEtypeHonored() bool {
	conn, ok := r.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return true
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return true
	}
	build, err := strconv.Atoi(asset.Platform.Version)
	if err != nil {
		return true
	}
	return build < kerberosLegacyEtypeLastBuild
}

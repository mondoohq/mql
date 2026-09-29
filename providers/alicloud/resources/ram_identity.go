// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strings"
	"sync"
	"time"

	ramclient "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/alicloud/connection"
)

// ---------------------------------------------------------------------------
// account-wide security preferences
// ---------------------------------------------------------------------------

// mqlAlicloudRamInternal memoizes the account's security preferences. Every
// flattened preference field reads the same GetSecurityPreference response, so
// querying all of them costs one call rather than one each.
type mqlAlicloudRamInternal struct {
	ramAccountState
	preferenceOnce sync.Once
	preference     *ramclient.GetSecurityPreferenceResponseBodySecurityPreference
	preferenceErr  error
}

// securityPreferences reads the account's console and credential preferences
// once. A failure is memoized alongside the value so a permission error is
// reported the same way to every field rather than retried per field.
func (r *mqlAlicloudRam) securityPreferences() (*ramclient.GetSecurityPreferenceResponseBodySecurityPreference, error) {
	r.preferenceOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			r.preferenceErr = err
			return
		}
		resp, err := client.GetSecurityPreference()
		if err != nil {
			r.preferenceErr = err
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.preference = resp.Body.SecurityPreference
	})
	return r.preference, r.preferenceErr
}

func (r *mqlAlicloudRam) allowUserToManageAccessKeys() (bool, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.AccessKeyPreference == nil {
		return false, err
	}
	return ramBoolValue(sp.AccessKeyPreference.AllowUserToManageAccessKeys), nil
}

func (r *mqlAlicloudRam) allowUserToManageMfaDevices() (bool, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.MFAPreference == nil {
		return false, err
	}
	return ramBoolValue(sp.MFAPreference.AllowUserToManageMFADevices), nil
}

func (r *mqlAlicloudRam) allowUserToManagePublicKeys() (bool, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.PublicKeyPreference == nil {
		return false, err
	}
	return ramBoolValue(sp.PublicKeyPreference.AllowUserToManagePublicKeys), nil
}

func (r *mqlAlicloudRam) allowUserToChangePassword() (bool, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.LoginProfilePreference == nil {
		return false, err
	}
	return ramBoolValue(sp.LoginProfilePreference.AllowUserToChangePassword), nil
}

func (r *mqlAlicloudRam) saveMfaTicketEnabled() (bool, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.LoginProfilePreference == nil {
		return false, err
	}
	return ramBoolValue(sp.LoginProfilePreference.EnableSaveMFATicket), nil
}

func (r *mqlAlicloudRam) loginNetworkMasks() ([]any, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.LoginProfilePreference == nil {
		return []any{}, err
	}
	return ramNetworkMasks(sp.LoginProfilePreference.LoginNetworkMasks), nil
}

func (r *mqlAlicloudRam) loginSessionDuration() (int64, error) {
	sp, err := r.securityPreferences()
	if err != nil || sp == nil || sp.LoginProfilePreference == nil {
		return 0, err
	}
	if sp.LoginProfilePreference.LoginSessionDuration == nil {
		return 0, nil
	}
	return int64(*sp.LoginProfilePreference.LoginSessionDuration), nil
}

// ramBoolValue reads a bool preference, treating an absent value as false. An
// unread permission must not report a restriction that was never confirmed.
func ramBoolValue(b *bool) bool {
	return b != nil && *b
}

// ramNetworkMasks splits the login network mask list, which the API returns as
// a single semicolon-separated string. An empty value yields an empty list,
// which is the honest reading: console sign-in is accepted from anywhere.
func ramNetworkMasks(raw *string) []any {
	value := strings.TrimSpace(ramStrVal(raw))
	if value == "" {
		return []any{}
	}
	res := []any{}
	for _, mask := range strings.Split(value, ";") {
		mask = strings.TrimSpace(mask)
		if mask == "" {
			continue
		}
		res = append(res, mask)
	}
	return res
}

// ---------------------------------------------------------------------------
// per-user console access and MFA
// ---------------------------------------------------------------------------

// ramUserCredentialState memoizes the two per-user credential lookups. Both are
// shared by several fields, so a query that reads console access and MFA
// together costs one call each rather than one per field.
type ramUserCredentialState struct {
	loginOnce sync.Once
	login     *ramclient.GetLoginProfileResponseBodyLoginProfile

	mfaOnce sync.Once
	mfa     *ramclient.GetUserMFAInfoResponseBodyMFADevice
}

// loginProfileDetail reads the user's console login profile once. A user with
// no console access makes the API return an EntityNotExist error, which is the
// answer rather than a failure, so it resolves to a nil profile.
func (r *mqlAlicloudRamUser) loginProfileDetail() *ramclient.GetLoginProfileResponseBodyLoginProfile {
	r.loginOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach RAM to read a login profile")
			return
		}
		userName := r.UserName.Data
		resp, err := client.GetLoginProfile(&ramclient.GetLoginProfileRequest{UserName: &userName})
		if err != nil {
			// EntityNotExist is the normal answer for a user with no console
			// login, so it is logged rather than surfaced as a scan failure
			log.Debug().Err(err).Str("user", userName).Msg("alicloud> could not fetch RAM user login profile")
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.login = resp.Body.LoginProfile
	})
	return r.login
}

// mfaDeviceDetail reads the user's bound MFA device once. A user with no device
// bound makes the API return an error, which resolves to a nil device.
func (r *mqlAlicloudRamUser) mfaDeviceDetail() *ramclient.GetUserMFAInfoResponseBodyMFADevice {
	r.mfaOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach RAM to read an MFA device")
			return
		}
		userName := r.UserName.Data
		resp, err := client.GetUserMFAInfo(&ramclient.GetUserMFAInfoRequest{UserName: &userName})
		if err != nil {
			log.Debug().Err(err).Str("user", userName).Msg("alicloud> could not fetch RAM user MFA info")
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.MFADevice == nil {
			return
		}
		if ramStrVal(resp.Body.MFADevice.SerialNumber) == "" {
			// the API answers with an empty device rather than an error for
			// some users; an empty serial number means nothing is bound
			return
		}
		r.mfa = resp.Body.MFADevice
	})
	return r.mfa
}

// consoleLoginEnabled reports whether the user can sign in to the console. The
// presence of a login profile is the signal; there is no separate flag.
func (r *mqlAlicloudRamUser) consoleLoginEnabled() (bool, error) {
	return r.loginProfileDetail() != nil, nil
}

func (r *mqlAlicloudRamUser) mfaBindRequired() (bool, error) {
	profile := r.loginProfileDetail()
	if profile == nil {
		// no console access, so no console MFA requirement applies
		return false, nil
	}
	return ramBoolValue(profile.MFABindRequired), nil
}

func (r *mqlAlicloudRamUser) passwordResetRequired() (bool, error) {
	profile := r.loginProfileDetail()
	if profile == nil {
		return false, nil
	}
	return ramBoolValue(profile.PasswordResetRequired), nil
}

func (r *mqlAlicloudRamUser) loginProfileCreateDate() (*time.Time, error) {
	profile := r.loginProfileDetail()
	if profile == nil {
		return nil, nil
	}
	return ramParseTime(profile.CreateDate), nil
}

func (r *mqlAlicloudRamUser) mfaEnabled() (bool, error) {
	return r.mfaDeviceDetail() != nil, nil
}

func (r *mqlAlicloudRamUser) mfaDeviceType() (string, error) {
	device := r.mfaDeviceDetail()
	if device == nil {
		return "", nil
	}
	return ramStrVal(device.Type), nil
}

func (r *mqlAlicloudRamUser) mfaDeviceSerialNumber() (string, error) {
	device := r.mfaDeviceDetail()
	if device == nil {
		return "", nil
	}
	return ramStrVal(device.SerialNumber), nil
}

// ---------------------------------------------------------------------------
// role trust policies
// ---------------------------------------------------------------------------

// ramTrustPrincipals flattens the principals named by the allowing statements
// of a trust policy, sorted and deduplicated. Denying statements are skipped:
// they narrow the trust rather than granting it, so listing their principals
// would report identities that cannot assume the role.
func ramTrustPrincipals(statements []policyStatement) []string {
	seen := map[string]struct{}{}
	for _, s := range statements {
		if !s.isAllow() {
			continue
		}
		for _, entries := range s.Principal {
			for _, p := range entries {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				seen[p] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

// ramTrustPrincipalsOfKind flattens the principals of one kind, for example
// Service or RAM, out of the allowing statements of a trust policy. The key is
// matched case-insensitively because the grammar accepts either casing.
func ramTrustPrincipalsOfKind(statements []policyStatement, kind string) []string {
	seen := map[string]struct{}{}
	for _, s := range statements {
		if !s.isAllow() {
			continue
		}
		for key, entries := range s.Principal {
			if !strings.EqualFold(key, kind) {
				continue
			}
			for _, p := range entries {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				seen[p] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

// ramPrincipalAccountID extracts the account id from a RAM principal. The two
// forms a trust policy uses are acs:ram::<uid>:root for a whole account and
// acs:ram::<uid>:user/<name> for one identity in it. Anything else, including a
// service principal or the wildcard, yields an empty string.
func ramPrincipalAccountID(principal string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(principal), "acs:ram::")
	if !ok {
		return ""
	}
	uid, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	uid = strings.TrimSpace(uid)
	if uid == "" || uid == "*" {
		return ""
	}
	return uid
}

// ramTrustedAccountIDs returns the accounts a trust policy admits, parsed out of
// its RAM principals and deduplicated.
func ramTrustedAccountIDs(statements []policyStatement) []string {
	seen := map[string]struct{}{}
	for _, p := range ramTrustPrincipalsOfKind(statements, "RAM") {
		if uid := ramPrincipalAccountID(p); uid != "" {
			seen[uid] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// sortedKeys returns the keys of a set in sorted order, so a list field is
// stable between scans rather than reflecting Go's map iteration order.
func sortedKeys(set map[string]struct{}) []string {
	res := make([]string, 0, len(set))
	for k := range set {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// strsToAny widens a []string into the []any an MQL list field takes.
func strsToAny(in []string) []any {
	res := make([]any, 0, len(in))
	for _, s := range in {
		res = append(res, s)
	}
	return res
}

// ramTrustState memoizes a role's parsed trust policy. Five fields read it, so
// the assume-role document is fetched and decoded once per role.
type ramTrustState struct {
	trustOnce   sync.Once
	parsedTrust []policyStatement
	trustErr    error
}

// parsedTrustStatements decodes the role's assume-role policy document once.
func (r *mqlAlicloudRamRole) parsedTrustStatements() ([]policyStatement, error) {
	r.trustOnce.Do(func() {
		doc := r.GetAssumeRolePolicyDocument()
		if doc.Error != nil {
			r.trustErr = doc.Error
			return
		}
		r.parsedTrust, r.trustErr = parsePolicyDocument(doc.Data)
	})
	return r.parsedTrust, r.trustErr
}

func (r *mqlAlicloudRamRole) trustStatements() ([]any, error) {
	parsed, err := r.parsedTrustStatements()
	if err != nil {
		return nil, err
	}
	return newPolicyStatements(r.MqlRuntime, "role/"+r.RoleName.Data, parsed)
}

func (r *mqlAlicloudRamRole) trustedPrincipals() ([]any, error) {
	parsed, err := r.parsedTrustStatements()
	if err != nil {
		return nil, err
	}
	return strsToAny(ramTrustPrincipals(parsed)), nil
}

func (r *mqlAlicloudRamRole) trustedAccountIds() ([]any, error) {
	parsed, err := r.parsedTrustStatements()
	if err != nil {
		return nil, err
	}
	return strsToAny(ramTrustedAccountIDs(parsed)), nil
}

func (r *mqlAlicloudRamRole) trustedServices() ([]any, error) {
	parsed, err := r.parsedTrustStatements()
	if err != nil {
		return nil, err
	}
	return strsToAny(ramTrustPrincipalsOfKind(parsed, "Service")), nil
}

func (r *mqlAlicloudRamRole) hasWildcardPrincipal() (bool, error) {
	parsed, err := r.parsedTrustStatements()
	if err != nil {
		return false, err
	}
	return policyGrantsAnonymousAccess(parsed), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"

	directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

func (g *mqlGoogleworkspace) users() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}

	// Projection("full") returns multi-value fields (sshPublicKeys,
	// posixAccounts, customSchemas, organizations, addresses, ...). The
	// default "basic" projection omits these silently, so the user-level
	// MQL fields would return null on any tenant that populates them. The
	// extra payload is on the same paginated request — no additional API
	// calls.
	users, err := directoryService.Users.List().Customer(conn.CustomerID()).Projection("full").MaxResults(500).Do()
	if err != nil {
		return nil, err
	}

	for {
		for i := range users.Users {
			r, err := newMqlGoogleWorkspaceUser(g.MqlRuntime, users.Users[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if users.NextPageToken == "" {
			break
		}

		users, err = directoryService.Users.List().Customer(conn.CustomerID()).Projection("full").MaxResults(500).PageToken(users.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func newMqlGoogleWorkspaceUser(runtime *plugin.Runtime, entry *directory.User) (any, error) {
	var lastLoginTime *time.Time
	var creationTime *time.Time
	var deletionTime *time.Time

	if llt, err := time.Parse(time.RFC3339, entry.LastLoginTime); err == nil {
		lastLoginTime = &llt
	}
	if ct, err := time.Parse(time.RFC3339, entry.CreationTime); err == nil {
		creationTime = &ct
	}
	if dt, err := time.Parse(time.RFC3339, entry.DeletionTime); err == nil {
		deletionTime = &dt
	}

	// User multi-value fields (SshPublicKeys, PosixAccounts, Emails,
	// ExternalIds, Phones, Organizations, Addresses) are typed `interface{}` on
	// the SDK struct because the create/update API accepts a single entry as
	// well as a list, but list responses always return an array. Marshal once
	// into the documented shape so we can construct typed sub-resources per
	// entry.
	sshKeys, err := buildUserSshPublicKeys(runtime, entry.Id, entry.SshPublicKeys)
	if err != nil {
		return nil, err
	}
	posix, err := buildUserPosixAccounts(runtime, entry.Id, entry.PosixAccounts)
	if err != nil {
		return nil, err
	}
	emails, err := buildUserEmails(runtime, entry.Id, entry.Emails)
	if err != nil {
		return nil, err
	}
	externalIds, err := buildUserExternalIds(runtime, entry.Id, entry.ExternalIds)
	if err != nil {
		return nil, err
	}
	phones, err := buildUserPhones(runtime, entry.Id, entry.Phones)
	if err != nil {
		return nil, err
	}
	orgs, err := buildUserOrganizations(runtime, entry.Id, entry.Organizations)
	if err != nil {
		return nil, err
	}
	addresses, err := buildUserAddresses(runtime, entry.Id, entry.Addresses)
	if err != nil {
		return nil, err
	}
	customSchemas := customSchemasToDict(entry.CustomSchemas)

	var familyName, givenName, fullName string
	if entry.Name != nil {
		familyName = entry.Name.FamilyName
		givenName = entry.Name.GivenName
		fullName = entry.Name.FullName
	}

	return CreateResource(runtime, "googleworkspace.user", map[string]*llx.RawData{
		"id":                         llx.StringData(entry.Id),
		"familyName":                 llx.StringData(familyName),
		"givenName":                  llx.StringData(givenName),
		"fullName":                   llx.StringData(fullName),
		"primaryEmail":               llx.StringData(entry.PrimaryEmail),
		"recoveryEmail":              llx.StringData(entry.RecoveryEmail),
		"recoveryPhone":              llx.StringData(entry.RecoveryPhone),
		"agreedToTerms":              llx.BoolData(entry.AgreedToTerms),
		"aliases":                    llx.ArrayData(convert.SliceAnyToInterface[string](entry.Aliases), types.Any),
		"suspended":                  llx.BoolData(entry.Suspended),
		"suspensionReason":           llx.StringData(entry.SuspensionReason),
		"archived":                   llx.BoolData(entry.Archived),
		"isAdmin":                    llx.BoolData(entry.IsAdmin),
		"isDelegatedAdmin":           llx.BoolData(entry.IsDelegatedAdmin),
		"isEnforcedIn2Sv":            llx.BoolData(entry.IsEnforcedIn2Sv),
		"isEnrolledIn2Sv":            llx.BoolData(entry.IsEnrolledIn2Sv),
		"isMailboxSetup":             llx.BoolData(entry.IsMailboxSetup),
		"orgUnitPath":                llx.StringData(entry.OrgUnitPath),
		"changePasswordAtNextLogin":  llx.BoolData(entry.ChangePasswordAtNextLogin),
		"ipWhitelisted":              llx.BoolData(entry.IpWhitelisted),
		"includeInGlobalAddressList": llx.BoolData(entry.IncludeInGlobalAddressList),
		"isGuestUser":                llx.BoolData(entry.IsGuestUser),
		"nonEditableAliases":         llx.ArrayData(convert.SliceAnyToInterface[string](entry.NonEditableAliases), types.Any),
		"thumbnailPhotoUrl":          llx.StringData(entry.ThumbnailPhotoUrl),
		"customerId":                 llx.StringData(entry.CustomerId),
		"lastLoginTime":              llx.TimeDataPtr(lastLoginTime),
		"creationTime":               llx.TimeDataPtr(creationTime),
		"deletionTime":               llx.TimeDataPtr(deletionTime),
		"hashFunction":               llx.StringData(entry.HashFunction),
		"sshPublicKeys":              llx.ArrayData(sshKeys, types.Resource("googleworkspace.user.sshPublicKey")),
		"posixAccounts":              llx.ArrayData(posix, types.Resource("googleworkspace.user.posixAccount")),
		"emails":                     llx.ArrayData(emails, types.Resource("googleworkspace.user.email")),
		"externalIds":                llx.ArrayData(externalIds, types.Resource("googleworkspace.user.externalId")),
		"phones":                     llx.ArrayData(phones, types.Resource("googleworkspace.user.phone")),
		"organizations":              llx.ArrayData(orgs, types.Resource("googleworkspace.user.organization")),
		"addresses":                  llx.ArrayData(addresses, types.Resource("googleworkspace.user.address")),
		"customSchemas":              llx.DictData(customSchemas),
	})
}

func (g *mqlGoogleworkspaceUser) id() (string, error) {
	return "googleworkspace.user/" + g.Id.Data, g.Id.Error
}

// unmarshalUserMultiValue converts a `directory.User` multi-value field
// (`interface{}` on the SDK struct because the API accepts a single entry
// or an array on create/update) into a typed slice. nil and non-array
// payloads collapse to an empty slice — list responses always return an
// array but we tolerate the create/update shape too. Marshal/unmarshal
// errors mean the SDK wire format has drifted; log so the divergence is
// diagnosable, then collapse to empty so the user stays queryable.
func unmarshalUserMultiValue[T any](v any) []T {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		log.Warn().Err(err).Msg("googleworkspace> could not marshal user multi-value payload; sub-list will be empty")
		return nil
	}
	var out []T
	if err := json.Unmarshal(data, &out); err != nil {
		log.Warn().Err(err).Msg("googleworkspace> could not unmarshal user multi-value payload into typed slice; sub-list will be empty")
		return nil
	}
	return out
}

type userEmail struct {
	Address    string `json:"address"`
	Type       string `json:"type"`
	CustomType string `json:"customType"`
	Primary    bool   `json:"primary"`
}

func buildUserEmails(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userEmail](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.email", map[string]*llx.RawData{
			"__id":       llx.StringData(fmt.Sprintf("googleworkspace.user/%s/email/%d/%s/%s", userID, i, e.Type, e.Address)),
			"address":    llx.StringData(e.Address),
			"type":       llx.StringData(e.Type),
			"customType": llx.StringData(e.CustomType),
			"primary":    llx.BoolData(e.Primary),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userPhone struct {
	Value      string `json:"value"`
	Type       string `json:"type"`
	CustomType string `json:"customType"`
	Primary    bool   `json:"primary"`
}

func buildUserPhones(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userPhone](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.phone", map[string]*llx.RawData{
			"__id":       llx.StringData(fmt.Sprintf("googleworkspace.user/%s/phone/%d/%s/%s", userID, i, e.Type, e.Value)),
			"value":      llx.StringData(e.Value),
			"type":       llx.StringData(e.Type),
			"customType": llx.StringData(e.CustomType),
			"primary":    llx.BoolData(e.Primary),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userExternalId struct {
	Value      string `json:"value"`
	Type       string `json:"type"`
	CustomType string `json:"customType"`
}

func buildUserExternalIds(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userExternalId](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.externalId", map[string]*llx.RawData{
			"__id":       llx.StringData(fmt.Sprintf("googleworkspace.user/%s/externalId/%d/%s/%s", userID, i, e.Type, e.Value)),
			"value":      llx.StringData(e.Value),
			"type":       llx.StringData(e.Type),
			"customType": llx.StringData(e.CustomType),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userAddress struct {
	Formatted          string `json:"formatted"`
	Type               string `json:"type"`
	CustomType         string `json:"customType"`
	SourceIsStructured bool   `json:"sourceIsStructured"`
	PoBox              string `json:"poBox"`
	ExtendedAddress    string `json:"extendedAddress"`
	StreetAddress      string `json:"streetAddress"`
	Locality           string `json:"locality"`
	Region             string `json:"region"`
	PostalCode         string `json:"postalCode"`
	Country            string `json:"country"`
	CountryCode        string `json:"countryCode"`
	Primary            bool   `json:"primary"`
}

func buildUserAddresses(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userAddress](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.address", map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("googleworkspace.user/%s/address/%d/%s", userID, i, e.Type)),
			"formatted":          llx.StringData(e.Formatted),
			"type":               llx.StringData(e.Type),
			"customType":         llx.StringData(e.CustomType),
			"sourceIsStructured": llx.BoolData(e.SourceIsStructured),
			"poBox":              llx.StringData(e.PoBox),
			"extendedAddress":    llx.StringData(e.ExtendedAddress),
			"streetAddress":      llx.StringData(e.StreetAddress),
			"locality":           llx.StringData(e.Locality),
			"region":             llx.StringData(e.Region),
			"postalCode":         llx.StringData(e.PostalCode),
			"country":            llx.StringData(e.Country),
			"countryCode":        llx.StringData(e.CountryCode),
			"primary":            llx.BoolData(e.Primary),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userOrganization struct {
	Name               string `json:"name"`
	Title              string `json:"title"`
	Primary            bool   `json:"primary"`
	Type               string `json:"type"`
	CustomType         string `json:"customType"`
	Department         string `json:"department"`
	Symbol             string `json:"symbol"`
	Location           string `json:"location"`
	Description        string `json:"description"`
	CostCenter         string `json:"costCenter"`
	FullTimeEquivalent int64  `json:"fullTimeEquivalent"`
	Domain             string `json:"domain"`
}

func buildUserOrganizations(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userOrganization](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.organization", map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("googleworkspace.user/%s/organization/%d/%s/%s/%s", userID, i, e.Name, e.Department, e.Title)),
			"name":               llx.StringData(e.Name),
			"title":              llx.StringData(e.Title),
			"primary":            llx.BoolData(e.Primary),
			"type":               llx.StringData(e.Type),
			"customType":         llx.StringData(e.CustomType),
			"department":         llx.StringData(e.Department),
			"symbol":             llx.StringData(e.Symbol),
			"location":           llx.StringData(e.Location),
			"description":        llx.StringData(e.Description),
			"costCenter":         llx.StringData(e.CostCenter),
			"fullTimeEquivalent": llx.IntData(e.FullTimeEquivalent),
			"domain":             llx.StringData(e.Domain),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userPosixAccount struct {
	Username            string `json:"username"`
	Uid                 string `json:"uid"` // SDK encodes as string ("uint64-as-string")
	Gid                 string `json:"gid"`
	HomeDirectory       string `json:"homeDirectory"`
	Shell               string `json:"shell"`
	SystemId            string `json:"systemId"`
	AccountId           string `json:"accountId"`
	OperatingSystemType string `json:"operatingSystemType"`
	Primary             bool   `json:"primary"`
}

func buildUserPosixAccounts(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userPosixAccount](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		mql, err := CreateResource(runtime, "googleworkspace.user.posixAccount", map[string]*llx.RawData{
			"__id":                llx.StringData(fmt.Sprintf("googleworkspace.user/%s/posixAccount/%d/%s/%s", userID, i, e.SystemId, e.Username)),
			"username":            llx.StringData(e.Username),
			"uid":                 llx.IntData(parseInt64(e.Uid)),
			"gid":                 llx.IntData(parseInt64(e.Gid)),
			"homeDirectory":       llx.StringData(e.HomeDirectory),
			"shell":               llx.StringData(e.Shell),
			"systemId":            llx.StringData(e.SystemId),
			"accountId":           llx.StringData(e.AccountId),
			"operatingSystemType": llx.StringData(e.OperatingSystemType),
			"primary":             llx.BoolData(e.Primary),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

type userSshPublicKey struct {
	Key                string `json:"key"`
	ExpirationTimeUsec string `json:"expirationTimeUsec"`
	Fingerprint        string `json:"fingerprint"`
}

func buildUserSshPublicKeys(runtime *plugin.Runtime, userID string, v any) ([]any, error) {
	entries := unmarshalUserMultiValue[userSshPublicKey](v)
	out := make([]any, 0, len(entries))
	for i, e := range entries {
		// Prefer fingerprint (server-issued, stable) over key contents; fall
		// back to index so two keys without a fingerprint still get distinct ids.
		keyDisc := e.Fingerprint
		if keyDisc == "" {
			keyDisc = strconv.Itoa(i)
		}
		mql, err := CreateResource(runtime, "googleworkspace.user.sshPublicKey", map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("googleworkspace.user/%s/sshPublicKey/%s", userID, keyDisc)),
			"key":                llx.StringData(e.Key),
			"expirationTimeUsec": llx.StringData(e.ExpirationTimeUsec),
			"fingerprint":        llx.StringData(e.Fingerprint),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, mql)
	}
	return out, nil
}

// parseInt64 best-effort converts a numeric string (typically a uint64 the
// SDK encoded as a string for JSON-safety) into an int64. Empty / invalid
// values collapse to 0, consistent with the SDK semantics for unset fields.
func parseInt64(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// customSchemasToDict converts the directory.User.CustomSchemas map (each
// value a JSON-encoded blob of org-defined custom fields) into a flat
// dict-of-dicts keyed by schema name. Schemas that fail to decode are
// skipped.
func customSchemasToDict(schemas map[string]googleapi.RawMessage) map[string]any {
	if len(schemas) == 0 {
		return nil
	}
	out := make(map[string]any, len(schemas))
	for name, raw := range schemas {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		out[name] = v
	}
	return out
}

// usageReport resolves the user's daily usage report from the parent
// googleworkspace resource's shared cache. The cache is populated by a
// single batched `UserUsageReport.Get("all", date)` call across the whole
// customer, so per-user lookups are map reads — no per-user API call, and
// the date-discovery retry loop runs once for the whole tenant instead of
// once per user.
func (g *mqlGoogleworkspaceUser) usageReport() (*mqlGoogleworkspaceReportUsage, error) {
	if g.PrimaryEmail.Error != nil {
		return nil, g.PrimaryEmail.Error
	}
	primaryEmail := g.PrimaryEmail.Data

	parent, err := workspaceResource(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	reportsByEmail, _, err := parent.loadUsageReports()
	if err != nil {
		return nil, err
	}
	report, ok := reportsByEmail[primaryEmail]
	if !ok {
		// User has no published usage report on the most recent available
		// date — common for recently provisioned, suspended, or deleted
		// users. Surface this as a null field rather than an error so audits
		// can still iterate the user list.
		g.UsageReport.State = plugin.StateIsSet | plugin.StateIsNull
		// A customer with no published reports at all (date == "") is not an
		// error condition — return a null field so `users { usageReport }`
		// doesn't fail for every user on a new/report-disabled tenant.
		return nil, nil
	}
	return newMqlGoogleWorkspaceUsageReport(g.MqlRuntime, report)
}

// shouldCheckEarlierDateForReport matches the two 400 errors Google
// returns when the requested date is in the future or beyond the
// most-recent published report. It drives the day-walk-back loop in
// fetchAllUsageReports.
func shouldCheckEarlierDateForReport(err error) bool {
	if strings.Contains(err.Error(), "Error 400: Start date can not be later than ") {
		return true
	}
	if strings.Contains(err.Error(), "Error 400: Data for dates later than ") {
		return true
	}
	return false
}

func (g *mqlGoogleworkspaceUser) tokens() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryUserSecurityScope)
	if err != nil {
		return nil, err
	}

	if g.PrimaryEmail.Error != nil {
		return nil, g.PrimaryEmail.Error
	}
	primaryEmail := g.PrimaryEmail.Data

	tokenList, err := directoryService.Tokens.List(primaryEmail).Do()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range tokenList.Items {
		r, err := newMqlGoogleWorkspaceToken(g.MqlRuntime, tokenList.Items[i])
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func newMqlGoogleWorkspaceToken(runtime *plugin.Runtime, entry *directory.Token) (any, error) {
	return CreateResource(runtime, "googleworkspace.token", map[string]*llx.RawData{
		"anonymous":   llx.BoolData(entry.Anonymous),
		"clientId":    llx.StringData(entry.ClientId),
		"displayText": llx.StringData(entry.DisplayText),
		"nativeApp":   llx.BoolData(entry.NativeApp),
		"scopes":      llx.ArrayData(convert.SliceAnyToInterface[string](entry.Scopes), types.Any),
		"userKey":     llx.StringData(entry.UserKey),
	})
}

func (g *mqlGoogleworkspaceToken) id() (string, error) {
	if g.ClientId.Error != nil {
		return "", g.ClientId.Error
	}
	clientID := g.ClientId.Data

	if g.UserKey.Error != nil {
		return "", g.UserKey.Error
	}
	userKey := g.UserKey.Data

	return "googleworkspace.token/" + userKey + "/" + clientID, nil
}

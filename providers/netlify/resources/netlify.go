// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlNetlify) id() (string, error) {
	return "netlify", nil
}

// --- shared helpers -------------------------------------------------------

// netlifyTime decodes a Netlify timestamp, which arrives as an RFC 3339 string
// and is absent or empty on records that never reached the state it describes.
type netlifyTime struct {
	t *time.Time
}

func (n *netlifyTime) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if str == "" {
		return nil
	}
	tt, err := time.Parse(time.RFC3339, str)
	if err != nil {
		// A few fields carry a plain calendar date rather than a full
		// timestamp, so that shape is parsed before treating the value as
		// unreadable.
		if day, dayErr := time.Parse(time.DateOnly, str); dayErr == nil {
			n.t = &day
			return nil
		}
		// A timestamp the API changed the shape of is reported as null rather
		// than failing the whole resource, but it is logged so the change is
		// visible instead of looking like a record that never reached the
		// state the field describes.
		log.Warn().Str("value", str).Msg("netlify> could not parse timestamp; reporting it as null")
		return nil
	}
	n.t = &tt
	return nil
}

// Time returns the decoded time value, or nil when the source was absent.
func (n netlifyTime) Time() *time.Time {
	return n.t
}

// optionalBool reports a control the API omits as null rather than as false, so
// a site that has never set it is distinguishable from one that set it off.
func optionalBool(v *bool) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.BoolData(*v)
}

// optionalString reports a value the API omits as null rather than as the empty
// string, so a field it did not report stays apart from one reported as blank.
func optionalString(v *string) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.StringData(*v)
}

// optionalInt reports a value the API omits as null rather than as zero, which
// would otherwise read as a real count or identifier of zero.
func optionalInt(v *int64) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(*v)
}

// rawJSONToDict decodes a JSON value whose shape varies by key into a dict. A
// value the API did not report stays null rather than becoming an empty map,
// which would read as a record that carries nothing rather than one that was
// never asked about.
func rawJSONToDict(raw json.RawMessage) *llx.RawData {
	if len(raw) == 0 {
		return llx.NilData
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		log.Warn().Msg("netlify> could not decode a JSON value; reporting it as null")
		return llx.NilData
	}
	if v == nil {
		return llx.NilData
	}
	return llx.DictData(v)
}

// mapStrToAny widens a string map into the any-valued map llx.MapData expects.
func mapStrToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// strSliceToAny widens a string slice into an any slice for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// netlifyConn returns the Netlify connection backing the runtime.
func netlifyConn(runtime *plugin.Runtime) *connection.NetlifyConnection {
	return runtime.Connection.(*connection.NetlifyConnection)
}

// getNetlify returns the root resource, which every cross-resource accessor
// goes through so that its cached account and site lists are reused rather
// than refetched.
func getNetlify(runtime *plugin.Runtime) (*mqlNetlify, error) {
	res, err := CreateResource(runtime, "netlify", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNetlify), nil
}

// findCachedResource looks for the entry identified by want in a list the root
// resource has already fetched, so that resolving a reference on many records
// costs one call for the whole scan rather than one call per record.
//
// A miss is reported rather than treated as an absence: the root lists are
// narrowed by the account and site the connection is scoped to, so a record can
// name something that is reachable but outside that scope. Callers fall back to
// a direct lookup on a miss, which keeps the scoped-out case behaving as it did
// before the list was consulted at all. An unreadable list is a miss for the
// same reason.
func findCachedResource[T any](list *plugin.TValue[[]any], id func(T) string, want string) (T, bool) {
	var zero T
	if want == "" || list.Error != nil || list.State&plugin.StateIsNull != 0 {
		return zero, false
	}
	for _, it := range list.Data {
		entry, ok := it.(T)
		if ok && id(entry) == want {
			return entry, true
		}
	}
	return zero, false
}

func netlifyAccountID(a *mqlNetlifyAccount) string     { return a.Id.Data }
func netlifySiteID(s *mqlNetlifySite) string           { return s.Id.Data }
func netlifyDeployKeyID(k *mqlNetlifyDeployKey) string { return k.Id.Data }

func netlifySiteDeployID(d *mqlNetlifySiteDeploy) string { return d.Id.Data }

// --- root resource --------------------------------------------------------

type userRecord struct {
	ID                string            `json:"id"`
	UID               string            `json:"uid"`
	Email             string            `json:"email"`
	FullName          string            `json:"full_name"`
	AvatarURL         string            `json:"avatar_url"`
	LoginProviders    []string          `json:"login_providers"`
	MfaEnabled        bool              `json:"mfa_enabled"`
	ConnectedAccounts map[string]string `json:"connected_accounts"`
	ManagedBySso      bool              `json:"managed_by_sso_or_directory_sync"`
	SiteCount         int64             `json:"site_count"`
	CreatedAt         netlifyTime       `json:"created_at"`
	LastLogin         netlifyTime       `json:"last_login"`
}

func (n *mqlNetlify) currentUser() (*mqlNetlifyUser, error) {
	c := netlifyConn(n.MqlRuntime)

	var rec userRecord
	if err := c.Get(context.Background(), "/user", nil, &rec); err != nil {
		return nil, err
	}

	id := rec.ID
	if id == "" {
		id = rec.UID
	}

	res, err := CreateResource(n.MqlRuntime, "netlify.user", map[string]*llx.RawData{
		"id":                          llx.StringData(id),
		"email":                       llx.StringData(rec.Email),
		"fullName":                    llx.StringData(rec.FullName),
		"avatarUrl":                   llx.StringData(rec.AvatarURL),
		"loginProviders":              llx.ArrayData(strSliceToAny(rec.LoginProviders), types.String),
		"mfaEnabled":                  llx.BoolData(rec.MfaEnabled),
		"connectedAccounts":           llx.MapData(mapStrToAny(rec.ConnectedAccounts), types.String),
		"managedBySsoOrDirectorySync": llx.BoolData(rec.ManagedBySso),
		"siteCount":                   llx.IntData(rec.SiteCount),
		"createdAt":                   llx.TimeDataPtr(rec.CreatedAt.Time()),
		"lastLogin":                   llx.TimeDataPtr(rec.LastLogin.Time()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNetlifyUser), nil
}

func (n *mqlNetlifyUser) id() (string, error) {
	return n.Id.Data, n.Id.Error
}

// sites flattens every site of every account in scope. The account list is
// read through its cached field so that querying accounts and sites together
// walks the accounts endpoint once rather than once per field.
func (n *mqlNetlify) sites() ([]any, error) {
	accounts := n.GetAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}

	var res []any
	for _, it := range accounts.Data {
		account := it.(*mqlNetlifyAccount)
		sites := account.GetSites()
		if sites.Error != nil {
			return nil, sites.Error
		}
		res = append(res, sites.Data...)
	}
	return res, nil
}

// dnsZones lists the Netlify-managed DNS zones of every account in scope.
func (n *mqlNetlify) dnsZones() ([]any, error) {
	c := netlifyConn(n.MqlRuntime)

	records, err := connection.GetPaged[dnsZoneRecord](context.Background(), c, "/dns_zones", nil)
	if err != nil {
		return nil, err
	}

	accountFilter := c.AccountFilter()

	var res []any
	for i := range records {
		rec := records[i]
		if accountFilter != "" && rec.AccountID != accountFilter && rec.AccountSlug != accountFilter {
			continue
		}
		zone, err := newNetlifyDnsZone(n.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, zone)
	}
	return res, nil
}

type deployKeyRecord struct {
	ID        string      `json:"id"`
	PublicKey string      `json:"public_key"`
	CreatedAt netlifyTime `json:"created_at"`
}

func (n *mqlNetlify) deployKeys() ([]any, error) {
	c := netlifyConn(n.MqlRuntime)

	records, err := connection.GetPaged[deployKeyRecord](context.Background(), c, "/deploy_keys", nil)
	if err != nil {
		return nil, err
	}

	var res []any
	for i := range records {
		key, err := newNetlifyDeployKey(n.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, key)
	}
	return res, nil
}

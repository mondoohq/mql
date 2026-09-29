// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0/management"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAuth0) id() (string, error) {
	return "auth0", nil
}

// initAuth0Tenant reads the tenant-wide settings singleton. It is queried
// directly (auth0.tenant); its cache key is the tenant domain, since there is
// exactly one tenant per connection.
func initAuth0Tenant(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	t, err := conn.Client().Tenant.Read(context.Background())
	if err != nil {
		return nil, nil, err
	}

	flags, err := convert.JsonToDict(t.Flags)
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(conn.Domain())
	args["friendlyName"] = llx.StringDataPtr(t.FriendlyName)
	args["supportEmail"] = llx.StringDataPtr(t.SupportEmail)
	args["supportUrl"] = llx.StringDataPtr(t.SupportURL)
	args["pictureUrl"] = llx.StringDataPtr(t.PictureURL)
	args["allowedLogoutUrls"] = llx.ArrayData(strList(t.AllowedLogoutURLs), types.String)
	args["sessionLifetime"] = floatPtr(t.SessionLifetime)
	args["idleSessionLifetime"] = floatPtr(t.IdleSessionLifetime)
	args["defaultAudience"] = llx.StringDataPtr(t.DefaultAudience)
	args["defaultDirectory"] = llx.StringDataPtr(t.DefaultDirectory)
	args["enabledLocales"] = llx.ArrayData(strList(t.EnabledLocales), types.String)
	args["flags"] = llx.DictData(flags)
	oidcPrompt, anonLifetime, anonCookie := tenantSessionSettings(t.Sessions)
	args["oidcLogoutPromptEnabled"] = llx.BoolDataPtr(oidcPrompt)
	args["anonymousSessionLifetime"] = llx.IntDataPtr(anonLifetime)
	args["anonymousSessionCookieEnabled"] = llx.BoolDataPtr(anonCookie)
	return args, nil, nil
}

// tenantSessionSettings returns the OIDC logout prompt flag and the anonymous
// session lifetime and cookie flag, each nil when the API did not report it.
func tenantSessionSettings(s *management.TenantSessions) (oidcLogoutPrompt *bool, anonymousLifetime *int, anonymousCookie *bool) {
	if s == nil {
		return nil, nil, nil
	}
	if s.Anonymous != nil {
		anonymousLifetime = s.Anonymous.LifetimeInMinutes
		anonymousCookie = s.Anonymous.ActivateCookie
	}
	return s.OIDCLogoutPromptEnabled, anonymousLifetime, anonymousCookie
}

// auth0conn returns the Auth0 connection backing this runtime.
func (r *mqlAuth0) conn() *connection.Auth0Connection {
	return r.MqlRuntime.Connection.(*connection.Auth0Connection)
}

// strList converts a *[]string (as returned by the SDK) into an MQL string
// array value, treating a nil pointer as an empty list.
func strList(s *[]string) []any {
	if s == nil {
		return []any{}
	}
	res := make([]any, 0, len(*s))
	for _, v := range *s {
		res = append(res, v)
	}
	return res
}

// floatPtr converts a *float64 into an MQL float value, preserving nil as null.
func floatPtr(v *float64) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.FloatData(*v)
}

// mapBool safely extracts a boolean value from a loosely typed JSON map
// (map[string]interface{}), returning nil when the key is absent or not a bool.
func mapBool(m map[string]interface{}, key string) *bool {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(bool); ok {
		return &v
	}
	return nil
}

// mapInt safely extracts an integer value from a loosely typed JSON map,
// tolerating the float64 that encoding/json produces for numbers.
func mapInt(m map[string]interface{}, key string) *int64 {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case float64:
		i := int64(v)
		return &i
	case int:
		i := int64(v)
		return &i
	case int64:
		return &v
	}
	return nil
}

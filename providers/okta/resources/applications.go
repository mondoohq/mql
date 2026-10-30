// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

// oktaApplicationRaw captures the fields we expose from Okta's polymorphic
// application response. The SDK returns a discriminated union
// (ListApplications200ResponseInner) whose concrete variants differ per app
// type; rather than switch on every variant we re-marshal each entry to its
// canonical JSON and decode the shared fields here.
type oktaApplicationRaw struct {
	Id          string          `json:"id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Label       string          `json:"label,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
	SignOnMode  string          `json:"signOnMode,omitempty"`
	Status      string          `json:"status,omitempty"`
	Features    []string        `json:"features,omitempty"`
	Credentials json.RawMessage `json:"credentials,omitempty"`
	Licensing   json.RawMessage `json:"licensing,omitempty"`
	Profile     json.RawMessage `json:"profile,omitempty"`
	Settings    json.RawMessage `json:"settings,omitempty"`
	Visibility  json.RawMessage `json:"visibility,omitempty"`

	UniversalLogout *oktaUniversalLogoutRaw `json:"universalLogout,omitempty"`
}

// oktaUniversalLogoutRaw is the application's Universal Logout block. It is
// absent on applications Okta cannot sign the user out of, which is why the
// pointer is kept rather than flattened: the whole block missing and every
// value within it being empty are the same reading, but only one of them is
// worth telling apart from a value the API declined to report.
type oktaUniversalLogoutRaw struct {
	IdentityStack string `json:"identityStack,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Status        string `json:"status,omitempty"`
	SupportType   string `json:"supportType,omitempty"`
}

func oktaApplicationFromUnion(item okta.ListApplications200ResponseInner) (*oktaApplicationRaw, error) {
	raw, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}
	var app oktaApplicationRaw
	if err := json.Unmarshal(raw, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

func (o *mqlOkta) applications() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	appSetSlice, resp, err := client.ApplicationAPI.ListApplications(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(appSetSlice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListApplications200ResponseInner) error {
		for i := range datalist {
			app, err := oktaApplicationFromUnion(datalist[i])
			if err != nil {
				return err
			}
			r, err := newMqlOktaApplication(o.MqlRuntime, app)
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	err = appendEntry(appSetSlice)
	if err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.ListApplications200ResponseInner
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		err = appendEntry(page)
		if err != nil {
			return nil, err
		}
	}
	return list, nil
}

func initOktaApplication(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If we already have the full set of fields, no fetch needed.
	if len(args) > 1 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		// Bare resource construction (no id) is a valid empty state.
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()
	item, resp, err := client.ApplicationAPI.GetApplication(ctx, id).Execute()
	if err != nil {
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.application %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}
	if item == nil {
		return args, nil, nil
	}

	app, err := oktaApplicationFromUnion(*item)
	if err != nil {
		return nil, nil, err
	}
	appArgs, err := oktaApplicationArgs(app)
	if err != nil {
		return nil, nil, err
	}
	maps.Copy(args, appArgs)
	return args, nil, nil
}

func oktaApplicationArgs(entry *oktaApplicationRaw) (map[string]*llx.RawData, error) {
	credentials, err := convert.JsonToDict(entry.Credentials)
	if err != nil {
		return nil, err
	}

	licensing, err := convert.JsonToDict(entry.Licensing)
	if err != nil {
		return nil, err
	}

	profile, err := convert.JsonToDict(entry.Profile)
	if err != nil {
		return nil, err
	}

	settings, err := convert.JsonToDict(entry.Settings)
	if err != nil {
		return nil, err
	}

	// An application without the block reports empty rather than null, which
	// matches how every other absent string on this resource reads.
	ul := entry.UniversalLogout
	if ul == nil {
		ul = &oktaUniversalLogoutRaw{}
	}

	visibility, err := convert.JsonToDict(entry.Visibility)
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":                           llx.StringData(entry.Id),
		"name":                         llx.StringData(entry.Name),
		"label":                        llx.StringData(entry.Label),
		"created":                      llx.TimeDataPtr(entry.Created),
		"lastUpdated":                  llx.TimeDataPtr(entry.LastUpdated),
		"credentials":                  llx.DictData(credentials),
		"features":                     llx.ArrayData(convert.SliceAnyToInterface(entry.Features), types.String),
		"licensing":                    llx.DictData(licensing),
		"profile":                      llx.DictData(profile),
		"settings":                     llx.DictData(settings),
		"signOnMode":                   llx.StringData(entry.SignOnMode),
		"status":                       llx.StringData(entry.Status),
		"visibility":                   llx.DictData(visibility),
		"universalLogoutStatus":        llx.StringData(ul.Status),
		"universalLogoutSupportType":   llx.StringData(ul.SupportType),
		"universalLogoutProtocol":      llx.StringData(ul.Protocol),
		"universalLogoutIdentityStack": llx.StringData(ul.IdentityStack),
	}, nil
}

func newMqlOktaApplication(runtime *plugin.Runtime, entry *oktaApplicationRaw) (any, error) {
	args, err := oktaApplicationArgs(entry)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "okta.application", args)
}

func (o *mqlOktaApplication) id() (string, error) {
	return "okta.application/" + o.Id.Data, o.Id.Error
}

// signingKeys returns the X.509 signing certificates / JWKs published for this app.
// These are used to sign SAML assertions and OIDC tokens, so checking expiresAt and
// status is essential for catching expired/about-to-expire signing certs.
func (o *mqlOktaApplication) signingKeys() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	keys, resp, err := client.ApplicationSSOCredentialKeyAPI.ListApplicationKeys(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendKeys := func(entries []okta.JsonWebKey) error {
		for i := range entries {
			k := entries[i]
			r, err := CreateResource(o.MqlRuntime, "okta.application.key", map[string]*llx.RawData{
				"applicationId": llx.StringData(o.Id.Data),
				"kid":           llx.StringData(oktaStr(k.Kid)),
				"status":        llx.StringData(oktaStrFrom(k.AdditionalProperties["status"])),
				"alg":           llx.StringData(oktaStrFrom(k.AdditionalProperties["alg"])),
				"kty":           llx.StringData(oktaStr(k.Kty)),
				"use":           llx.StringData(oktaStr(k.Use)),
				"keyOps":        llx.ArrayData(oktaAnySliceFrom(k.AdditionalProperties["key_ops"]), types.String),
				"created":       llx.TimeDataPtr(k.Created),
				"lastUpdated":   llx.TimeDataPtr(k.LastUpdated),
				"expiresAt":     llx.TimeDataPtr(k.ExpiresAt),
				"x5c":           llx.ArrayData(convert.SliceAnyToInterface(k.X5c), types.String),
				"x5t":           llx.StringData(oktaStrFrom(k.AdditionalProperties["x5t"])),
				"x5tS256":       llx.StringData(oktaStr(k.X5tS256)),
				"n":             llx.StringData(oktaStr(k.N)),
				"e":             llx.StringData(oktaStr(k.E)),
			})
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendKeys(keys); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.JsonWebKey
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendKeys(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func (o *mqlOktaApplicationKey) id() (string, error) {
	return "okta.application.key/" + o.ApplicationId.Data + "/" + o.Kid.Data, o.Kid.Error
}

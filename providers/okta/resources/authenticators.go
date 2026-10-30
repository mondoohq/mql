// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

// mqlOktaAuthenticatorInternal caches the provider and settings sub-objects of
// the authenticator so the typed accessors can resolve them lazily. The SDK returns
// authenticators as a discriminated union, so we decode the shared fields from
// the canonical JSON instead of reading SDK structs directly.
type mqlOktaAuthenticatorInternal struct {
	provider *oktaAuthenticatorProvider
	settings *oktaAuthenticatorSettings
}

type oktaAuthenticatorRaw struct {
	Id          string          `json:"id,omitempty"`
	Key         string          `json:"key,omitempty"`
	Name        string          `json:"name,omitempty"`
	Type        string          `json:"type,omitempty"`
	Status      string          `json:"status,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
	Settings    json.RawMessage `json:"settings,omitempty"`
	Provider    json.RawMessage `json:"provider,omitempty"`
}

type oktaAuthenticatorSettings struct {
	AllowedFor             string `json:"allowedFor,omitempty"`
	TokenLifetimeInMinutes *int64 `json:"tokenLifetimeInMinutes,omitempty"`
	UserVerification       string `json:"userVerification,omitempty"`
}

type oktaAuthenticatorProvider struct {
	Type          string          `json:"type,omitempty"`
	Configuration json.RawMessage `json:"configuration,omitempty"`
}

func (o *mqlOkta) authenticators() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	authenticators, resp, err := client.AuthenticatorAPI.ListAuthenticators(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntries := func(entries []okta.ListAuthenticators200ResponseInner) error {
		for i := range entries {
			raw, err := json.Marshal(entries[i])
			if err != nil {
				return err
			}
			var entry oktaAuthenticatorRaw
			if err := json.Unmarshal(raw, &entry); err != nil {
				return err
			}
			r, err := newMqlOktaAuthenticator(o.MqlRuntime, &entry)
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntries(authenticators); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.ListAuthenticators200ResponseInner
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntries(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaAuthenticator(runtime *plugin.Runtime, entry *oktaAuthenticatorRaw) (*mqlOktaAuthenticator, error) {
	args := map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"key":         llx.StringData(entry.Key),
		"name":        llx.StringData(entry.Name),
		"type":        llx.StringData(entry.Type),
		"status":      llx.StringData(entry.Status),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	}

	var settings *oktaAuthenticatorSettings
	if len(entry.Settings) > 0 {
		dict, err := convert.JsonToDict(entry.Settings)
		if err != nil {
			return nil, err
		}
		args["settings"] = llx.DictData(dict)

		settings = &oktaAuthenticatorSettings{}
		if err := json.Unmarshal(entry.Settings, settings); err != nil {
			return nil, err
		}
	} else {
		args["settings"] = llx.DictData(map[string]any{})
	}

	var provider *oktaAuthenticatorProvider
	if len(entry.Provider) > 0 {
		provider = &oktaAuthenticatorProvider{}
		if err := json.Unmarshal(entry.Provider, provider); err != nil {
			return nil, err
		}
	}

	r, err := CreateResource(runtime, "okta.authenticator", args)
	if err != nil {
		return nil, err
	}
	mqlAuth := r.(*mqlOktaAuthenticator)
	mqlAuth.provider = provider
	mqlAuth.settings = settings
	return mqlAuth, nil
}

func (o *mqlOktaAuthenticator) id() (string, error) {
	return "okta.authenticator/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaAuthenticator) providerType() (string, error) {
	if o.provider == nil || o.provider.Type == "" {
		o.ProviderType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return o.provider.Type, nil
}

func (o *mqlOktaAuthenticator) providerConfiguration() (any, error) {
	if o.provider == nil || len(o.provider.Configuration) == 0 {
		o.ProviderConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.JsonToDict(o.provider.Configuration)
}

func (o *mqlOktaAuthenticator) allowedFor() (string, error) {
	if o.settings == nil || o.settings.AllowedFor == "" {
		o.AllowedFor.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return o.settings.AllowedFor, nil
}

func (o *mqlOktaAuthenticator) tokenLifetimeInMinutes() (int64, error) {
	if o.settings == nil || o.settings.TokenLifetimeInMinutes == nil {
		o.TokenLifetimeInMinutes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *o.settings.TokenLifetimeInMinutes, nil
}

func (o *mqlOktaAuthenticator) userVerification() (string, error) {
	if o.settings == nil || o.settings.UserVerification == "" {
		o.UserVerification.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return o.settings.UserVerification, nil
}

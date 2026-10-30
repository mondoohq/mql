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
	"go.mondoo.com/mql/types"
)

// authzServerPolicyRaw captures the authorization-server policy fields we
// expose. The SDK keeps these scalars in the model's AdditionalProperties map, so we
// decode the canonical JSON into this shared shape instead.
type authzServerPolicyRaw struct {
	Id          string          `json:"id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Priority    int64           `json:"priority,omitempty"`
	Status      string          `json:"status,omitempty"`
	System      *bool           `json:"system,omitempty"`
	Type        string          `json:"type,omitempty"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
}

func (o *mqlOkta) authorizationServers() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	servers, resp, err := client.AuthorizationServerAPI.ListAuthorizationServers(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(entries []okta.AuthorizationServer) error {
		for i := range entries {
			r, err := newMqlOktaAuthorizationServer(o.MqlRuntime, &entries[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(servers); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.AuthorizationServer
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaAuthorizationServer(runtime *plugin.Runtime, entry *okta.AuthorizationServer) (any, error) {
	// The SDK does not type the `default` flag on the authorization server; it
	// is returned as an additional property, so read it from there.
	defaultValue := false
	if v, ok := entry.AdditionalProperties["default"].(bool); ok {
		defaultValue = v
	}

	var signingKid, signingRotationMode, signingUse string
	var signingLastRotated, signingNextRotation *time.Time
	if entry.Credentials != nil && entry.Credentials.Signing != nil {
		s := entry.Credentials.Signing
		signingKid = oktaStr(s.Kid)
		signingRotationMode = oktaStr(s.RotationMode)
		signingUse = oktaStr(s.Use)
		signingLastRotated = s.LastRotated
		signingNextRotation = s.NextRotation
	}

	// Jwks is the key set tokens are encrypted against, which is a different
	// set from the signing keys the server publishes.
	jwks, err := convert.JsonToDict(entry.Jwks)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.authorizationServer", map[string]*llx.RawData{
		"id":                                    llx.StringData(oktaStr(entry.Id)),
		"name":                                  llx.StringData(oktaStr(entry.Name)),
		"description":                           llx.StringData(oktaStr(entry.Description)),
		"status":                                llx.StringData(oktaStr(entry.Status)),
		"default":                               llx.BoolData(defaultValue),
		"issuer":                                llx.StringData(oktaStr(entry.Issuer)),
		"issuerMode":                            llx.StringData(oktaStr(entry.IssuerMode)),
		"accessTokenEncryptedResponseAlgorithm": llx.StringData(oktaStr(entry.AccessTokenEncryptedResponseAlgorithm)),
		"jwksUri":                               llx.StringData(oktaStr(entry.JwksUri)),
		"jwks":                                  llx.DictData(jwks),
		"audiences":                             llx.ArrayData(convert.SliceAnyToInterface(entry.Audiences), types.String),
		"signingKid":                            llx.StringData(signingKid),
		"signingRotationMode":                   llx.StringData(signingRotationMode),
		"signingLastRotated":                    llx.TimeDataPtr(signingLastRotated),
		"signingNextRotation":                   llx.TimeDataPtr(signingNextRotation),
		"signingUse":                            llx.StringData(signingUse),
		"created":                               llx.TimeDataPtr(entry.Created),
		"lastUpdated":                           llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaAuthorizationServer) id() (string, error) {
	return "okta.authorizationServer/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaAuthorizationServer) policies() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	policies, resp, err := client.AuthorizationServerPoliciesAPI.ListAuthorizationServerPolicies(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(entries []okta.AuthorizationServerPolicy) error {
		for i := range entries {
			raw, err := json.Marshal(entries[i])
			if err != nil {
				return err
			}
			var entry authzServerPolicyRaw
			if err := json.Unmarshal(raw, &entry); err != nil {
				return err
			}
			r, err := newMqlOktaAuthorizationServerPolicy(o.MqlRuntime, o.Id.Data, &entry)
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(policies); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.AuthorizationServerPolicy
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func (o *mqlOktaAuthorizationServer) scopes() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	scopes, resp, err := client.AuthorizationServerScopesAPI.ListOAuth2Scopes(ctx, o.Id.Data).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(entries []okta.OAuth2Scope) error {
		for i := range entries {
			r, err := newMqlOktaAuthorizationServerScope(o.MqlRuntime, o.Id.Data, &entries[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(scopes); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.OAuth2Scope
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func (o *mqlOktaAuthorizationServer) claims() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	claims, resp, err := client.AuthorizationServerClaimsAPI.ListOAuth2Claims(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(entries []okta.OAuth2Claim) error {
		for i := range entries {
			r, err := newMqlOktaAuthorizationServerClaim(o.MqlRuntime, o.Id.Data, &entries[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(claims); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.OAuth2Claim
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func (o *mqlOktaAuthorizationServer) keys() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()

	// The typed AuthorizationServerJsonWebKey drops created/lastUpdated/
	// expiresAt/keyOps/x5c/x5t/x5tS256, so fetch the keys directly to retain the
	// full JWK shape.
	apiSupplement := conn.ApiExtension()
	keys, err := apiSupplement.ListAuthorizationServerKeys(ctx, o.Id.Data)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range keys {
		k := keys[i]
		if k == nil {
			continue
		}
		r, err := CreateResource(o.MqlRuntime, "okta.authorizationServer.key", map[string]*llx.RawData{
			"authorizationServerId": llx.StringData(o.Id.Data),
			"kid":                   llx.StringData(k.Kid),
			"status":                llx.StringData(k.Status),
			"alg":                   llx.StringData(k.Alg),
			"kty":                   llx.StringData(k.Kty),
			"use":                   llx.StringData(k.Use),
			"keyOps":                llx.ArrayData(convert.SliceAnyToInterface(k.KeyOps), types.String),
			"created":               llx.TimeDataPtr(k.Created),
			"lastUpdated":           llx.TimeDataPtr(k.LastUpdated),
			"expiresAt":             llx.TimeDataPtr(k.ExpiresAt),
			"x5c":                   llx.ArrayData(convert.SliceAnyToInterface(k.X5c), types.String),
			"x5t":                   llx.StringData(k.X5t),
			"x5tS256":               llx.StringData(k.X5tS256),
			"n":                     llx.StringData(k.N),
			"e":                     llx.StringData(k.E),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (o *mqlOktaAuthorizationServerKey) id() (string, error) {
	return "okta.authorizationServer.key/" + o.AuthorizationServerId.Data + "/" + o.Kid.Data, o.Kid.Error
}

func newMqlOktaAuthorizationServerPolicy(runtime *plugin.Runtime, authServerId string, entry *authzServerPolicyRaw) (any, error) {
	conditions, err := convert.JsonToDict(entry.Conditions)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.authorizationServer.policy", map[string]*llx.RawData{
		"authorizationServerId": llx.StringData(authServerId),
		"id":                    llx.StringData(entry.Id),
		"name":                  llx.StringData(entry.Name),
		"description":           llx.StringData(entry.Description),
		"priority":              llx.IntData(entry.Priority),
		"status":                llx.StringData(entry.Status),
		"system":                llx.BoolData(oktaBool(entry.System)),
		"type":                  llx.StringData(entry.Type),
		"conditions":            llx.DictData(conditions),
		"created":               llx.TimeDataPtr(entry.Created),
		"lastUpdated":           llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaAuthorizationServerPolicy) id() (string, error) {
	return "okta.authorizationServer.policy/" + o.AuthorizationServerId.Data + "/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaAuthorizationServerPolicy) rules() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.AuthorizationServerId.Data == "" || o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	rules, resp, err := client.AuthorizationServerRulesAPI.ListAuthorizationServerPolicyRules(
		ctx, o.AuthorizationServerId.Data, o.Id.Data,
	).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(entries []okta.AuthorizationServerPolicyRule) error {
		for i := range entries {
			raw, err := json.Marshal(entries[i])
			if err != nil {
				return err
			}
			var entry oktaPolicyRuleRaw
			if err := json.Unmarshal(raw, &entry); err != nil {
				return err
			}
			actions, err := convert.JsonToDict(entry.Actions)
			if err != nil {
				return err
			}
			conditions, err := convert.JsonToDict(entry.Conditions)
			if err != nil {
				return err
			}

			r, err := CreateResource(o.MqlRuntime, "okta.authorizationServer.policyRule", map[string]*llx.RawData{
				"authorizationServerId": llx.StringData(o.AuthorizationServerId.Data),
				"policyId":              llx.StringData(o.Id.Data),
				"id":                    llx.StringData(entry.Id),
				"name":                  llx.StringData(entry.Name),
				"priority":              llx.IntData(entry.Priority),
				"status":                llx.StringData(entry.Status),
				"system":                llx.BoolData(oktaBool(entry.System)),
				"type":                  llx.StringData(entry.Type),
				"actions":               llx.DictData(actions),
				"conditions":            llx.DictData(conditions),
				"created":               llx.TimeDataPtr(entry.Created),
				"lastUpdated":           llx.TimeDataPtr(entry.LastUpdated),
			})
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(rules); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.AuthorizationServerPolicyRule
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func (o *mqlOktaAuthorizationServerPolicyRule) id() (string, error) {
	return "okta.authorizationServer.policyRule/" + o.AuthorizationServerId.Data + "/" + o.PolicyId.Data + "/" + o.Id.Data, o.Id.Error
}

func newMqlOktaAuthorizationServerScope(runtime *plugin.Runtime, authServerId string, entry *okta.OAuth2Scope) (any, error) {
	return CreateResource(runtime, "okta.authorizationServer.scope", map[string]*llx.RawData{
		"authorizationServerId": llx.StringData(authServerId),
		"id":                    llx.StringData(oktaStr(entry.Id)),
		"name":                  llx.StringData(entry.Name),
		"displayName":           llx.StringData(oktaStr(entry.DisplayName)),
		"description":           llx.StringData(oktaStr(entry.Description)),
		"consent":               llx.StringData(oktaStr(entry.Consent)),
		"default":               llx.BoolData(oktaBool(entry.Default)),
		"metadataPublish":       llx.StringData(oktaStr(entry.MetadataPublish)),
		"system":                llx.BoolData(oktaBool(entry.System)),
	})
}

func (o *mqlOktaAuthorizationServerScope) id() (string, error) {
	return "okta.authorizationServer.scope/" + o.AuthorizationServerId.Data + "/" + o.Id.Data, o.Id.Error
}

func newMqlOktaAuthorizationServerClaim(runtime *plugin.Runtime, authServerId string, entry *okta.OAuth2Claim) (any, error) {
	var scopes []string
	if entry.Conditions != nil {
		scopes = entry.Conditions.Scopes
	}

	return CreateResource(runtime, "okta.authorizationServer.claim", map[string]*llx.RawData{
		"authorizationServerId": llx.StringData(authServerId),
		"id":                    llx.StringData(oktaStr(entry.Id)),
		"name":                  llx.StringData(oktaStr(entry.Name)),
		"status":                llx.StringData(oktaStr(entry.Status)),
		"system":                llx.BoolData(oktaBool(entry.System)),
		"claimType":             llx.StringData(oktaStr(entry.ClaimType)),
		"valueType":             llx.StringData(oktaStr(entry.ValueType)),
		"value":                 llx.StringData(oktaStr(entry.Value)),
		"alwaysIncludeInToken":  llx.BoolData(oktaBool(entry.AlwaysIncludeInToken)),
		"groupFilterType":       llx.StringData(oktaStr(entry.GroupFilterType)),
		"scopes":                llx.ArrayData(convert.SliceAnyToInterface(scopes), types.String),
	})
}

func (o *mqlOktaAuthorizationServerClaim) id() (string, error) {
	return "okta.authorizationServer.claim/" + o.AuthorizationServerId.Data + "/" + o.Id.Data, o.Id.Error
}

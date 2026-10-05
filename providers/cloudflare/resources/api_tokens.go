// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"encoding/json"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/accounts"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/user"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareApiToken) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// tokenPolicyDicts converts a token's grants into dicts. Each entry carries the
// policy id, its effect, the resources it applies to, and the permission groups
// it grants. The token secret is not part of any list response and is never
// exposed here.
func tokenPolicyDicts(policies []shared.TokenPolicy) []any {
	out := make([]any, 0, len(policies))
	for j := range policies {
		p := policies[j]
		pgs := make([]any, 0, len(p.PermissionGroups))
		for k := range p.PermissionGroups {
			pg := p.PermissionGroups[k]
			pgs = append(pgs, map[string]any{
				"id":   pg.ID,
				"name": pg.Name,
			})
		}
		// The resources field is a polymorphic union in cloudflare-go;
		// round-trip it through JSON so the dict holds a plain decoded value
		// matching the raw API shape.
		var resources any
		if b, err := json.Marshal(p.Resources); err == nil {
			_ = json.Unmarshal(b, &resources)
		}
		out = append(out, map[string]any{
			"id":               p.ID,
			"effect":           string(p.Effect),
			"resources":        resources,
			"permissionGroups": pgs,
		})
	}
	return out
}

// newAPITokenResource builds a cloudflare.apiToken from a token record. Both the
// user-scoped and the account-owned endpoints return the same shared.Token, so
// one builder serves both.
//
// cacheKey scopes the resource: a user token and an account token are distinct
// objects even though both are addressed by a token id. accountID is empty for a
// user-owned token, which then reports a null accountId rather than claiming
// ownership by an account.
func newAPITokenResource(runtime *plugin.Runtime, cacheKey, accountID string, t shared.Token) (plugin.Resource, error) {
	accountData := llx.NilData
	if accountID != "" {
		accountData = llx.StringData(accountID)
	}

	return CreateResource(runtime, "cloudflare.apiToken", map[string]*llx.RawData{
		"__id":       llx.StringData("cloudflare.apiToken@" + cacheKey),
		"id":         llx.StringData(t.ID),
		"name":       llx.StringData(t.Name),
		"status":     llx.StringData(string(t.Status)),
		"issuedOn":   timeOrNil(t.IssuedOn),
		"modifiedOn": timeOrNil(t.ModifiedOn),
		"notBefore":  timeOrNil(t.NotBefore),
		"expiresOn":  timeOrNil(t.ExpiresOn),
		"lastUsedOn": timeOrNil(t.LastUsedOn),
		"accountId":  accountData,
		"ipIn":       llx.ArrayData(convert.SliceAnyToInterface(t.Condition.RequestIP.In), types.String),
		"ipNotIn":    llx.ArrayData(convert.SliceAnyToInterface(t.Condition.RequestIP.NotIn), types.String),
		"policies":   llx.ArrayData(tokenPolicyDicts(t.Policies), types.Dict),
		// Only account-owned tokens carry these; a user token omits them, and
		// they must read as null there rather than as an empty string.
		"creatorEmail":    tokenStringOrNil(t.CreatorEmailAtCreation, t.JSON.CreatorEmailAtCreation.IsNull()),
		"provisionerType": tokenStringOrNil(t.ProvisionerType, t.JSON.ProvisionerType.IsNull()),
		"provisionerId":   tokenStringOrNil(t.ProvisionerID, t.JSON.ProvisionerID.IsNull()),
	})
}

// tokenStringOrNil returns null for a token attribute the API omitted, sent as
// null, or sent empty, and the string otherwise.
func tokenStringOrNil(v string, absent bool) *llx.RawData {
	if absent || v == "" {
		return llx.NilData
	}
	return llx.StringData(v)
}

// apiTokens lists API tokens visible to the calling user. These are *user*
// scoped (`/user/tokens`), not account scoped, so they are surfaced on the root
// cloudflare resource — the same set is returned regardless of which accounts
// the user belongs to. Tokens owned by an account are listed by
// cloudflare.account.apiTokens.
func (c *mqlCloudflare) apiTokens() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.User.Tokens.ListAutoPaging(context.TODO(), user.TokenListParams{})
	for iter.Next() {
		t := iter.Current()

		res, err := newAPITokenResource(c.MqlRuntime, "user/"+t.ID, "", t)
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		// Token listing requires a token with the right permissions; treat
		// permission/availability errors as an empty result rather than failing.
		// A failure the API blames on the credentials themselves (code 9109,
		// an account-scoped token used against a user endpoint) is not degraded
		// — see credentialScopeCodes.
		if isUnavailable(err) {
			return nil, nil
		}
		return nil, err
	}

	return result, nil
}

// apiTokens lists the tokens owned by the account rather than by a user. These
// are the long-lived automation credentials: they survive any one person leaving,
// so their expiry, IP allowlist, last use and scope are what an access review
// needs. Account-owned tokens are an Enterprise capability, so an account without
// it degrades to an empty list like the other gated collections.
func (c *mqlCloudflareAccount) apiTokens() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	result := []any{}
	iter := conn.Cf.Accounts.Tokens.ListAutoPaging(context.TODO(), accounts.TokenListParams{
		AccountID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		t := iter.Current()

		res, err := newAPITokenResource(c.MqlRuntime, "account/"+c.Id.Data+"/"+t.ID, c.Id.Data, t)
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

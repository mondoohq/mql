// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/types"
)

type envVarRecord struct {
	Key       string            `json:"key"`
	Scopes    []string          `json:"scopes"`
	IsSecret  bool              `json:"is_secret"`
	UpdatedAt netlifyTime       `json:"updated_at"`
	UpdatedBy *envVarUserData   `json:"updated_by"`
	Values    []envVarValueData `json:"values"`
}

type envVarUserData struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// mqlNetlifyEnvVarInternal caches what updatedBy needs to resolve the member
// out of the owning account's roster.
type mqlNetlifyEnvVarInternal struct {
	cacheAccountID      string
	cacheUpdatedByEmail string
}

type envVarValueData struct {
	Context          string `json:"context"`
	ContextParameter string `json:"context_parameter"`
	Value            string `json:"value"`
}

func (a *mqlNetlifyAccount) environmentVariables() ([]any, error) {
	res, err := fetchEnvVars(a.MqlRuntime, a.Id.Data, "", nil)
	if err != nil {
		// A member without administrative rights cannot read the account's
		// variables. Reporting them as null keeps that apart from an account
		// that has none, which an empty list would read as.
		if connection.IsForbidden(err) {
			a.EnvironmentVariables = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// fetchEnvVars reads the environment variables of an account, optionally
// narrowed to one site, and builds a resource per variable. The owner
// identifiers form the cache key so an account-wide variable and the same
// variable read through a site stay distinct.
func fetchEnvVars(runtime *plugin.Runtime, accountID, siteID string, query url.Values) ([]any, error) {
	c := netlifyConn(runtime)

	records, err := connection.GetPaged[envVarRecord](context.Background(), c,
		"/accounts/"+url.PathEscape(accountID)+"/env", query)
	if err != nil {
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]

		values := make([]any, 0, len(rec.Values))
		for _, v := range rec.Values {
			values = append(values, map[string]any{
				"context":          v.Context,
				"contextParameter": v.ContextParameter,
				"value":            v.Value,
			})
		}

		updatedByEmail := ""
		if rec.UpdatedBy != nil {
			updatedByEmail = rec.UpdatedBy.Email
		}

		id := accountID + "/" + siteID + "/" + rec.Key
		envVar, err := CreateResource(runtime, "netlify.envVar", map[string]*llx.RawData{
			"__id":      llx.StringData(id),
			"key":       llx.StringData(rec.Key),
			"scopes":    llx.ArrayData(strSliceToAny(rec.Scopes), types.String),
			"isSecret":  llx.BoolData(rec.IsSecret),
			"values":    llx.ArrayData(values, types.Dict),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlEnvVar := envVar.(*mqlNetlifyEnvVar)
		mqlEnvVar.cacheAccountID = accountID
		mqlEnvVar.cacheUpdatedByEmail = updatedByEmail
		res = append(res, mqlEnvVar)
	}
	return res, nil
}

// updatedBy resolves the member that last changed the variable.
//
// The match runs on the email address rather than an identifier: the roster
// keys a member by its membership id while other parts of the API refer to the
// user behind it, and an email is the one value that means the same thing in
// both. Resolution goes through the account's already-fetched roster, so a
// query over many variables does not refetch it per variable.
func (e *mqlNetlifyEnvVar) updatedBy() (*mqlNetlifyAccountMember, error) {
	if e.cacheUpdatedByEmail == "" || e.cacheAccountID == "" {
		e.UpdatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(e.MqlRuntime)
	if err != nil {
		return nil, err
	}

	accounts := root.GetAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}

	for _, it := range accounts.Data {
		account, ok := it.(*mqlNetlifyAccount)
		if !ok || account.Id.Data != e.cacheAccountID {
			continue
		}

		members := account.GetMembers()
		if members.Error != nil {
			return nil, members.Error
		}
		// A token that cannot read the roster cannot attribute the change.
		if members.State&plugin.StateIsNull != 0 {
			break
		}

		for _, mit := range members.Data {
			member, ok := mit.(*mqlNetlifyAccountMember)
			if ok && member.Email.Data == e.cacheUpdatedByEmail {
				return member, nil
			}
		}
	}

	// The member has left the account since the variable was last written.
	e.UpdatedBy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

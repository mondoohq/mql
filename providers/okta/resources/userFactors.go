// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// mqlOktaUserFactorInternal caches the owning user's id so the typed user()
// accessor can resolve without exposing a deprecated public field.
type mqlOktaUserFactorInternal struct {
	cacheUserId string
}

// userFactorRaw decodes the user factors endpoint directly so we can capture
// the type-specific Profile object that the SDK's UserFactor struct discards.
type userFactorRaw struct {
	Id          string         `json:"id,omitempty"`
	FactorType  string         `json:"factorType,omitempty"`
	Provider    string         `json:"provider,omitempty"`
	Status      string         `json:"status,omitempty"`
	Created     *time.Time     `json:"created,omitempty"`
	LastUpdated *time.Time     `json:"lastUpdated,omitempty"`
	Profile     map[string]any `json:"profile,omitempty"`
}

// factors returns the MFA factors enrolled by this user.
func (o *mqlOktaUser) factors() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	raw, err := apiSupplement.ListUserFactors(ctx, o.Id.Data)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range raw {
		var entry userFactorRaw
		if err := json.Unmarshal(raw[i], &entry); err != nil {
			return nil, err
		}
		r, err := newMqlOktaUserFactor(o.MqlRuntime, o.Id.Data, &entry)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func newMqlOktaUserFactor(runtime *plugin.Runtime, userId string, factor *userFactorRaw) (*mqlOktaUserFactor, error) {
	args := map[string]*llx.RawData{
		"id":          llx.StringData(factor.Id),
		"factorType":  llx.StringData(factor.FactorType),
		"provider":    llx.StringData(factor.Provider),
		"status":      llx.StringData(factor.Status),
		"created":     llx.TimeDataPtr(factor.Created),
		"lastUpdated": llx.TimeDataPtr(factor.LastUpdated),
	}
	if factor.Profile != nil {
		args["profile"] = llx.DictData(factor.Profile)
	} else {
		args["profile"] = llx.NilData
	}

	r, err := CreateResource(runtime, "okta.userFactor", args)
	if err != nil {
		return nil, err
	}
	mqlFactor := r.(*mqlOktaUserFactor)
	mqlFactor.cacheUserId = userId
	return mqlFactor, nil
}

func (o *mqlOktaUserFactor) id() (string, error) {
	return "okta.userFactor/" + o.cacheUserId + "/" + o.Id.Data, o.Id.Error
}

// user resolves the typed user this factor belongs to. The runtime caches
// okta.user instances keyed by id, so repeated lookups across factors reuse a
// single GetUser call.
func (o *mqlOktaUserFactor) user() (*mqlOktaUser, error) {
	if o.cacheUserId == "" {
		o.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := NewResource(o.MqlRuntime, "okta.user", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheUserId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaUser), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/auth0/go-auth0/management"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/auth0/connection"
)

// mqlAuth0ConnectionInternal caches the raw enabled-client IDs so the
// enabledClients accessor can resolve them into typed auth0.client references
// without an extra API call.
type mqlAuth0ConnectionInternal struct {
	cacheEnabledClientIds []string
}

// connections lists every identity connection available in the tenant.
func (a *mqlAuth0) connections() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Connection.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, c := range list.Connections {
			r, err := newMqlAuth0Connection(a.MqlRuntime, c)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// newMqlAuth0Connection maps a single SDK connection to its MQL resource,
// promoting the database-strategy password and MFA options to typed fields.
func newMqlAuth0Connection(runtime *plugin.Runtime, c *management.Connection) (plugin.Resource, error) {
	var optionsDict any
	if c.Options != nil {
		d, err := convert.JsonToDict(c.Options)
		if err != nil {
			return nil, err
		}
		optionsDict = d
	}

	// Typed database-connection options are only present for the auth0
	// (database) strategy; other strategies carry a different options shape,
	// leaving these fields null.
	var passwordPolicy *string
	var disableSignup, requiresUsername, bruteForceProtection *bool
	var passwordDictionaryEnabled, passwordHistoryEnabled, passwordNoPersonalInfo *bool
	var mfaActive, mfaReturnEnrollSettings *bool
	var passwordHistorySize *int64
	if opts, ok := c.Options.(*management.ConnectionOptions); ok && opts != nil {
		passwordPolicy = opts.PasswordPolicy
		disableSignup = opts.DisableSignup
		requiresUsername = opts.RequiresUsername
		bruteForceProtection = opts.BruteForceProtection
		passwordDictionaryEnabled = mapBool(opts.PasswordDictionary, "enable")
		passwordHistoryEnabled = mapBool(opts.PasswordHistory, "enable")
		passwordHistorySize = mapInt(opts.PasswordHistory, "size")
		passwordNoPersonalInfo = mapBool(opts.PasswordNoPersonalInfo, "enable")
		mfaActive = mapBool(opts.MFA, "active")
		mfaReturnEnrollSettings = mapBool(opts.MFA, "return_enroll_settings")
	}

	r, err := CreateResource(runtime, "auth0.connection", map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(c.ID),
		"name":                      llx.StringDataPtr(c.Name),
		"strategy":                  llx.StringDataPtr(c.Strategy),
		"isDomainConnection":        llx.BoolDataPtr(c.IsDomainConnection),
		"disableSignup":             llx.BoolDataPtr(disableSignup),
		"requiresUsername":          llx.BoolDataPtr(requiresUsername),
		"passwordPolicy":            llx.StringDataPtr(passwordPolicy),
		"passwordDictionaryEnabled": llx.BoolDataPtr(passwordDictionaryEnabled),
		"passwordHistoryEnabled":    llx.BoolDataPtr(passwordHistoryEnabled),
		"passwordHistorySize":       llx.IntDataPtr(passwordHistorySize),
		"passwordNoPersonalInfo":    llx.BoolDataPtr(passwordNoPersonalInfo),
		"mfaActive":                 llx.BoolDataPtr(mfaActive),
		"mfaReturnEnrollSettings":   llx.BoolDataPtr(mfaReturnEnrollSettings),
		"bruteForceProtection":      llx.BoolDataPtr(bruteForceProtection),
		"options":                   llx.DictData(optionsDict),
	})
	if err != nil {
		return nil, err
	}

	mqlConn := r.(*mqlAuth0Connection)
	if c.EnabledClients != nil {
		mqlConn.cacheEnabledClientIds = *c.EnabledClients
	}
	return r, nil
}

// initAuth0Connection resolves an identity connection by its ID on demand.
func initAuth0Connection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return nil, nil, fmt.Errorf("auth0.connection requires an id argument")
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("auth0.connection requires a valid id")
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	c, err := conn.Client().Connection.Read(context.Background(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0.connection with id %q not found: %w", id, err)
	}

	res, err := newMqlAuth0Connection(runtime, c)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// enabledClients resolves the applications enabled on this connection into
// typed auth0.client references.
func (c *mqlAuth0Connection) enabledClients() ([]any, error) {
	if len(c.cacheEnabledClientIds) == 0 {
		return []any{}, nil
	}

	var result []any
	for _, clientID := range c.cacheEnabledClientIds {
		r, err := NewResource(c.MqlRuntime, "auth0.client",
			map[string]*llx.RawData{"id": llx.StringData(clientID)})
		if err != nil {
			// A stale or deleted client ID should not fail the whole connection.
			log.Debug().Err(err).Str("client", clientID).Msg("auth0> unable to resolve enabled client")
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

func (r *mqlAuth0Connection) id() (string, error) {
	return "auth0.connection/" + r.Id.Data, nil
}

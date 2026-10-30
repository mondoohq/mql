// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
)

// connectedAppsTokenFanoutLimit bounds the parallel Tokens.List fan-out
// across users. The Admin SDK Directory quota is ~2400 units per 100s, so
// 10 concurrent requests at ~150-300ms each stays well within budget while
// collapsing wall-clock from N×latency to N/10×latency.
const connectedAppsTokenFanoutLimit = 10

type connectedApp struct {
	clientID string
	scopes   []string
	name     string
	users    []*mqlGoogleworkspaceUser
	tokens   []*mqlGoogleworkspaceToken
}

func (g *mqlGoogleworkspace) connectedApps() ([]any, error) {
	// get all users. Resolve via GetUsers() so connectedApps works even when
	// the caller never touched googleworkspace.users directly.
	usersField := g.GetUsers()
	if usersField.Error != nil {
		return nil, usersField.Error
	}
	users := usersField.Data

	// Phase 1: fan out Tokens.List for every user in parallel. Each user's
	// tokens are independent API calls, so the previous serial loop was
	// O(N × latency) wall-clock. The errgroup populates the per-user MQL
	// cache (c.Tokens) so subsequent queries that touch user.tokens hit it
	// for free.
	grp, _ := errgroup.WithContext(context.Background())
	grp.SetLimit(connectedAppsTokenFanoutLimit)
	for _, user := range users {
		usr := user.(*mqlGoogleworkspaceUser)
		grp.Go(func() error {
			return usr.GetTokens().Error
		})
	}
	if err := grp.Wait(); err != nil {
		return nil, err
	}

	// Phase 2: aggregate the (now-cached) tokens serially. This is pure
	// CPU work, no API calls — safe to keep serial.
	connectedApps := map[string]*connectedApp{}
	for _, user := range users {
		usr := user.(*mqlGoogleworkspaceUser)
		tokens := usr.GetTokens()
		if tokens.Error != nil {
			return nil, tokens.Error
		}

		for _, token := range tokens.Data {
			tk := token.(*mqlGoogleworkspaceToken)

			if tk.ClientId.Error != nil {
				return nil, tk.ClientId.Error
			}
			clientID := tk.ClientId.Data
			// Skip tokens without a clientId: they would all collapse into one
			// phantom connected-app under the empty-string key.
			if clientID == "" {
				continue
			}

			cApp, ok := connectedApps[clientID]
			if !ok {
				cApp = &connectedApp{
					clientID: clientID,
					users:    []*mqlGoogleworkspaceUser{},
					tokens:   []*mqlGoogleworkspaceToken{},
				}
			}

			// assign name
			if tk.DisplayText.Error != nil {
				return nil, tk.DisplayText.Error
			}
			cApp.name = tk.DisplayText.Data

			// merge scopes (dedup once at the end to avoid O(n²) churn)
			if tk.Scopes.Error != nil {
				return nil, tk.Scopes.Error
			}
			for _, scope := range tk.Scopes.Data {
				if s, ok := scope.(string); ok {
					cApp.scopes = append(cApp.scopes, s)
				} else {
					log.Warn().Str("clientId", clientID).Msgf("googleworkspace> unexpected scope type %T in connected-app token; dropping", scope)
				}
			}

			cApp.tokens = append(cApp.tokens, tk)
			cApp.users = append(cApp.users, usr)

			connectedApps[clientID] = cApp
		}
	}

	// group token by client id
	runtime := g.MqlRuntime
	res := make([]any, 0, len(connectedApps))
	for _, connectedApp := range connectedApps {
		mqlUsers := make([]any, len(connectedApp.users))
		for i := range connectedApp.users {
			mqlUsers[i] = connectedApp.users[i]
		}

		mqlTokens := make([]any, len(connectedApp.tokens))
		for i := range connectedApp.tokens {
			mqlTokens[i] = connectedApp.tokens[i]
		}

		mqlApp, err := CreateResource(runtime, "googleworkspace.connectedApp", map[string]*llx.RawData{
			"clientId": llx.StringData(connectedApp.clientID),
			"name":     llx.StringData(connectedApp.name),
			"scopes":   llx.ArrayData(convert.SliceAnyToInterface[string](stringx.DedupStringArray(connectedApp.scopes)), types.Any),
			"users":    llx.ArrayData(mqlUsers, types.Any),
			"tokens":   llx.ArrayData(mqlTokens, types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlApp)
	}

	return res, nil
}

func (g *mqlGoogleworkspaceConnectedApp) id() (string, error) {
	return "googleworkspace.connectedApp/" + g.ClientId.Data, g.ClientId.Error
}

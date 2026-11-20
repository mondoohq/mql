// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"
	"time"

	beta "github.com/microsoftgraph/msgraph-beta-sdk-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// credentialSignInCache holds the latest sign-in of every application
// credential in the tenant's credential sign-in activity report, keyed by
// lower-cased key id. The report is read once per scan.
type credentialSignInCache struct {
	once  sync.Once
	byKey map[string]time.Time
	err   error
}

func (m *mqlMicrosoft) credentialLastSignIn(keyID string) (*time.Time, error) {
	c := &m.credentialSignIns
	c.once.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		client, err := conn.BetaGraphClient()
		if err != nil {
			c.err = err
			return
		}
		c.byKey, c.err = fetchCredentialSignIns(context.Background(), client)
	})
	if c.err != nil {
		return nil, c.err
	}
	t, ok := c.byKey[strings.ToLower(keyID)]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

// fetchCredentialSignIns reads every page of the beta
// reports/appCredentialSignInActivities listing.
func fetchCredentialSignIns(ctx context.Context, client *beta.GraphServiceClient) (map[string]time.Time, error) {
	resp, err := client.Reports().AppCredentialSignInActivities().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	rows, err := iterate[betamodels.AppCredentialSignInActivityable](ctx, resp, client.GetAdapter(),
		betamodels.CreateAppCredentialSignInActivityCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	return latestSignInByKey(rows), nil
}

// latestSignInByKey keeps the latest sign-in of each key id. The report can
// hold one row per credential and resource it signed in to.
func latestSignInByKey(rows []betamodels.AppCredentialSignInActivityable) map[string]time.Time {
	res := map[string]time.Time{}
	for _, row := range rows {
		if row == nil || row.GetKeyId() == nil || *row.GetKeyId() == "" || row.GetSignInActivity() == nil {
			continue
		}
		t := row.GetSignInActivity().GetLastSignInDateTime()
		if t == nil {
			continue
		}
		key := strings.ToLower(*row.GetKeyId())
		if prev, ok := res[key]; !ok || t.After(prev) {
			res[key] = *t
		}
	}
	return res
}

func credentialLastSignIn(runtime *plugin.Runtime, keyID string) (*time.Time, error) {
	res, err := runtime.CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoft).credentialLastSignIn(keyID)
}

func (a *mqlMicrosoftKeyCredential) lastSignInDateTime() (*time.Time, error) {
	return credentialLastSignIn(a.MqlRuntime, a.KeyId.Data)
}

func (a *mqlMicrosoftPasswordCredential) lastSignInDateTime() (*time.Time, error) {
	return credentialLastSignIn(a.MqlRuntime, a.KeyId.Data)
}

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
	"go.mondoo.com/mql/providers/ms365/connection"
)

// spSignInActivityCache holds the tenant's service principal sign-in activity
// report, fetched once and keyed by lower-cased application id. The report is
// one row per application, so reading it whole costs a handful of pages where
// a per-principal lookup would cost a request per service principal.
type spSignInActivityCache struct {
	once    sync.Once
	byAppID map[string]betamodels.ServicePrincipalSignInActivityable
	err     error
}

// servicePrincipalSignInActivity returns the report row for the service
// principal's application, or nil when the report holds none.
func (a *mqlMicrosoftServiceprincipal) servicePrincipalSignInActivity() (betamodels.ServicePrincipalSignInActivityable, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	c := &ms.spSignInActivity
	c.once.Do(func() {
		conn := ms.MqlRuntime.Connection.(*connection.Ms365Connection)
		client, err := conn.BetaGraphClient()
		if err != nil {
			c.err = err
			return
		}
		c.byAppID, c.err = fetchServicePrincipalSignInActivities(context.Background(), client)
	})
	if c.err != nil {
		return nil, c.err
	}
	return c.byAppID[strings.ToLower(a.AppId.Data)], nil
}

// fetchServicePrincipalSignInActivities reads every page of the beta
// reports/servicePrincipalSignInActivities listing and indexes it by
// application id.
func fetchServicePrincipalSignInActivities(ctx context.Context, client *beta.GraphServiceClient) (map[string]betamodels.ServicePrincipalSignInActivityable, error) {
	resp, err := client.Reports().ServicePrincipalSignInActivities().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	rows, err := iterate[betamodels.ServicePrincipalSignInActivityable](ctx, resp, client.GetAdapter(),
		betamodels.CreateServicePrincipalSignInActivityCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	return indexSignInActivitiesByAppID(rows), nil
}

// indexSignInActivitiesByAppID keys report rows by lower-cased application
// id, skipping rows without one.
func indexSignInActivitiesByAppID(rows []betamodels.ServicePrincipalSignInActivityable) map[string]betamodels.ServicePrincipalSignInActivityable {
	res := make(map[string]betamodels.ServicePrincipalSignInActivityable, len(rows))
	for _, row := range rows {
		if row == nil || row.GetAppId() == nil || *row.GetAppId() == "" {
			continue
		}
		res[strings.ToLower(*row.GetAppId())] = row
	}
	return res
}

// lastSignInOf reads the sign-in time of one activity category, nil when the
// row or the category is absent.
func lastSignInOf(row betamodels.ServicePrincipalSignInActivityable, category func(betamodels.ServicePrincipalSignInActivityable) betamodels.SignInActivityable) *time.Time {
	if row == nil {
		return nil
	}
	activity := category(row)
	if activity == nil {
		return nil
	}
	return activity.GetLastSignInDateTime()
}

func (a *mqlMicrosoftServiceprincipal) signInCategory(category func(betamodels.ServicePrincipalSignInActivityable) betamodels.SignInActivityable) (*time.Time, error) {
	row, err := a.servicePrincipalSignInActivity()
	if err != nil {
		return nil, err
	}
	return lastSignInOf(row, category), nil
}

func (a *mqlMicrosoftServiceprincipal) lastSignInDateTime() (*time.Time, error) {
	return a.signInCategory(betamodels.ServicePrincipalSignInActivityable.GetLastSignInActivity)
}

func (a *mqlMicrosoftServiceprincipal) lastAppOnlyClientSignInDateTime() (*time.Time, error) {
	return a.signInCategory(betamodels.ServicePrincipalSignInActivityable.GetApplicationAuthenticationClientSignInActivity)
}

func (a *mqlMicrosoftServiceprincipal) lastDelegatedClientSignInDateTime() (*time.Time, error) {
	return a.signInCategory(betamodels.ServicePrincipalSignInActivityable.GetDelegatedClientSignInActivity)
}

func (a *mqlMicrosoftServiceprincipal) lastAppOnlyResourceSignInDateTime() (*time.Time, error) {
	return a.signInCategory(betamodels.ServicePrincipalSignInActivityable.GetApplicationAuthenticationResourceSignInActivity)
}

func (a *mqlMicrosoftServiceprincipal) lastDelegatedResourceSignInDateTime() (*time.Time, error) {
	return a.signInCategory(betamodels.ServicePrincipalSignInActivityable.GetDelegatedResourceSignInActivity)
}

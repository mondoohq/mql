// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

func (r *mqlSnowflakeAccount) managedAccounts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	accounts, err := client.ManagedAccounts.Show(ctx, sdk.NewShowManagedAccountRequest())
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(accounts))
	for i := range accounts {
		mqlAccount, err := newMqlSnowflakeManagedAccount(r.MqlRuntime, accounts[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlAccount)
	}

	return list, nil
}

func newMqlSnowflakeManagedAccount(runtime *plugin.Runtime, account sdk.ManagedAccount) (*mqlSnowflakeManagedAccount, error) {
	r, err := CreateResource(runtime, "snowflake.managedAccount", map[string]*llx.RawData{
		"__id":              llx.StringData(account.ID().FullyQualifiedName()),
		"name":              llx.StringData(account.Name),
		"cloud":             llx.StringData(account.Cloud),
		"region":            llx.StringData(account.Region),
		"locator":           llx.StringData(account.Locator),
		"url":               llx.StringData(account.URL),
		"accountLocatorUrl": llx.StringData(account.AccountLocatorURL),
		"isReader":          llx.BoolData(account.IsReader),
		"comment":           llx.StringDataPtr(account.Comment),
		"createdAt":         parseSnowflakeTime(account.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeManagedAccount), nil
}

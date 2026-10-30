// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

func (r *mqlSnowflakeAccount) id() (string, error) {
	return "snowflake.account", nil
}

func (r *mqlSnowflakeAccount) currentAccount() error {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	current, err := client.ContextFunctions.CurrentSessionDetails(ctx)
	if err != nil {
		return err
	}

	r.AccountId = plugin.TValue[string]{Data: current.Account, Error: nil, State: plugin.StateIsSet}
	r.Region = plugin.TValue[string]{Data: current.Region, Error: nil, State: plugin.StateIsSet}

	url, urlErr := current.AccountURL()
	r.Url = plugin.TValue[string]{Data: url, Error: urlErr, State: plugin.StateIsSet}
	return nil
}

func (r *mqlSnowflakeAccount) accountId() (string, error) {
	return "", r.currentAccount()
}

func (r *mqlSnowflakeAccount) region() (string, error) {
	return "", r.currentAccount()
}

func (r *mqlSnowflakeAccount) url() (string, error) {
	return "", r.currentAccount()
}

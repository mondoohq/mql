// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// organizationAccounts lists the accounts of the organization the scanned
// account belongs to.
//
// SHOW ACCOUNTS is an ORGADMIN statement, and the role a scan runs as is
// usually ACCOUNTADMIN, which does not hold it. A refusal leaves the field
// null, because an empty list would report an organization of one account,
// which is a claim the scan has not established and which would satisfy any
// assertion written over the list. Every other failure keeps propagating: a
// connection that dropped is not an organization without siblings.
func (r *mqlSnowflakeAccount) organizationAccounts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	accounts, err := client.Accounts.Show(ctx, &sdk.ShowAccountRequest{})
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		log.Debug().Err(err).Msg("snowflake: SHOW ACCOUNTS needs ORGADMIN, organizationAccounts will be null")
		r.OrganizationAccounts.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	list := make([]any, 0, len(accounts))
	for i := range accounts {
		mqlAccount, err := newMqlSnowflakeOrganizationAccount(r.MqlRuntime, accounts[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlAccount)
	}
	return list, nil
}

// newMqlSnowflakeOrganizationAccount builds one account row.
//
// The cache key carries the organization as well as the account name. An
// account name is unique only inside its organization, and a session that has
// been moved between organizations can see both, so the bare name would collide
// and report the first of a pair twice.
//
// Every optional column reaches us as a pointer and is passed through as one,
// so a column the row does not carry stays null instead of becoming an empty
// string, a false, or a zero. An edition that reads as the empty string and one
// that was never reported are different answers.
func newMqlSnowflakeOrganizationAccount(runtime *plugin.Runtime, account sdk.Account) (*mqlSnowflakeOrganizationAccount, error) {
	var edition *string
	if account.Edition != nil {
		value := string(*account.Edition)
		edition = &value
	}

	r, err := CreateResource(runtime, "snowflake.organizationAccount", map[string]*llx.RawData{
		"__id":                  llx.StringData(account.OrganizationName + "." + account.AccountName),
		"organizationName":      llx.StringData(account.OrganizationName),
		"accountName":           llx.StringData(account.AccountName),
		"accountLocator":        llx.StringData(account.AccountLocator),
		"accountUrl":            llx.StringDataPtr(account.AccountURL),
		"region":                llx.StringData(account.SnowflakeRegion),
		"regionGroup":           llx.StringDataPtr(account.RegionGroup),
		"edition":               llx.StringDataPtr(edition),
		"comment":               llx.StringDataPtr(account.Comment),
		"createdAt":             llx.TimeDataPtr(account.CreatedOn),
		"isOrgAdmin":            llx.BoolDataPtr(account.IsOrgAdmin),
		"isOrganizationAccount": llx.BoolData(account.IsOrganizationAccount),
		"isEventsAccount":       llx.BoolDataPtr(account.IsEventsAccount),
		"managedAccounts":       llx.IntDataPtr(account.ManagedAccounts),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeOrganizationAccount), nil
}

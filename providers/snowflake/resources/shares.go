// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlSnowflakeAccount) shares() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	shares, err := client.Shares.Show(ctx, &sdk.ShowShareRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range shares {
		mqlShare, err := newMqlSnowflakeShare(r.MqlRuntime, shares[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlShare)
	}

	return list, nil
}

func newMqlSnowflakeShare(runtime *plugin.Runtime, share sdk.Share) (*mqlSnowflakeShare, error) {
	to := make([]any, 0, len(share.To))
	for _, acct := range share.To {
		to = append(to, acct.FullyQualifiedName())
	}

	databaseName := ""
	if share.DatabaseName.Name() != "" {
		databaseName = share.DatabaseName.FullyQualifiedName()
	}

	r, err := CreateResource(runtime, "snowflake.share", map[string]*llx.RawData{
		"__id":      llx.StringData(string(share.Kind) + "/" + shareFullyQualifiedName(share)),
		"name":      llx.StringData(shareFullyQualifiedName(share)),
		"kind":      llx.StringData(string(share.Kind)),
		"to":        llx.ArrayData(to, types.String),
		"comment":   llx.StringData(share.Comment),
		"createdAt": llx.TimeData(share.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlShare := r.(*mqlSnowflakeShare)
	mqlShare.cacheDatabaseName = databaseName
	mqlShare.cacheOwner = share.Owner
	return mqlShare, nil
}

// mqlSnowflakeShareInternal holds the backing database name and owning role
// name that database() and ownerRole() resolve.
type mqlSnowflakeShareInternal struct {
	cacheDatabaseName string
	cacheOwner        string
}

func (r *mqlSnowflakeShare) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.cacheDatabaseName, &r.Database)
}

func (r *mqlSnowflakeShare) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

// shareFullyQualifiedName is the owner-account-qualified share name, such as
// "ORG"."ACCOUNT"."SHARE", which tells an inbound share apart from an outbound
// share of the same name.
func shareFullyQualifiedName(share sdk.Share) string {
	return sdk.NewExternalObjectIdentifier(
		sdk.NewAccountIdentifierFromFullyQualifiedName(share.OwnerAccount),
		sdk.NewAccountObjectIdentifier(share.Name),
	).FullyQualifiedName()
}

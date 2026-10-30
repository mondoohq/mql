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

type mqlSnowflakeApplicationInternal struct {
	cacheOwner string
}

type mqlSnowflakeApplicationPackageInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeAccount) applications() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	applications, err := client.Applications.Show(ctx, sdk.NewShowApplicationRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range applications {
		app := applications[i]
		res, err := CreateResource(r.MqlRuntime, "snowflake.application", map[string]*llx.RawData{
			"__id":       llx.StringData(sdk.NewAccountObjectIdentifier(app.Name).FullyQualifiedName()),
			"name":       llx.StringData(app.Name),
			"sourceType": llx.StringData(app.SourceType),
			"source":     llx.StringData(app.Source),
			"version":    llx.StringData(app.Version),
			"label":      llx.StringData(app.Label),
			"patch":      llx.IntData(app.Patch),
			"comment":    llx.StringData(app.Comment),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlSnowflakeApplication).cacheOwner = app.Owner
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlSnowflakeApplication) owner() (*mqlSnowflakeRole, error) {
	if r.cacheOwner == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := snowflakeRoleByName(r.MqlRuntime, r.cacheOwner)
	if err != nil {
		return nil, err
	}
	if role == nil {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

func (r *mqlSnowflakeAccount) applicationPackages() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	packages, err := client.ApplicationPackages.Show(ctx, sdk.NewShowApplicationPackageRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range packages {
		pkg := packages[i]
		res, err := CreateResource(r.MqlRuntime, "snowflake.applicationPackage", map[string]*llx.RawData{
			"__id":             llx.StringData(sdk.NewAccountObjectIdentifier(pkg.Name).FullyQualifiedName()),
			"name":             llx.StringData(pkg.Name),
			"distribution":     llx.StringData(pkg.Distribution),
			"applicationClass": llx.StringData(pkg.ApplicationClass),
			"comment":          llx.StringData(pkg.Comment),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlSnowflakeApplicationPackage).cacheOwner = pkg.Owner
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlSnowflakeApplicationPackage) owner() (*mqlSnowflakeRole, error) {
	if r.cacheOwner == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := snowflakeRoleByName(r.MqlRuntime, r.cacheOwner)
	if err != nil {
		return nil, err
	}
	if role == nil {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

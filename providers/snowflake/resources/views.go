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

func (r *mqlSnowflakeAccount) views() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	views, err := client.Views.Show(ctx, &sdk.ShowViewRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range views {
		mqlResource, err := newMqlSnowflakeView(r.MqlRuntime, views[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlResource)
	}

	return list, nil
}

func newMqlSnowflakeView(runtime *plugin.Runtime, view sdk.View) (*mqlSnowflakeView, error) {
	r, err := CreateResource(runtime, "snowflake.view", map[string]*llx.RawData{
		"__id":           llx.StringData(view.ID().FullyQualifiedName()),
		"name":           llx.StringData(view.Name),
		"kind":           llx.StringData(view.Kind),
		"reserved":       llx.StringData(view.Reserved),
		"databaseName":   llx.StringData(view.DatabaseName),
		"schemaName":     llx.StringData(view.SchemaName),
		"owner":          llx.StringData(view.Owner),
		"comment":        llx.StringData(view.Comment),
		"text":           llx.StringData(view.Text),
		"isSecure":       llx.BoolData(view.IsSecure),
		"isMaterialized": llx.BoolData(view.IsMaterialized),
		"ownerRoleType":  llx.StringData(view.OwnerRoleType),
		"changeTracking": llx.StringData(view.ChangeTracking),
		// TODO we need to check the format of the date
		// "createdAt":      llx.TimeData(view.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeView)
	return mqlResource, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mondoo/connection"
)

func initMondooOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.Connection)
	if conn.Type != connection.ConnTypeOrganization {
		return nil, nil, errors.New("cannot initialize mondoo.organization, invalid connection")
	}
	args["mrn"] = llx.StringData(conn.Upstream.SpaceMrn)
	args["name"] = llx.StringData(connection.MrnBasenameOrMrn(conn.Upstream.SpaceMrn))

	return args, nil, nil
}

func (m *mqlMondooOrganization) id() (string, error) {
	return m.Mrn.Data, nil
}

func (m *mqlMondooOrganization) spaces() ([]any, error) {
	conn := m.MqlRuntime.Connection.(*connection.Connection)

	var q struct {
		Organization struct {
			Id         string `graphql:"id"`
			Mrn        string `graphql:"mrn"`
			Name       string
			SpacesList struct {
				TotalCount int `graphql:"totalCount"`
				Edges      []struct {
					Node struct {
						ID   string
						Mrn  string
						Name string
					}
				}
			}
		} `graphql:"organization(mrn: $mrn)"`
	}
	vars := map[string]any{
		"mrn": mondoogql.String(conn.Upstream.SpaceMrn),
	}

	err := conn.Client.Query(context.Background(), &q, vars)
	if err != nil {
		return nil, err
	}

	res := make([]any, len(q.Organization.SpacesList.Edges))
	for i := range q.Organization.SpacesList.Edges {
		e := q.Organization.SpacesList.Edges[i]
		raw, err := CreateResource(m.MqlRuntime, "mondoo.space", map[string]*llx.RawData{
			"name": llx.StringData(e.Node.Name),
			"mrn":  llx.StringData(e.Node.Mrn),
		})
		if err != nil {
			return nil, err
		}
		res[i] = raw
	}

	return res, nil
}

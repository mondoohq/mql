// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/circleci/connection"
)

// mqlCircleciContextInternal caches the owning organization's id, which the
// API response for a context does not include but the organization()
// typed reference needs.
type mqlCircleciContextInternal struct {
	cacheOrgId string
}

// newMqlCircleciContext maps a single API context to its MQL resource.
func newMqlCircleciContext(runtime *plugin.Runtime, c connection.Context, orgId string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "circleci.context", map[string]*llx.RawData{
		"__id":      llx.StringData(c.ID),
		"id":        llx.StringData(c.ID),
		"name":      llx.StringData(c.Name),
		"createdAt": llx.TimeDataPtr(parseCircleciTime(c.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}

	mqlContext := res.(*mqlCircleciContext)
	mqlContext.cacheOrgId = orgId
	return mqlContext, nil
}

// organization resolves the organization that owns this context.
func (c *mqlCircleciContext) organization() (*mqlCircleciOrganization, error) {
	if c.cacheOrgId == "" {
		c.Organization.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "circleci.organization", map[string]*llx.RawData{
		"id": llx.StringData(c.cacheOrgId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCircleciOrganization), nil
}

// environmentVariables lists the environment variable names configured in
// this context. CircleCI's API never returns context environment variable
// values, in any form.
func (c *mqlCircleciContext) environmentVariables() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	var all []any
	pageToken := ""
	for {
		resp, err := client.ListContextEnvVars(context.Background(), c.Id.Data, pageToken)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Items {
			res, err := CreateResource(c.MqlRuntime, "circleci.context.environmentVariable", map[string]*llx.RawData{
				"__id":      llx.StringData(c.Id.Data + "/" + v.Variable),
				"variable":  llx.StringData(v.Variable),
				"createdAt": llx.TimeDataPtr(parseCircleciTime(v.CreatedAt)),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciContextEnvironmentVariable).cacheContext = c
			all = append(all, res)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return all, nil
}

// mqlCircleciContextEnvironmentVariableInternal caches the context this
// environment variable belongs to, so the context() typed reference resolves
// without an extra API call.
type mqlCircleciContextEnvironmentVariableInternal struct {
	cacheContext *mqlCircleciContext
}

// context resolves the context this environment variable is configured in.
func (v *mqlCircleciContextEnvironmentVariable) context() (*mqlCircleciContext, error) {
	if v.cacheContext == nil {
		v.Context.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return v.cacheContext, nil
}

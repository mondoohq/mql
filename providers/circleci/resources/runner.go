// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/circleci/connection"
)

// runnerResourceClasses lists the self-hosted runner resource classes
// registered under this organization's namespace. CircleCI's runner API
// scopes resource classes by namespace, which is the organization's name.
func (o *mqlCircleciOrganization) runnerResourceClasses() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	resp, err := client.ListRunnerResourceClasses(context.Background(), o.Name.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(resp.Items))
	for _, rc := range resp.Items {
		res, err := CreateResource(o.MqlRuntime, "circleci.runner.resourceClass", map[string]*llx.RawData{
			"__id":          llx.StringData(rc.ID),
			"id":            llx.StringData(rc.ID),
			"resourceClass": llx.StringData(rc.ResourceClass),
			"description":   llx.StringData(rc.Description),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlCircleciRunnerResourceClass).cacheOrgId = o.Id.Data
		all = append(all, res)
	}
	return all, nil
}

// mqlCircleciRunnerResourceClassInternal caches the owning organization's id,
// which the runner resource-class API response does not include but the
// organization() typed reference needs.
type mqlCircleciRunnerResourceClassInternal struct {
	cacheOrgId string
}

// organization resolves the organization whose namespace this resource class
// is registered under.
func (c *mqlCircleciRunnerResourceClass) organization() (*mqlCircleciOrganization, error) {
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

// tokens lists the resource-class tokens that self-hosted runner agents use
// to register with this resource class. The secret token value is never
// returned by the API.
func (c *mqlCircleciRunnerResourceClass) tokens() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	resp, err := client.ListRunnerTokens(context.Background(), c.ResourceClass.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(resp.Items))
	for _, t := range resp.Items {
		res, err := CreateResource(c.MqlRuntime, "circleci.runner.token", map[string]*llx.RawData{
			"__id":          llx.StringData(t.ID),
			"id":            llx.StringData(t.ID),
			"resourceClass": llx.StringData(t.ResourceClass),
			"nickname":      llx.StringData(t.Nickname),
			"createdAt":     llx.TimeDataPtr(parseCircleciTime(t.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

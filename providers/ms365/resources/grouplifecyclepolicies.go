// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

func (a *mqlMicrosoft) groupLifecyclePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	resp, err := graphClient.GroupLifecyclePolicies().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, p := range resp.GetValue() {
		policy, err := newMqlMicrosoftGroupLifecyclePolicy(a.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}

	return res, nil
}

func newMqlMicrosoftGroupLifecyclePolicy(runtime *plugin.Runtime, p models.GroupLifecyclePolicyable) (*mqlMicrosoftGroupLifecyclePolicy, error) {
	if p.GetId() == nil {
		return nil, errors.New("group lifecycle policy response is missing an ID")
	}

	data := map[string]*llx.RawData{
		"__id":                        llx.StringDataPtr(p.GetId()),
		"id":                          llx.StringDataPtr(p.GetId()),
		"groupLifetimeInDays":         llx.IntDataPtr(p.GetGroupLifetimeInDays()),
		"managedGroupTypes":           llx.StringDataPtr(p.GetManagedGroupTypes()),
		"alternateNotificationEmails": llx.StringDataPtr(p.GetAlternateNotificationEmails()),
	}

	resource, err := CreateResource(runtime, "microsoft.groupLifecyclePolicy", data)
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftGroupLifecyclePolicy), nil
}

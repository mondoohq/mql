// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/okta/okta-sdk-golang/v6/okta"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// subscriptionRoleRef returns the reference the subscription endpoint takes for
// this assignment: the standard role type for a standard role, and the custom
// role's id for a custom one. It is empty
// for a custom-role assignment whose role id could not be read, in which case
// there is nothing to ask about.
func (o *mqlOktaRole) subscriptionRoleRef() string {
	roleType := o.Type.Data
	if strings.HasPrefix(roleType, oktaCustomRoleTypePrefix) {
		return o.cacheCustomRoleID
	}
	return roleType
}

// subscriptions reports which administrator notifications the role receives,
// keyed by notification type.
//
// A role that answers nothing at all reports null rather than an empty map: an
// empty map reads as an administrator subscribed to no notification, which is
// the finding, and would make the check pass on an org that never answered.
func (o *mqlOktaRole) subscriptions() (map[string]any, error) {
	if o.Type.Error != nil {
		return nil, o.Type.Error
	}

	roleRef := o.subscriptionRoleRef()
	if roleRef == "" {
		o.Subscriptions.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	items, resp, err := conn.RoleSubscriptions(context.Background(), roleRef)
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			o.Subscriptions.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	return oktaSubscriptionMap(items), nil
}

// oktaSubscriptionMap keys the subscriptions by notification type. An entry
// with no notification type names nothing and is dropped rather than collected
// under an empty key, where it would overwrite the next one like it.
func oktaSubscriptionMap(items []okta.Subscription) map[string]any {
	result := map[string]any{}
	for i := range items {
		notificationType := oktaStr(items[i].NotificationType)
		if notificationType == "" {
			continue
		}
		result[notificationType] = oktaStr(items[i].Status)
	}
	return result
}

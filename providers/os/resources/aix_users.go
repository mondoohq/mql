// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// aixLocalUser returns the local user of the given name, or nil when
// /etc/passwd has none.
func aixLocalUser(runtime *plugin.Runtime, name string) (*mqlUser, error) {
	raw, err := CreateResource(runtime, "users", nil)
	if err != nil {
		return nil, err
	}
	users := raw.(*mqlUsers)
	if err := users.refreshCache(nil); err != nil {
		return nil, err
	}
	return users.usersByName[name], nil
}

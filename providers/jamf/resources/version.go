// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (r *mqlJamf) version() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	info, err := client.GetJamfProVersion()
	if err != nil {
		return "", err
	}
	if info == nil || info.Version == nil {
		return "", nil
	}
	return *info.Version, nil
}

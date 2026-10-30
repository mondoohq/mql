// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (r *mqlJamf) computerInventoryCount() (int64, error) {
	// If the full inventory was already fetched in this session, reuse it
	// instead of issuing another HTTP call.
	if r.ComputerInventory.IsSet() && r.ComputerInventory.Error == nil {
		return int64(len(r.ComputerInventory.Data)), nil
	}

	// Bypass the SDK's GetComputersInventory because it always paginates
	// through every record. We only want the total, which the Jamf Pro API
	// reports in the first page. Endpoint:
	// https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	var out struct {
		TotalCount int `json:"totalCount"`
	}
	resp, err := conn.Client.HTTP.DoRequest("GET", "/api/v1/computers-inventory?page=0&page-size=1", nil, &out)
	if err != nil {
		return 0, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	return int64(out.TotalCount), nil
}

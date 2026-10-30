// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import "encoding/json"

// Blueprint is a configuration bundle assigned to devices. The /blueprints
// endpoint does not enumerate a blueprint's library items, so that
// association is not modeled here.
type Blueprint struct {
	ID             string                  `json:"id"`
	Name           string                  `json:"name"`
	Description    string                  `json:"description"`
	Icon           string                  `json:"icon"`
	Color          string                  `json:"color"`
	Type           string                  `json:"type"`
	ComputersCount int                     `json:"computers_count"`
	EnrollmentCode BlueprintEnrollmentCode `json:"enrollment_code"`
	CreatedAt      string                  `json:"created_at"`
	UpdatedAt      string                  `json:"updated_at"`
}

// BlueprintEnrollmentCode is the enrollment-code object the API nests on a
// blueprint (the field is an object, not a bare string).
type BlueprintEnrollmentCode struct {
	Code     string `json:"code"`
	IsActive bool   `json:"is_active"`
}

// ListBlueprints walks /v1/blueprints (DRF envelope, offset paging).
func (c *Client) ListBlueprints() ([]Blueprint, error) {
	var all []Blueprint
	err := c.paginateEnvelope("/api/v1/blueprints", func(results json.RawMessage) error {
		var page []Blueprint
		if err := json.Unmarshal(results, &page); err != nil {
			return err
		}
		all = append(all, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

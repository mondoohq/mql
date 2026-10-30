// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import "encoding/json"

// User is an end-user record in the Iru directory as returned by GET
// /v1/users. The embedded `user` object on a device row is a smaller shape
// (id/name/email plus is_archived/active) that also unmarshals into this
// struct; the fields it does not carry stay at their zero value.
type User struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Email       string           `json:"email"`
	Active      bool             `json:"active"`
	Archived    bool             `json:"archived"`
	Department  string           `json:"department"`
	JobTitle    string           `json:"job_title"`
	DeviceCount int              `json:"device_count"`
	CreatedAt   string           `json:"created_at"`
	UpdatedAt   string           `json:"updated_at"`
	Integration *UserIntegration `json:"integration,omitempty"`

	// IsArchived mirrors the `is_archived` key used on the device-embedded
	// user object; the top-level /users listing uses `archived` instead.
	// Both are folded together by the Archived accessor.
	IsArchived bool `json:"is_archived"`
}

// UserIntegration identifies the directory integration a user was synced
// from (for example a Google Workspace or Entra ID connection).
type UserIntegration struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Type string `json:"type"`
}

// ListUsers walks /v1/users (DRF envelope, cursor paging).
func (c *Client) ListUsers() ([]User, error) {
	var all []User
	err := c.paginateEnvelope("/api/v1/users", func(results json.RawMessage) error {
		var page []User
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

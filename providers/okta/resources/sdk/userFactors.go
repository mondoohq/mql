// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"net/url"
)

// ListUserFactors returns the MFA factors enrolled by a user as raw JSON
// objects. We decode them in the caller rather than through the generated SDK's
// UserFactor type: that type is a discriminated union which drops the
// per-factorType `profile` object, and the profile is where the enrollment
// detail (phone number, credential id, authenticator name) lives.
//
// The endpoint returns every enrolled factor in a single response, so there is
// no `Link: rel="next"` loop here.
func (m *ApiExtension) ListUserFactors(ctx context.Context, userId string) ([]json.RawMessage, error) {
	var factors []json.RawMessage
	_, err := m.get(ctx, m.url("/api/v1/users/"+url.PathEscape(userId)+"/factors"), &factors)
	if err != nil {
		return nil, err
	}
	return factors, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"
)

// AttackProtectionSettings holds the org-level brute-force protection flags.
type AttackProtectionSettings struct {
	PreventBruteForceLockoutFromUnknownDevices bool
	VerifyKnowledgeSecondWhen2faRequired       bool
}

// GetAttackProtectionSettings fetches the org's attack-protection settings.
//
// The SDK's AttackProtectionAPI.GetUserLockoutSettings and
// GetAuthenticatorSettings type their responses as slices, but both endpoints
// return a single JSON object (for example
// `{"preventBruteForceLockoutFromUnknownDevices":false}`), so the SDK's
// Execute() fails to unmarshal. We issue the two GETs ourselves and decode each
// into its object shape. The returned http.Response is the first call's
// response so callers can branch on its status code.
func (m *ApiExtension) GetAttackProtectionSettings(ctx context.Context) (*AttackProtectionSettings, *http.Response, error) {
	var lockout struct {
		PreventBruteForceLockoutFromUnknownDevices bool `json:"preventBruteForceLockoutFromUnknownDevices"`
	}
	resp, err := m.get(ctx, m.url("/attack-protection/api/v1/user-lockout-settings"), &lockout)
	if err != nil {
		return nil, resp, err
	}

	var authenticator struct {
		VerifyKnowledgeSecondWhen2faRequired bool `json:"verifyKnowledgeSecondWhen2faRequired"`
	}
	if _, err := m.get(ctx, m.url("/attack-protection/api/v1/authenticator-settings"), &authenticator); err != nil {
		return nil, resp, err
	}

	return &AttackProtectionSettings{
		PreventBruteForceLockoutFromUnknownDevices: lockout.PreventBruteForceLockoutFromUnknownDevices,
		VerifyKnowledgeSecondWhen2faRequired:       authenticator.VerifyKnowledgeSecondWhen2faRequired,
	}, resp, nil
}

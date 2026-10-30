// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"fmt"
	"time"
)

// JsonWebKey is the full JWK shape the endpoint returns. The generated
// AuthorizationServerJsonWebKey model only types a subset
// (alg/e/kid/kty/n/status/use), dropping created/lastUpdated/expiresAt/
// keyOps/x5c/x5t/x5tS256. We decode the raw credentials/keys response ourselves
// so those fields stay populated rather than reading empty.
type JsonWebKey struct {
	Kid         string     `json:"kid,omitempty"`
	Status      string     `json:"status,omitempty"`
	Alg         string     `json:"alg,omitempty"`
	Kty         string     `json:"kty,omitempty"`
	Use         string     `json:"use,omitempty"`
	KeyOps      []string   `json:"key_ops,omitempty"`
	Created     *time.Time `json:"created,omitempty"`
	LastUpdated *time.Time `json:"lastUpdated,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	X5c         []string   `json:"x5c,omitempty"`
	X5t         string     `json:"x5t,omitempty"`
	X5tS256     string     `json:"x5t#S256,omitempty"`
	N           string     `json:"n,omitempty"`
	E           string     `json:"e,omitempty"`
}

// ListAuthorizationServerKeys fetches the signing keys for an authorization
// server, decoding the full JWK shape (see JsonWebKey) rather than the trimmed
// generated model.
func (m *ApiExtension) ListAuthorizationServerKeys(ctx context.Context, authServerId string) ([]*JsonWebKey, error) {
	var keys []*JsonWebKey
	url := m.url(fmt.Sprintf("/api/v1/authorizationServers/%s/credentials/keys", authServerId))
	if _, err := m.get(ctx, url, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

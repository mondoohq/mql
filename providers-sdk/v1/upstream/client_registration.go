// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	unverified_jwt "github.com/golang-jwt/jwt/v5"
)

type CustomTokenClaims struct {
	Space          string            `json:"space"`
	Description    string            `json:"desc"`
	ApiEndpoint    string            `json:"api_endpoint"`
	Labels         map[string]string `json:"labels"`
	Owner          string            `json:"owner"`
	CertValidUntil time.Time         `json:"cert_valid_until"`
}

type VerifyClaim struct {
	jwt.Claims
	CustomTokenClaims
}

func (a *VerifyClaim) IsExpired() bool {
	if a.Expiry != nil && time.Now().After(a.Expiry.Time()) {
		return true
	}
	return false
}

type extractTokenClaims struct {
	unverified_jwt.RegisteredClaims
	CustomTokenClaims
}

// ExtractTokenClaims is just reading the jwt token and extracts the claims
// This is especially useful for the client that has no access to the certificate
// to verify the token but still want to display information like expiry time and description
func ExtractTokenClaims(token string) (*VerifyClaim, error) {
	unverifiedClaims := &extractTokenClaims{}
	p := unverified_jwt.Parser{}
	_, _, err := p.ParseUnverified(token, unverifiedClaims)
	if err != nil {
		return nil, err
	}

	// convert to AmsVerifyClaim
	var expiry *jwt.NumericDate
	if unverifiedClaims.ExpiresAt != nil {
		nd := jwt.NumericDate(unverifiedClaims.ExpiresAt.Unix())
		expiry = &nd
	}

	var notBefore *jwt.NumericDate
	if unverifiedClaims.NotBefore != nil {
		nd := jwt.NumericDate(unverifiedClaims.NotBefore.Unix())
		notBefore = &nd
	}

	var issuedAt *jwt.NumericDate
	if unverifiedClaims.IssuedAt != nil {
		nd := jwt.NumericDate(unverifiedClaims.IssuedAt.Unix())
		notBefore = &nd
	}

	out := VerifyClaim{
		ID:                unverifiedClaims.ID,
		Issuer:            unverifiedClaims.Issuer,
		Subject:           unverifiedClaims.Subject,
		Audience:          jwt.Audience(unverifiedClaims.Audience),
		Expiry:            expiry,
		NotBefore:         notBefore,
		IssuedAt:          issuedAt,
		CustomTokenClaims: unverifiedClaims.CustomTokenClaims,
	}

	return &out, nil
}

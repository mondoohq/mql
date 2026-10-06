// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// KeyProofType is the JWS "typ" header of a proof of possession.
	KeyProofType = "mondoo-key-proof+jwt"
	// MaxKeyProofLifetime is the longest validity (exp - iat) the server accepts.
	MaxKeyProofLifetime = 900 * time.Second
)

// GenerateKey creates the per-login P-384 key. The private half never leaves
// this machine; the server issues a certificate for the public half.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// EncodePublicKey returns base64url (no padding) of the DER SubjectPublicKeyInfo.
func EncodePublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

// EncodePrivateKeyPEM returns the key as a PKCS#8 "PRIVATE KEY" PEM block.
func EncodePrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// HashValue is base64url(SHA-256(v)), used to bind a proof to one code or token.
func HashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewKeyProof signs a compact ES384 JWS proving possession of key. audience is
// the exact URL of the endpoint receiving it and bound is the code, device code
// or token the proof is tied to. lifetime is capped at MaxKeyProofLifetime.
//
// The claims are a plain map so "aud" serializes as a single string.
func NewKeyProof(key *ecdsa.PrivateKey, audience, bound string, issuedAt time.Time, lifetime time.Duration) (string, error) {
	if lifetime <= 0 || lifetime > MaxKeyProofLifetime {
		lifetime = MaxKeyProofLifetime
	}
	claims := jwt.MapClaims{
		"iss":       ClientID,
		"aud":       audience,
		"iat":       issuedAt.Unix(),
		"exp":       issuedAt.Add(lifetime).Unix(),
		"jti":       randomString(16),
		"code_hash": HashValue(bound),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	tok.Header["typ"] = KeyProofType
	return tok.SignedString(key)
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

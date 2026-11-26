// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// minRSABits is the smallest RSA key a key signer may use.
const minRSABits = 2048

// LoadPublicKey parses one PEM public key and returns it with its
// fingerprint, "sha256:<hex>" of the DER SubjectPublicKeyInfo. ECDSA P-256,
// P-384 and P-521, Ed25519 and RSA of at least 2048 bits are accepted;
// anything else is an error.
func LoadPublicKey(pemBytes []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", errors.New("the public key is not a PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("reading the public key: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return nil, "", fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return nil, "", fmt.Errorf("an RSA key of %d bits is too weak, at least %d are required", k.N.BitLen(), minRSABits)
		}
	default:
		return nil, "", fmt.Errorf("unsupported public key type %T", pub)
	}
	return pub, Fingerprint(block.Bytes), nil
}

// LoadPublicKeys parses concatenated PEM public keys.
func LoadPublicKeys(pemBytes []byte) (map[string]crypto.PublicKey, error) {
	out := map[string]crypto.PublicKey{}
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		pub, fp, err := LoadPublicKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, err
		}
		out[fp] = pub
	}
	if len(out) == 0 && strings.TrimSpace(string(pemBytes)) != "" {
		return nil, errors.New("no PEM public key found")
	}
	return out, nil
}

// Fingerprint is how a key signer is named: "sha256:<hex>" of its DER
// SubjectPublicKeyInfo.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fingerprintOf returns the fingerprint of a parsed public key.
func fingerprintOf(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return Fingerprint(der), nil
}

// normalizeFingerprint reads a key fingerprint or a bundle's public key hint
// in the forms in use: "sha256:<hex>", bare hex, or the base64 of the
// sha256. It returns "sha256:<hex>", or "" when s is none of them.
func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "sha256:"), "SHA256:")
	if b, err := hex.DecodeString(s); err == nil && len(b) == sha256.Size {
		return "sha256:" + strings.ToLower(s)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == sha256.Size {
			return "sha256:" + hex.EncodeToString(b)
		}
	}
	return ""
}

// pemBlocks splits concatenated PEM blocks.
func pemBlocks(b []byte) []string {
	var out []string
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, string(pem.EncodeToMemory(block)))
	}
}

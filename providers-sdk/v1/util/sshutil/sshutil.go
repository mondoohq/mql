// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sshutil derives cryptographic posture (key algorithm and size) from
// OpenSSH public keys. Providers use it to surface SSH key algorithm and key
// size for post-quantum-cryptography readiness audits.
package sshutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

// ParsePublicKey extracts the key algorithm and size in bits from an
// OpenSSH-format public key. It returns ("", 0) when the key cannot be parsed
// so weak-key audits can distinguish "unparseable" from a known algorithm.
func ParsePublicKey(publicKey string) (algorithm string, bits int64) {
	algorithm, bits, _, _ = ParseAuthorizedKey(publicKey)
	return algorithm, bits
}

// ParseAuthorizedKey extracts the algorithm, size in bits, and trailing comment
// from a single OpenSSH-format public key line. ok is false when the line
// cannot be parsed so weak-key audits can distinguish "unparseable" from a
// known algorithm.
func ParseAuthorizedKey(line string) (algorithm string, bits int64, comment string, ok bool) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || pub == nil {
		return "", 0, "", false
	}
	algorithm = pub.Type()
	if ck, isCrypto := pub.(ssh.CryptoPublicKey); isCrypto {
		switch k := ck.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			bits = int64(k.N.BitLen())
		case *ecdsa.PublicKey:
			bits = int64(k.Curve.Params().BitSize)
		case ed25519.PublicKey:
			bits = 256
		}
	}
	return algorithm, bits, comment, true
}

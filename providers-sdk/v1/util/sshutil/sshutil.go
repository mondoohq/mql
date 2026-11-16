// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sshutil derives cryptographic posture (key algorithm and size) from
// OpenSSH public keys. Providers use it to surface SSH key algorithm and key
// size for post-quantum-cryptography readiness audits.
package sshutil

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA is deprecated, but legacy DSA keys are still detected for crypto-posture audits
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"

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
	pub, comment, _, err := ParseAuthorizedKeyLine([]byte(line))
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
		case *dsa.PublicKey:
			bits = int64(k.P.BitLen())
		}
	}
	return algorithm, bits, comment, true
}

// ParseAuthorizedKeyLine parses one authorized_keys line like
// ssh.ParseAuthorizedKey, and also reads "ssh-dss" keys, which x/crypto/ssh
// stopped parsing in v0.59.0.
func ParseAuthorizedKeyLine(line []byte) (key ssh.PublicKey, comment string, options []string, err error) {
	key, comment, options, _, err = ssh.ParseAuthorizedKey(line)
	if err == nil {
		return key, comment, options, nil
	}
	if dsaKey, dsaComment, dsaOptions, ok := parseDSAAuthorizedKey(line); ok {
		return dsaKey, dsaComment, dsaOptions, nil
	}
	return nil, "", nil, err
}

// ParsePublicKeyBlob parses a public key in the SSH wire format like
// ssh.ParsePublicKey, and also reads "ssh-dss" keys.
func ParsePublicKeyBlob(blob []byte) (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(blob)
	if err == nil {
		return key, nil
	}
	if dsaKey, ok := parseDSAPublicKey(blob); ok {
		return dsaKey, nil
	}
	return nil, err
}

// dsaPublicKey is an "ssh-dss" key. It reports the key and its parameters;
// it cannot verify signatures.
type dsaPublicKey dsa.PublicKey

var errDSAVerify = errors.New("ssh: DSA signatures are not supported")

func (k *dsaPublicKey) Type() string { return ssh.InsecureKeyAlgoDSA }

func (k *dsaPublicKey) Marshal() []byte {
	return ssh.Marshal(dsaWire{ssh.InsecureKeyAlgoDSA, k.P, k.Q, k.G, k.Y, nil})
}

func (k *dsaPublicKey) Verify([]byte, *ssh.Signature) error { return errDSAVerify }

func (k *dsaPublicKey) CryptoPublicKey() crypto.PublicKey { return (*dsa.PublicKey)(k) }

// dsaWire is the "ssh-dss" public key blob of RFC 4253 section 6.6.
type dsaWire struct {
	Type       string
	P, Q, G, Y *big.Int
	Rest       []byte `ssh:"rest"`
}

func parseDSAPublicKey(blob []byte) (*dsaPublicKey, bool) {
	var w dsaWire
	if err := ssh.Unmarshal(blob, &w); err != nil || w.Type != ssh.InsecureKeyAlgoDSA || len(w.Rest) != 0 || w.P.Sign() <= 0 {
		return nil, false
	}
	return &dsaPublicKey{Parameters: dsa.Parameters{P: w.P, Q: w.Q, G: w.G}, Y: w.Y}, true
}

// parseDSAAuthorizedKey reads an authorized_keys line whose key type is
// "ssh-dss": an optional options field, the key type, the base64 key blob
// and an optional comment, as sshd(8) describes the format.
func parseDSAAuthorizedKey(line []byte) (*dsaPublicKey, string, []string, bool) {
	in := bytes.TrimSpace(line)
	var options []string
	keyType, rest := cutField(in)
	if string(keyType) != ssh.InsecureKeyAlgoDSA {
		options, in = cutOptions(in)
		keyType, rest = cutField(in)
		if string(keyType) != ssh.InsecureKeyAlgoDSA {
			return nil, "", nil, false
		}
	}
	encoded, comment := cutField(rest)
	blob, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, "", nil, false
	}
	key, ok := parseDSAPublicKey(blob)
	if !ok {
		return nil, "", nil, false
	}
	return key, string(bytes.TrimSpace(comment)), options, true
}

func isBlank(b byte) bool { return b == ' ' || b == '\t' }

// cutField splits off the first space- or tab-separated field of in.
func cutField(in []byte) (field, rest []byte) {
	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		return in, nil
	}
	return in[:i], bytes.TrimLeft(in[i:], " \t")
}

// cutOptions splits off the comma-separated options field that may lead an
// authorized_keys line. Commas and blanks inside double quotes belong to the
// option, and \" does not close a quote.
func cutOptions(in []byte) (options []string, rest []byte) {
	inQuote := false
	start := 0
	for i, b := range in {
		end := !inQuote && isBlank(b)
		if (b == ',' && !inQuote) || end {
			if i > start {
				options = append(options, string(in[start:i]))
			}
			start = i + 1
		}
		if end {
			return options, bytes.TrimLeft(in[i:], " \t")
		}
		if b == '"' && (i == 0 || in[i-1] != '\\') {
			inQuote = !inQuote
		}
	}
	return nil, nil
}

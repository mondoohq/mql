// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package keypair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

const DefaultRsaBits = 4096

// SSH holds an SSH keys pair
type SSH struct {
	// PrivateKey contains PEM encoded private key
	PrivateKey []byte

	// PublicKey serializes key for inclusion in an OpenSSH authorized_keys file
	// https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
	PublicKey []byte

	// Optional Passphrase
	Passphrase []byte
}

// NewEd25519Keys creates EdD25519 key pair
func NewEd25519Keys() (*SSH, error) {
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := MarshalED25519PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &SSH{
		PrivateKey: pem.EncodeToMemory(&pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: privateKeyBytes,
		}),
		PublicKey: MarshalPublicKey(publicKey, ""),
	}, nil
}

// NewRSAKeys creates RSA key pair
func NewRSAKeys(bits int, passphrase []byte) (*SSH, error) {
	// generate rsa private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey), // ASN.1 DER format
	}

	// optional: encrypt private key with passphrase
	if len(passphrase) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, passphrase, x509.PEMCipherAES256) //nolint:staticcheck // legacy PEM encryption required for compatibility
		if err != nil {
			return nil, err
		}
	}

	// generate rsa public key
	publicRSAKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	return &SSH{
		PrivateKey: pem.EncodeToMemory(block), // PEM encoded
		PublicKey:  MarshalPublicKey(publicRSAKey, ""),
		Passphrase: passphrase,
	}, nil
}

func MarshalPublicKey(pubKey ssh.PublicKey, note string) []byte {
	return append(bytes.TrimRight(ssh.MarshalAuthorizedKey(pubKey), "\n"), []byte(note)...)
}

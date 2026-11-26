// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshutil

import (
	"crypto/dsa" //nolint:staticcheck // legacy DSA keys are what this tests
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// dsaKeyBlob generates a 1024-bit DSA key and returns its "ssh-dss" wire
// blob (RFC 4253 section 6.6), encoded here independently of the parser.
func dsaKeyBlob(t *testing.T) []byte {
	t.Helper()
	var key dsa.PrivateKey
	require.NoError(t, dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(&key, rand.Reader))
	return ssh.Marshal(struct {
		Type       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", key.P, key.Q, key.G, key.Y})
}

// Synthetic: x/crypto/ssh stopped parsing ssh-dss keys in v0.59.0, and
// OpenSSH 10 no longer generates them, but authorized_keys files on older
// hosts still hold them.
func TestParseAuthorizedKeyLineDSA(t *testing.T) {
	blob := dsaKeyBlob(t)
	b64 := base64.StdEncoding.EncodeToString(blob)

	t.Run("plain", func(t *testing.T) {
		key, comment, options, err := ParseAuthorizedKeyLine([]byte("ssh-dss " + b64 + " old@host"))
		require.NoError(t, err)
		assert.Equal(t, "ssh-dss", key.Type())
		assert.Equal(t, "old@host", comment)
		assert.Empty(t, options)
		assert.Equal(t, blob, key.Marshal())
		assert.Error(t, key.Verify([]byte("data"), &ssh.Signature{Format: "ssh-dss"}))

		algorithm, bits, comment, ok := ParseAuthorizedKey("ssh-dss " + b64 + " old@host")
		assert.True(t, ok)
		assert.Equal(t, "ssh-dss", algorithm)
		assert.Equal(t, int64(1024), bits)
		assert.Equal(t, "old@host", comment)
	})

	t.Run("options with quoted commas and blanks", func(t *testing.T) {
		line := `  command="echo a, b",no-pty	ssh-dss ` + b64
		key, comment, options, err := ParseAuthorizedKeyLine([]byte(line))
		require.NoError(t, err)
		assert.Equal(t, "ssh-dss", key.Type())
		assert.Equal(t, "", comment)
		assert.Equal(t, []string{`command="echo a, b"`, "no-pty"}, options)
	})

	t.Run("declared type does not match the blob", func(t *testing.T) {
		_, _, _, err := ParseAuthorizedKeyLine([]byte("ssh-rsa " + b64))
		assert.Error(t, err)
	})

	t.Run("bad base64", func(t *testing.T) {
		_, _, _, err := ParseAuthorizedKeyLine([]byte("ssh-dss !!notbase64!! c"))
		assert.Error(t, err)
	})

	t.Run("trailing bytes in the blob", func(t *testing.T) {
		extra := base64.StdEncoding.EncodeToString(append(blob, 0, 0, 0, 1, 'x'))
		_, _, _, err := ParseAuthorizedKeyLine([]byte("ssh-dss " + extra))
		assert.Error(t, err)
	})
}

func TestParsePublicKeyBlobDSA(t *testing.T) {
	blob := dsaKeyBlob(t)
	key, err := ParsePublicKeyBlob(blob)
	require.NoError(t, err)
	assert.Equal(t, "ssh-dss", key.Type())
	dsaKey, ok := key.(ssh.CryptoPublicKey).CryptoPublicKey().(*dsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 1024, dsaKey.P.BitLen())

	_, err = ParsePublicKeyBlob(blob[:len(blob)-4])
	assert.Error(t, err)
}

const (
	ed25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATxrDDkLHMi0EMdsCES8icnsrbj+2ra3lsm2cjefUA7 alice@laptop"
	rsa2048Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzWUJ5o5nE8AvOzLTV45xJ7b7U3vcH3idgxSQRGumbgXR0JY2O36R6Da6reu+sy1Nio3QjHNX/0prUscJli/N1F8g512wDFwhbFtIUW5J3J4Np2PuGJftxjD119w4uanp47E7kj76IX1TuS86RyZXAAlOJ3BWIrDR/TCoCEdYfCl8yydaIv8Ook5ip1qjZi7JP/RtXagiFOTtvbOmUBeTFz2hDalk6un+l0V4sOE3taULMfaFRwhBi+XeNlnfSmsl1+Bp/T3qJMxLsgRV1AEhwg6hestMGN49TB/YIogiMhAcM8ACF47HIxDMeoNxZJmuRg2tTkDLh4DAG02czba0l"
	ecdsaKey   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHoiyNRU8Tk5rBs6ve4wExUzriltXZ/bl8YiuPfd7nF1kC894F306jKgJE0/0JIWSIcMWKeu1o6+e6fa64TwYig= test"
)

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name          string
		publicKey     string
		wantAlgorithm string
		wantBits      int64
	}{
		{"ed25519", ed25519Key, "ssh-ed25519", 256},
		{"rsa 2048", rsa2048Key, "ssh-rsa", 2048},
		{"ecdsa nistp256", ecdsaKey, "ecdsa-sha2-nistp256", 256},
		{"unparseable", "not a valid key", "", 0},
		{"empty", "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm, bits := ParsePublicKey(tt.publicKey)
			assert.Equal(t, tt.wantAlgorithm, algorithm)
			assert.Equal(t, tt.wantBits, bits)
		})
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	t.Run("returns comment and ok for a valid key", func(t *testing.T) {
		algorithm, bits, comment, ok := ParseAuthorizedKey(ed25519Key)
		assert.True(t, ok)
		assert.Equal(t, "ssh-ed25519", algorithm)
		assert.Equal(t, int64(256), bits)
		assert.Equal(t, "alice@laptop", comment)
	})

	t.Run("ok is false for an unparseable line", func(t *testing.T) {
		_, _, _, ok := ParseAuthorizedKey("garbage")
		assert.False(t, ok)
	})
}

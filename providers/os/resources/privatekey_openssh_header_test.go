// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/dsa" //nolint:staticcheck // OpenSSH-format DSA keys are what this tests
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// opensshDSAKey writes a DSA private key in the OpenSSH format, laid out as
// ssh-keygen 7.8+ writes it (PROTOCOL.key): `ssh-keygen -t dsa` on Debian 10
// produces this format, and x/crypto/ssh can marshal it for every key type
// but DSA. With a passphrase, the private section is opaque ciphertext
// behind an aes256-ctr/bcrypt header; only the clear header is read.
func opensshDSAKey(t *testing.T, encrypted bool) []byte {
	t.Helper()
	var key dsa.PrivateKey
	require.NoError(t, dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(&key, rand.Reader))
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	require.NoError(t, err)

	check := uint32(0x5eed)
	priv := ssh.Marshal(struct {
		Check1, Check2 uint32
		KeyType        string
		P, Q, G, Y, X  *big.Int
		Comment        string
	}{check, check, "ssh-dss", key.P, key.Q, key.G, key.Y, key.X, "mql-test-dsa"})
	// padded to the cipher block size, 8 without a cipher
	blockSize := 8
	if encrypted {
		blockSize = 16
	}
	for i := byte(1); len(priv)%blockSize != 0; i++ {
		priv = append(priv, i)
	}

	cipher, kdf, kdfOpts := "none", "none", ""
	if encrypted {
		cipher, kdf = "aes256-ctr", "bcrypt"
		kdfOpts = string(ssh.Marshal(struct {
			Salt   string
			Rounds uint32
		}{"0123456789abcdef", 16}))
		_, err := rand.Read(priv)
		require.NoError(t, err)
	}

	body := append([]byte(opensshKeyMagic), ssh.Marshal(struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}{cipher, kdf, kdfOpts, 1, pub.Marshal(), priv})...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})
}

// x/crypto/ssh cannot decode an OpenSSH-format DSA key ("ssh: unhandled key
// type"), which errored every field of the key in user.sshkeys.
func TestPrivatekeyOpenSSHDSA(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			data := opensshDSAKey(t, encrypted)

			info, err := inspectPrivateKey(data)
			require.NoError(t, err)
			assert.Equal(t, privateKeyInfo{Encrypted: encrypted, Algorithm: "DSA", Bits: 1024}, info)

			pk := newPrivatekey(string(data))
			algo, err := pk.publicKeyAlgorithm()
			require.NoError(t, err)
			assert.Equal(t, "DSA", algo)
			bits, err := pk.publicKeyBits()
			require.NoError(t, err)
			assert.Equal(t, int64(1024), bits)
		})
	}
}

// A body that starts like an OpenSSH key but is cut short is still an
// error: the header fallback must not invent values for it.
func TestPrivatekeyOpenSSHTruncatedHeader(t *testing.T) {
	block, _ := pem.Decode(opensshDSAKey(t, false))
	require.NotNil(t, block)

	for _, n := range []int{len(opensshKeyMagic), len(opensshKeyMagic) + 20, 60} {
		truncated := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes[:n]})
		_, err := inspectPrivateKey(truncated)
		assert.Error(t, err, "truncated at %d bytes", n)
	}
}

func TestPrivatekeyOpenSSHWrongMagic(t *testing.T) {
	block, _ := pem.Decode(opensshDSAKey(t, false))
	require.NotNil(t, block)

	body := append([]byte("openssh-key-v2\x00"), block.Bytes[len(opensshKeyMagic):]...)
	_, ok := inspectOpenSSHKeyHeader(body)
	assert.False(t, ok)

	_, ok = inspectOpenSSHKeyHeader(block.Bytes)
	assert.True(t, ok)
}

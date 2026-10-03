// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"golang.org/x/crypto/ssh"
)

// pkcs8PEM marshals a private key to an unencrypted PKCS#8 PEM block.
func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// opensshPEM marshals a private key to an OpenSSH-format PEM block. This is the
// default output of `ssh-keygen`, and unlike PKCS#8 it makes ParseRawPrivateKey
// return a *pointer* (e.g. *ed25519.PrivateKey), which the introspection
// switches must handle alongside the PKCS#8 value type.
func opensshPEM(t *testing.T, key any) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

// newPrivatekey builds a privatekey resource whose static pem field is set,
// so the computed publicKeyAlgorithm/publicKeyBits helpers can be exercised
// without a live connection.
func newPrivatekey(pemStr string) *mqlPrivatekey {
	return &mqlPrivatekey{
		Pem: plugin.TValue[string]{Data: pemStr, State: plugin.StateIsSet},
	}
}

func TestPrivatekeyPublicKeyIntrospection(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name          string
		pem           string
		wantAlgorithm string
		wantBits      int64
	}{
		{
			name:          "RSA-2048",
			pem:           pkcs8PEM(t, rsaKey),
			wantAlgorithm: "RSA",
			wantBits:      2048,
		},
		{
			name:          "ECDSA P-256",
			pem:           pkcs8PEM(t, ecKey),
			wantAlgorithm: "ECDSA",
			wantBits:      256,
		},
		{
			name:          "Ed25519",
			pem:           pkcs8PEM(t, edKey),
			wantAlgorithm: "Ed25519",
			wantBits:      256,
		},
		{
			// OpenSSH format yields a *ed25519.PrivateKey (pointer), unlike the
			// PKCS#8 case above which yields the value type. Both must resolve.
			name:          "Ed25519 (OpenSSH)",
			pem:           opensshPEM(t, edKey),
			wantAlgorithm: "Ed25519",
			wantBits:      256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pk := newPrivatekey(tc.pem)

			algo, err := pk.publicKeyAlgorithm()
			require.NoError(t, err)
			require.Equal(t, tc.wantAlgorithm, algo)

			bits, err := pk.publicKeyBits()
			require.NoError(t, err)
			require.Equal(t, tc.wantBits, bits)
		})
	}
}

func TestPrivatekeyEncryptedLegacyPEM(t *testing.T) {
	// Legacy PEM encryption (`Proc-Type: 4,ENCRYPTED`) hides the key size but
	// the block type still names the algorithm. The size is null, not 0.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated but still the
	// simplest way to produce an encrypted PEM fixture for this test.
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte("secret"), x509.PEMCipherAES256)
	require.NoError(t, err)
	data := pem.EncodeToMemory(encBlock)

	require.True(t, keyEncrypted(data))

	pk := newPrivatekey(string(data))
	algo, err := pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.Equal(t, "RSA", algo)

	_, err = pk.publicKeyBits()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyBits.IsNull())
}

func TestPrivatekeyEncryptedOpenSSH(t *testing.T) {
	// `ssh-keygen -N <passphrase>` writes an OpenSSH-format key whose PEM text
	// has no ENCRYPTED marker; the cipher name is inside the base64 body and
	// the public key is stored unencrypted next to it.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      any
		wantAlgo string
		wantBits int64
	}{
		{"Ed25519", edKey, "Ed25519", 256},
		{"RSA-3072", rsaKey, "RSA", 3072},
		{"ECDSA P-384", ecKey, "ECDSA", 384},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKeyWithPassphrase(tc.key, "", []byte("secret"))
			require.NoError(t, err)
			data := pem.EncodeToMemory(block)
			require.NotContains(t, string(data), "ENCRYPTED")

			require.True(t, keyEncrypted(data))

			pk := newPrivatekey(string(data))
			algo, err := pk.publicKeyAlgorithm()
			require.NoError(t, err)
			require.Equal(t, tc.wantAlgo, algo)

			bits, err := pk.publicKeyBits()
			require.NoError(t, err)
			require.Equal(t, tc.wantBits, bits)
		})
	}
}

func TestPrivatekeyEncryptedPKCS8(t *testing.T) {
	// `openssl pkcs8 -topk8 -v2 aes256` writes an ENCRYPTED PRIVATE KEY block,
	// which x/crypto/ssh rejects as an unsupported key type. The body is
	// opaque to the parser, so random bytes stand in for the ciphertext.
	body := make([]byte, 128)
	_, err := rand.Read(body)
	require.NoError(t, err)
	data := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: body})

	require.True(t, keyEncrypted(data))

	pk := newPrivatekey(string(data))
	_, err = pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyAlgorithm.IsNull())

	_, err = pk.publicKeyBits()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyBits.IsNull())
}

func TestPrivatekeyUnencryptedNotReportedEncrypted(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	require.False(t, keyEncrypted([]byte(opensshPEM(t, edKey))))
	require.False(t, keyEncrypted([]byte(pkcs8PEM(t, rsaKey))))
	require.False(t, keyEncrypted([]byte("not a valid pem")))
}

// keyEncrypted mirrors how user.sshkeys derives the encrypted field.
func keyEncrypted(data []byte) bool {
	info, err := inspectPrivateKey(data)
	return err == nil && info.Encrypted
}

func TestPrivatekeySeededParseIsNotRepeated(t *testing.T) {
	// user.sshkeys inspects each key once and seeds the result; the accessors
	// must use it rather than parse the PEM again. The PEM here is garbage, so
	// a second parse would return an error instead of the seeded values.
	pk := newPrivatekey("not a valid pem")
	pk.seedParsedKey(privateKeyInfo{Encrypted: true, Algorithm: "Ed25519", Bits: 256}, nil)

	algo, err := pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.Equal(t, "Ed25519", algo)

	bits, err := pk.publicKeyBits()
	require.NoError(t, err)
	require.Equal(t, int64(256), bits)
}

func TestPrivatekeyGarbagePEM(t *testing.T) {
	pk := newPrivatekey("not a valid pem")

	_, err := pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyAlgorithm.IsNull())

	_, err = pk.publicKeyBits()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyBits.IsNull())
}

// explicitCurvePKCS8 is the shape `openssl genpkey -algorithm EC
// -pkeyopt ec_paramgen_curve:prime256v1` writes on RHEL 7 (OpenSSL 1.0.2,
// no named-curve encoding): the curve is spelled out as explicit
// parameters, which x/crypto and OpenSSH 7.4 both reject with
// "x509: unknown elliptic curve".
func explicitCurvePKCS8(t *testing.T) string {
	t.Helper()
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	type pkcs8 struct {
		Version    int
		Algo       algorithmIdentifier
		PrivateKey []byte
	}
	type ecPrivateKey struct {
		Version    int
		PrivateKey []byte
	}
	// ECParameters ::= SEQUENCE { version, fieldID, curve, base, order, ... }
	params, err := asn1.Marshal(struct {
		Version int
		FieldID struct {
			FieldType asn1.ObjectIdentifier
			Prime     *big.Int
		}
	}{Version: 1, FieldID: struct {
		FieldType asn1.ObjectIdentifier
		Prime     *big.Int
	}{asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, elliptic.P256().Params().P}})
	require.NoError(t, err)
	inner, err := asn1.Marshal(ecPrivateKey{Version: 1, PrivateKey: make([]byte, 32)})
	require.NoError(t, err)
	der, err := asn1.Marshal(pkcs8{
		Algo: algorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PrivateKey: inner,
	})
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestPrivatekeyUnparsableKeyIsNull(t *testing.T) {
	data := []byte(explicitCurvePKCS8(t))
	_, inspectErr := inspectPrivateKey(data)
	require.ErrorContains(t, inspectErr, "unknown elliptic curve")

	// as user.sshkeys builds it: inspected once, the result seeded
	pk := newPrivatekey(string(data))
	pk.seedParsedKey(inspectPrivateKey(data))
	_, err := pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyAlgorithm.IsNull())
	_, err = pk.publicKeyBits()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyBits.IsNull())

	// as privatekey(pem: ...) parses it on demand
	pk = newPrivatekey(string(data))
	_, err = pk.publicKeyAlgorithm()
	require.NoError(t, err)
	require.True(t, pk.PublicKeyAlgorithm.IsNull())
}

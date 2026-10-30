// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // RFC 4121 mandates MD5 for the binding field
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	krbflags "github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewAPREQMechTokenRequiresMutualAuth decodes the AP-REQ we send and checks
// the mutual-required AP option. go-ldap's GSSAPIBind passes no AP options, and
// Active Directory rejects an AP-REQ without this one (AcceptSecurityContext
// data 57, go-ldap issue #536).
func TestNewAPREQMechTokenRequiresMutualAuth(t *testing.T) {
	c := &channelBindingGSSAPIClient{
		krb5: krbclient.NewWithPassword("svc", "TEST.LOCAL", "secret", config.New()),
		bnd:  make([]byte, 16),
	}
	sessionKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	tkt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   "TEST.LOCAL",
		SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "ldap/dc.test.local"),
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1, Cipher: []byte{0}},
	}

	b, err := c.newAPREQMechToken(tkt, sessionKey, []int{gssapi.ContextFlagMutual}, nil)
	require.NoError(t, err)

	var token spnego.KRB5Token
	require.NoError(t, token.Unmarshal(b))
	require.True(t, token.IsAPReq())
	assert.True(t, types.IsFlagSet(&token.APReq.APOptions, krbflags.APOptionMutualRequired))
}

// TestAuthenticatorChecksumNoBindingMatchesGokrb5 pins the no-binding checksum
// to gokrb5's own reference vector (spnego.newAuthenticatorChksum), proving our
// reimplementation is byte-for-byte identical when no channel binding is set —
// i.e. plaintext LDAP and unhardened DCs are completely unaffected.
func TestAuthenticatorChecksumNoBindingMatchesGokrb5(t *testing.T) {
	// From gokrb5 spnego/krb5Token_test.go (AuthChksum), flags Integ|Conf.
	want, err := hex.DecodeString("100000000000000000000000000000000000000030000000")
	require.NoError(t, err)

	got := authenticatorChecksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, nil)
	assert.Equal(t, want, got)
}

// TestAuthenticatorChecksumLayout verifies the RFC 4121 §4.1.1 field layout when
// a channel binding is present: length prefix 16, the 16-byte binding, then flags.
func TestAuthenticatorChecksumLayout(t *testing.T) {
	bnd := make([]byte, 16)
	for i := range bnd {
		bnd[i] = byte(i + 1)
	}
	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	got := authenticatorChecksum(flags, bnd)

	require.Len(t, got, 24)
	assert.Equal(t, uint32(16), binary.LittleEndian.Uint32(got[0:4]), "length prefix must be 16")
	assert.Equal(t, bnd, got[4:20], "binding must occupy bytes 4:20")

	var wantFlags uint32
	for _, f := range flags {
		wantFlags |= uint32(f)
	}
	assert.Equal(t, wantFlags, binary.LittleEndian.Uint32(got[20:24]), "flags must be OR-ed into bytes 20:24")
}

// TestAuthenticatorChecksumNilVsEmptyBinding confirms nil and 16 zero bytes are
// equivalent (both mean "no binding").
func TestAuthenticatorChecksumNilVsEmptyBinding(t *testing.T) {
	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	assert.Equal(t,
		authenticatorChecksum(flags, nil),
		authenticatorChecksum(flags, make([]byte, 16)),
	)
}

// TestTLSServerEndPointBinding verifies the RFC 5929 tls-server-end-point Bnd:
// MD5 of the GSS_C channel-bindings structure (four zero address fields, then
// the application-data length and bytes), where application data is
// "tls-server-end-point:" + certificate hash.
func TestTLSServerEndPointBinding(t *testing.T) {
	cert := generateTestCert(t, x509.SHA256WithRSA)

	// Independent reconstruction of the expected value.
	certHash := sha256Sum(cert.Raw)
	appData := append([]byte("tls-server-end-point:"), certHash...)
	buf := make([]byte, 20+len(appData))
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(appData)))
	copy(buf[20:], appData)
	sum := md5.Sum(buf) //nolint:gosec
	want := sum[:]

	got := tlsServerEndPointBinding(cert)
	require.Len(t, got, 16)
	assert.Equal(t, want, got)
}

// TestTLSServerEndPointBindingNilCert ensures a plaintext transport (nil cert)
// yields no binding.
func TestTLSServerEndPointBindingNilCert(t *testing.T) {
	assert.Nil(t, tlsServerEndPointBinding(nil))
}

// TestCertificateHashAlgorithmSelection covers RFC 5929 §4.1: the cert hash uses
// the certificate signature algorithm's hash, upgrading MD5/SHA-1 to SHA-256.
func TestCertificateHashAlgorithmSelection(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		hash    crypto.Hash
	}{
		{"sha256 stays sha256", x509.SHA256WithRSA, crypto.SHA256},
		{"sha384 stays sha384", x509.SHA384WithRSA, crypto.SHA384},
		{"sha512 stays sha512", x509.SHA512WithRSA, crypto.SHA512},
		{"sha1 upgrades to sha256", x509.SHA1WithRSA, crypto.SHA256},
		{"ecdsa sha384 stays sha384", x509.ECDSAWithSHA384, crypto.SHA384},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := generateTestCert(t, tc.sigAlgo)
			h := tc.hash.New()
			h.Write(cert.Raw)
			assert.Equal(t, h.Sum(nil), certificateHash(cert))
		})
	}
}

func sha256Sum(b []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(b)
	return h.Sum(nil)
}

// generateTestCert builds a self-signed certificate with the requested signature
// algorithm for channel-binding tests.
func generateTestCert(t *testing.T, sigAlgo x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "dc.test.local"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: sigAlgo,
	}

	var pub, priv any
	switch sigAlgo {
	case x509.ECDSAWithSHA384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		pub, priv = &key.PublicKey, key
	default:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub, priv = &key.PublicKey, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

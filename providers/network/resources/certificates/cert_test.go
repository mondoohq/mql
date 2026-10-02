// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package certificates

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteCertificates(t *testing.T) {
	certChain, err := Fetch("www.google.com:443")
	require.NoError(t, err)
	assert.True(t, len(certChain) >= 2)

	for i := range certChain {
		data, err := EncodeCertAsPEM(certChain[i])
		require.NoError(t, err)
		fmt.Println(string(data))
	}

	assert.Equal(t, "www.google.com", certChain[0].Subject.CommonName)
	// assert.Equal(t, "GTS CA 1C3", certChain[1].Subject.CommonName)
}

func TestParseCertificates(t *testing.T) {
	file := "./testdata/google.crt"

	f, err := os.Open(file)
	require.NoError(t, err)

	certChain, err := ParseCertsFromPEM(f)
	require.NoError(t, err)

	// root certificate is GlobalSign
	// assert.Equal(t, "", certChain[2].Subject.CommonName)

	cert := certChain[0]
	assert.Equal(t, []string{"US"}, cert.Subject.Country)
	assert.Equal(t, []string{"California"}, cert.Subject.Province)
	assert.Equal(t, []string{"Mountain View"}, cert.Subject.Locality)
	assert.Equal(t, []string{"Google LLC"}, cert.Subject.Organization)
	assert.Equal(t, "CN=www.google.com,O=Google LLC,L=Mountain View,ST=California,C=US", cert.Subject.String())

	assert.Equal(t, []string{"US"}, cert.Issuer.Country)
	assert.Equal(t, []string{"Google Trust Services"}, cert.Issuer.Organization)
	assert.Equal(t, "GTS CA 1O1", cert.Issuer.CommonName)
	assert.Equal(t, "CN=GTS CA 1O1,O=Google Trust Services,C=US", cert.Issuer.String())

	assert.Equal(t, int64(1590507003), cert.NotBefore.Unix())
	assert.Equal(t, int64(1597764603), cert.NotAfter.Unix())

	// TODO: subject alt names

	// public key info
	pk := cert.PublicKey.(*ecdsa.PublicKey)
	assert.Equal(t, "P-256", pk.Params().Name)   // NIST Curve
	assert.Equal(t, 256, pk.Params().BitSize)    // Key Size
	assert.Equal(t, 256, pk.Params().P.BitLen()) // Curve: P-256
	assert.Equal(t, "ECDSA", cert.PublicKeyAlgorithm.String())

	// miscellaneous
	// TODO: fill with leading 00 pad
	assert.Equal(t, "b2:6c:68:c0:28:6d:9e:92:08:00:00:00:00:43:55:25", HexEncodeToHumanString(cert.SerialNumber.Bytes()))
	assert.Equal(t, 3, cert.Version)
	assert.Equal(t, "SHA256-RSA", cert.SignatureAlgorithm.String())

	// SHA-1 Fingerprint
	assert.Equal(t, "df:03:32:0d:6d:b8:ac:f2:50:07:24:86:ba:9d:d5:04:15:31:61:ce", HexEncodeToHumanString(Sha1Hash(cert)))

	// SHA-256 Fingerprint
	assert.Equal(t, "91:4e:a6:a7:26:b8:57:f2:56:0d:f5:1c:8d:87:39:36:ab:d9:f2:22:3f:5a:a9:da:25:46:25:8c:11:50:8e:0a", HexEncodeToHumanString(Sha256Hash(cert)))

	// constraints
	assert.Equal(t, false, cert.IsCA)

	// key uses
	assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)

	// extended key uses
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage)

	// subject key id
	assert.Equal(t, "bd:81:6d:df:93:94:14:53:0b:92:39:22:74:9f:33:99:22:f8:f1:15", HexEncodeToHumanString(cert.SubjectKeyId))

	// authority key id
	assert.Equal(t, "98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b", HexEncodeToHumanString(cert.AuthorityKeyId))

	// crl endpoints
	assert.Equal(t, []string{"http://crl.pki.goog/GTS1O1core.crl"}, cert.CRLDistributionPoints)

	// authority info (aia)
	// location, method OCSP
	assert.Equal(t, []string{"http://ocsp.pki.goog/gts1o1core"}, cert.OCSPServer)
	assert.Equal(t, []string{"http://pki.goog/gsr2/GTS1O1.crt"}, cert.IssuingCertificateURL)

	// certificate policies
	// policy name and value
	assert.Equal(t, []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 2}, {1, 3, 6, 1, 4, 1, 11129, 2, 5, 3}}, cert.PolicyIdentifiers)

	// extensions
	for i := range cert.Extensions {
		extension := cert.Extensions[i]
		fmt.Printf("%s: %t value: %s\n", extension.Id, extension.Critical, string(extension.Value))
	}
}

func TestHexPrint(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	res := HexEncodeToHumanString(data)
	assert.Equal(t, "00:01:02:03:04:05:06:07:08:09:0a:0b:0c", res)
}

func TestSerialToHumanString(t *testing.T) {
	// EC-ACC, trusted by Debian 9 and 10, has this negative serial. OpenSSL
	// prints it as serial=-11D4C2142BDE21EB579D53FB0C223BFF.
	ecacc, ok := new(big.Int).SetString("-11D4C2142BDE21EB579D53FB0C223BFF", 16)
	require.True(t, ok)
	assert.Equal(t, "-11:d4:c2:14:2b:de:21:eb:57:9d:53:fb:0c:22:3b:ff", SerialToHumanString(ecacc))

	positive, ok := new(big.Int).SetString("11D4C2142BDE21EB579D53FB0C223BFF", 16)
	require.True(t, ok)
	assert.Equal(t, "11:d4:c2:14:2b:de:21:eb:57:9d:53:fb:0c:22:3b:ff", SerialToHumanString(positive))

	// A zero serial has no magnitude bytes; OpenSSL prints serial=00.
	assert.Equal(t, "00", SerialToHumanString(big.NewInt(0)))
	assert.Equal(t, "", SerialToHumanString(nil))
}

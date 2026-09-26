// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// All identifiers below are made up.
const (
	testTenantID      = "11223344-5566-7788-99aa-bbccddeeff00"
	testIntuneID      = "0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9"
	testOtherIntuneID = "9f8e7d6c-5b4a-4938-8271-605f4e3d2c1b"
	testEntraDeviceID = "c0ffee00-1234-4abc-8def-0123456789ab"
)

// testTenantBytes is testTenantID in Microsoft byte order: the first three
// fields little-endian, the last two big-endian.
var testTenantBytes = []byte{0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}

func octetString(t *testing.T, b []byte) []byte {
	t.Helper()
	v, err := asn1.Marshal(b)
	require.NoError(t, err)
	return v
}

func rdn(t *testing.T, cn string) asn1.RawValue {
	t.Helper()
	b, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	require.NoError(t, err)
	return asn1.RawValue{FullBytes: b}
}

// fakeCert assembles a certificate structure directly. The signature and key
// are placeholders: the parser reads only issuer, subject and extensions.
// serial lets a test use a negative serial number, which crypto/x509 rejects.
func fakeCert(t *testing.T, issuerCN, subjectCN string, serial []byte, exts ...pkix.Extension) []byte {
	t.Helper()
	empty := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	der, err := asn1.Marshal(rawCertificate{
		TBS: rawTBSCertificate{
			Version:            2,
			SerialNumber:       asn1.RawValue{FullBytes: append([]byte{0x02, byte(len(serial))}, serial...)},
			SignatureAlgorithm: empty,
			Issuer:             rdn(t, issuerCN),
			Validity:           empty,
			Subject:            rdn(t, subjectCN),
			PublicKey:          empty,
			Extensions:         exts,
		},
		SignatureAlgorithm: empty,
		Signature:          asn1.BitString{Bytes: []byte{0}, BitLength: 8},
	})
	require.NoError(t, err)
	return der
}

func tenantExt(t *testing.T, oid asn1.ObjectIdentifier) pkix.Extension {
	return pkix.Extension{Id: oid, Value: octetString(t, testTenantBytes)}
}

func TestGUIDFromMicrosoftBytes(t *testing.T) {
	assert.Equal(t, testTenantID, guidFromMicrosoftBytes(testTenantBytes))
	assert.Equal(t, "", guidFromMicrosoftBytes(testTenantBytes[:15]))
	assert.Equal(t, "", guidFromMicrosoftBytes(make([]byte, 16)), "the all-zero GUID is rejected")
}

func TestGUIDFromExtension(t *testing.T) {
	t.Run("raw 16 bytes", func(t *testing.T) {
		assert.Equal(t, testTenantID, guidFromExtension(testTenantBytes))
	})
	t.Run("octet string", func(t *testing.T) {
		assert.Equal(t, testTenantID, guidFromExtension(octetString(t, testTenantBytes)))
	})
	t.Run("octet string with a non-minimal length", func(t *testing.T) {
		v := append([]byte{0x04, 0x81, 0x10}, testTenantBytes...)
		assert.Equal(t, testTenantID, guidFromExtension(v))
	})
	t.Run("wrong length", func(t *testing.T) {
		assert.Equal(t, "", guidFromExtension(append([]byte{0x04, 0x0f}, testTenantBytes[:15]...)))
		assert.Equal(t, "", guidFromExtension([]byte{0x04, 0x10}))
		assert.Equal(t, "", guidFromExtension([]byte{0x05, 0x00}))
		assert.Equal(t, "", guidFromExtension(nil))
	})
}

func TestNormalizeGUID(t *testing.T) {
	assert.Equal(t, testIntuneID, normalizeGUID(strings.ToUpper(testIntuneID)))
	assert.Equal(t, testIntuneID, normalizeGUID("{"+testIntuneID+"}"))
	assert.Equal(t, "", normalizeGUID("00000000-0000-0000-0000-000000000000"))
	assert.Equal(t, "", normalizeGUID("not-a-guid"))
	assert.Equal(t, "", normalizeGUID("0a1b2c3d4e5f40618273a4b5c6d7e8f9"))
	assert.Equal(t, "", normalizeGUID("0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8fz"))
}

func TestParseDeviceCertificates(t *testing.T) {
	intune := fakeCert(t, intuneMDMIssuerCN, testIntuneID, []byte{0x01}, tenantExt(t, oidIntuneTenantID))
	entra := fakeCert(t, entraDeviceIssuerCN, testEntraDeviceID, []byte{0x02}, tenantExt(t, oidEntraTenantID))

	t.Run("intune and entra certificates", func(t *testing.T) {
		id := ParseDeviceCertificates([][]byte{intune, entra}, "")
		assert.Equal(t, DeviceIdentity{IntuneDeviceID: testIntuneID, EntraTenantID: testTenantID, EntraDeviceID: testEntraDeviceID}, id)
	})

	t.Run("entra only takes the tenant from the entra certificate", func(t *testing.T) {
		id := ParseDeviceCertificates([][]byte{entra}, "")
		assert.Equal(t, DeviceIdentity{EntraTenantID: testTenantID, EntraDeviceID: testEntraDeviceID}, id)
	})

	t.Run("issuer must match exactly", func(t *testing.T) {
		similar := fakeCert(t, "Microsoft Intune Device Management Device CA", testIntuneID, []byte{0x03}, tenantExt(t, oidIntuneTenantID))
		p2p := fakeCert(t, "MS-Organization-P2P-Access [2026]", testEntraDeviceID, []byte{0x04})
		assert.True(t, ParseDeviceCertificates([][]byte{similar, p2p}, "").Empty())
	})

	t.Run("negative serial number is tolerated", func(t *testing.T) {
		neg := fakeCert(t, intuneMDMIssuerCN, testIntuneID, []byte{0xff}, tenantExt(t, oidIntuneTenantID))
		_, err := x509.ParseCertificate(neg)
		require.Error(t, err, "crypto/x509 is expected to reject this certificate")
		assert.Equal(t, testIntuneID, ParseDeviceCertificates([][]byte{neg}, "").IntuneDeviceID)
	})

	t.Run("a certificate created by crypto/x509 parses", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(42),
			Subject:         pkix.Name{CommonName: testIntuneID},
			Issuer:          pkix.Name{CommonName: intuneMDMIssuerCN},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{tenantExt(t, oidIntuneTenantID)},
		}
		parent := &x509.Certificate{Subject: pkix.Name{CommonName: intuneMDMIssuerCN}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
		require.NoError(t, err)
		assert.Equal(t, DeviceIdentity{IntuneDeviceID: testIntuneID, EntraTenantID: testTenantID}, ParseDeviceCertificates([][]byte{der}, ""))
	})

	t.Run("several intune certificates", func(t *testing.T) {
		other := fakeCert(t, intuneMDMIssuerCN, testOtherIntuneID, []byte{0x05}, tenantExt(t, oidIntuneTenantID))
		assert.Empty(t, ParseDeviceCertificates([][]byte{intune, other}, "").IntuneDeviceID, "ambiguous without an enrollment ID")
		assert.Equal(t, testOtherIntuneID, ParseDeviceCertificates([][]byte{intune, other}, strings.ToUpper(testOtherIntuneID)).IntuneDeviceID)
		assert.Equal(t, testIntuneID, ParseDeviceCertificates([][]byte{intune, intune}, "").IntuneDeviceID, "duplicates are one identity")
	})

	t.Run("malformed input is ignored", func(t *testing.T) {
		notGUID := fakeCert(t, intuneMDMIssuerCN, "some-host", []byte{0x06}, tenantExt(t, oidIntuneTenantID))
		badTenant := fakeCert(t, intuneMDMIssuerCN, testIntuneID, []byte{0x07}, pkix.Extension{Id: oidIntuneTenantID, Value: octetString(t, make([]byte, 16))})
		id := ParseDeviceCertificates([][]byte{{0x30, 0x03, 0x02, 0x01}, notGUID}, "")
		assert.True(t, id.Empty())
		id = ParseDeviceCertificates([][]byte{badTenant}, "")
		assert.Equal(t, DeviceIdentity{IntuneDeviceID: testIntuneID}, id, "an all-zero tenant is dropped")
	})

	t.Run("no certificates", func(t *testing.T) {
		assert.True(t, ParseDeviceCertificates(nil, "").Empty())
	})
}

func TestParseIntuneInfo(t *testing.T) {
	intune := base64.StdEncoding.EncodeToString(fakeCert(t, intuneMDMIssuerCN, testIntuneID, []byte{0x01}, tenantExt(t, oidIntuneTenantID)))
	entra := base64.StdEncoding.EncodeToString(fakeCert(t, entraDeviceIssuerCN, testEntraDeviceID, []byte{0x02}))

	t.Run("enrollment and certificates", func(t *testing.T) {
		info, err := ParseIntuneInfo(strings.NewReader(`{"EnrollmentGUID":"x","EntDMID":"` + testIntuneID + `","Certs":["` + intune + `","` + entra + `"]}`))
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, testIntuneID, info.EntDMID)
		assert.Equal(t, DeviceIdentity{IntuneDeviceID: testIntuneID, EntraTenantID: testTenantID, EntraDeviceID: testEntraDeviceID}, info.Identity())
	})

	t.Run("a single certificate emitted as a string", func(t *testing.T) {
		info, err := ParseIntuneInfo(strings.NewReader(`{"EnrollmentGUID":null,"EntDMID":null,"Certs":"` + entra + `"}`))
		require.NoError(t, err)
		assert.Equal(t, "", info.EntDMID)
		assert.Equal(t, testEntraDeviceID, info.Identity().EntraDeviceID)
	})

	t.Run("output without certificates", func(t *testing.T) {
		info, err := ParseIntuneInfo(strings.NewReader(`{"EnrollmentGUID":"x","EntDMID":"` + testIntuneID + `"}`))
		require.NoError(t, err)
		assert.Equal(t, testIntuneID, info.EntDMID)
		assert.True(t, info.Identity().Empty())
	})

	t.Run("undecodable certificate is skipped", func(t *testing.T) {
		info, err := ParseIntuneInfo(strings.NewReader(`{"Certs":["!!not-base64!!","` + entra + `"]}`))
		require.NoError(t, err)
		assert.Len(t, info.Certificates, 1)
	})

	t.Run("empty output", func(t *testing.T) {
		info, err := ParseIntuneInfo(strings.NewReader("  \n"))
		require.NoError(t, err)
		assert.Nil(t, info)
		assert.True(t, info.Identity().Empty())
	})
}

func TestDeviceIdentityLabelsAndPlatformID(t *testing.T) {
	full := DeviceIdentity{IntuneDeviceID: testIntuneID, EntraTenantID: testTenantID, EntraDeviceID: testEntraDeviceID}
	pf := &inventory.Platform{}
	full.SetLabels(pf)
	assert.Equal(t, map[string]string{
		LabelIntuneDeviceID: testIntuneID,
		LabelEntraTenantID:  testTenantID,
		LabelEntraDeviceID:  testEntraDeviceID,
	}, pf.Labels)
	assert.Equal(t, full, DeviceIdentityFromLabels(pf))
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/intune/tenants/"+testTenantID+"/devices/"+testIntuneID, full.IntunePlatformID())

	assert.Equal(t, "", DeviceIdentity{IntuneDeviceID: testIntuneID}.IntunePlatformID(), "a device ID is only meaningful within its tenant")
	assert.Equal(t, "", DeviceIdentity{EntraTenantID: testTenantID}.IntunePlatformID())

	partial := &inventory.Platform{Labels: map[string]string{"other": "x"}}
	DeviceIdentity{EntraDeviceID: testEntraDeviceID}.SetLabels(partial)
	assert.Equal(t, map[string]string{"other": "x", LabelEntraDeviceID: testEntraDeviceID}, partial.Labels)
	assert.True(t, DeviceIdentityFromLabels(nil).Empty())
}

// IdentityDetectable gates the certificate read, so consumers use it to tell
// "not a member" from "never looked". A server answering true would spend a
// round trip per scan; answering false for a workstation would report every
// Entra-joined client as unknown.
func TestIdentityDetectable(t *testing.T) {
	pf := func(productType, title string) *inventory.Platform {
		return &inventory.Platform{
			Title:  title,
			Labels: map[string]string{"windows.mondoo.com/product-type": productType},
		}
	}

	assert.True(t, IdentityDetectable(pf("1", "Windows 11 Enterprise")))
	assert.True(t, IdentityDetectable(pf("3", "Windows 11 Enterprise Multi-Session")))
	assert.False(t, IdentityDetectable(pf("3", "Windows Server 2022 Datacenter")))
	assert.False(t, IdentityDetectable(pf("2", "Windows Server 2022 Datacenter")), "domain controller")
	assert.False(t, IdentityDetectable(pf("", "Windows")), "product type unknown")
	assert.False(t, IdentityDetectable(nil))
}

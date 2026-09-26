// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeProp encodes one serialized store-element property: ID, reserved (1),
// length, data.
func storeProp(id uint32, data []byte) []byte {
	b := make([]byte, 12, 12+len(data))
	binary.LittleEndian.PutUint32(b[0:], id)
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(data)))
	return append(b, data...)
}

func storeBlob(props ...[]byte) []byte {
	var b []byte
	for _, p := range props {
		b = append(b, p...)
	}
	return b
}

func TestCertificateFromStoreBlob(t *testing.T) {
	der := fakeCert(t, intuneMDMIssuerCN, testIntuneID, []byte{0x01}, tenantExt(t, oidIntuneTenantID))

	t.Run("certificate after other properties", func(t *testing.T) {
		blob := storeBlob(
			storeProp(92, []byte{0, 0, 0, 0}),
			storeProp(20, make([]byte, 20)), // key identifier
			storeProp(3, make([]byte, 20)),  // SHA-1 hash
			storeProp(certCertPropID, der),
		)
		got, err := CertificateFromStoreBlob(blob)
		require.NoError(t, err)
		assert.Equal(t, der, got)
		// the certificate feeds the same identity parser as the other paths
		assert.Equal(t, testIntuneID, ParseDeviceCertificates([][]byte{got}, "").IntuneDeviceID)
	})

	t.Run("certificate first", func(t *testing.T) {
		got, err := CertificateFromStoreBlob(storeBlob(storeProp(certCertPropID, der), storeProp(3, make([]byte, 20))))
		require.NoError(t, err)
		assert.Equal(t, der, got)
	})

	t.Run("no certificate property", func(t *testing.T) {
		_, err := CertificateFromStoreBlob(storeBlob(storeProp(3, make([]byte, 20))))
		assert.Error(t, err)
	})

	t.Run("length beyond the blob", func(t *testing.T) {
		blob := storeProp(certCertPropID, der)
		_, err := CertificateFromStoreBlob(blob[:len(blob)-1])
		assert.Error(t, err)
	})

	t.Run("huge length does not overflow", func(t *testing.T) {
		blob := storeProp(certCertPropID, []byte{1})
		binary.LittleEndian.PutUint32(blob[8:], 0xffffffff)
		_, err := CertificateFromStoreBlob(blob)
		assert.Error(t, err)
	})

	t.Run("empty and truncated header", func(t *testing.T) {
		for _, b := range [][]byte{nil, {}, {0x20, 0, 0}} {
			_, err := CertificateFromStoreBlob(b)
			assert.Error(t, err)
		}
	})

	t.Run("empty certificate property", func(t *testing.T) {
		_, err := CertificateFromStoreBlob(storeProp(certCertPropID, nil))
		assert.Error(t, err)
	})
}

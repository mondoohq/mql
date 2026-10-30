// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/binary"
	"errors"

	"github.com/rs/zerolog/log"
)

// certCertPropID is CERT_CERT_PROP_ID: the property of a serialized certificate
// store element that holds the DER-encoded certificate itself.
const certCertPropID = 32

// maxStoreBlobProperties bounds the property walk so a corrupt blob cannot keep
// the parser busy. Real elements carry around ten properties.
const maxStoreBlobProperties = 256

// CertificateFromStoreBlob returns the DER certificate held in the "Blob" value
// that the Windows registry certificate store keeps for each certificate
// (HKLM\SOFTWARE\Microsoft\SystemCertificates\<store>\Certificates\<thumbprint>).
//
// The blob is a serialized store element: a sequence of properties, each a
// little-endian uint32 property ID, a uint32 reserved field, a uint32 length,
// and that many bytes of data. The certificate is the property with ID
// CERT_CERT_PROP_ID (32). Every length is checked against the remaining input,
// so a truncated or corrupt blob yields an error instead of a panic.
func CertificateFromStoreBlob(blob []byte) ([]byte, error) {
	const header = 12
	offset := 0
	for i := 0; i < maxStoreBlobProperties && offset+header <= len(blob); i++ {
		id := binary.LittleEndian.Uint32(blob[offset:])
		if reserved := binary.LittleEndian.Uint32(blob[offset+4:]); reserved != 1 {
			// The format documents this field as 1. Keep parsing, but leave a
			// trace for diagnosing a corrupt or unexpected blob.
			log.Debug().Uint32("property", id).Uint32("reserved", reserved).Msg("certificate store blob: unexpected reserved value")
		}
		length := binary.LittleEndian.Uint32(blob[offset+8:])
		start := offset + header
		if uint64(length) > uint64(len(blob)-start) {
			return nil, errors.New("certificate store blob: property length exceeds blob")
		}
		end := start + int(length)
		if id == certCertPropID {
			if length == 0 {
				return nil, errors.New("certificate store blob: empty certificate property")
			}
			return append([]byte(nil), blob[start:end]...), nil
		}
		offset = end
	}
	return nil, errors.New("certificate store blob: no certificate property")
}

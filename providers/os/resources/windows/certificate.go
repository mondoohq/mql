// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// CertificatesScript enumerates the certificates in the Windows certificate
// stores, for both the machine-wide location and the location belonging to the
// account the scan runs as.
//
// The provider is walked rather than a fixed list of store names, because the
// set of stores is not closed: Windows ships Root, CA, My, TrustedPublisher,
// Disallowed and others, and software adds its own. Enumerating whatever is
// present reports a store nobody expected, which is the interesting case.
//
// The certificate is emitted as base64 DER rather than assembled into PEM
// here. PowerShell's line wrapping differs between versions and would have to
// be undone before parsing; Go wraps it once, consistently.
//
// A store that cannot be opened is skipped rather than failing the walk.
// Several stores under CurrentUser are inaccessible to a service account, and
// a scan that returns nothing because one store was locked is worse than one
// that returns the rest.
//
// ConvertTo-Json is forced to a list with @(): PowerShell serializes a single
// object as an object rather than a one-element array, which would otherwise
// need two parse paths.
const CertificatesScript = `
$ErrorActionPreference = 'SilentlyContinue'
@(foreach ($loc in @('LocalMachine','CurrentUser')) {
  Get-ChildItem -Path ("Cert:\" + $loc) | ForEach-Object {
    $store = $_.Name
    Get-ChildItem -Path ("Cert:\" + $loc + "\" + $store) | ForEach-Object {
      [PSCustomObject]@{
        Location = $loc
        Store = $store
        Thumbprint = $_.Thumbprint
        HasPrivateKey = [bool]$_.HasPrivateKey
        Der = [Convert]::ToBase64String($_.RawData)
      }
    }
  }
}) | ConvertTo-Json -Compress -Depth 3
`

// Certificate is one certificate as it sits in one Windows store.
type Certificate struct {
	// Location is "LocalMachine" or "CurrentUser".
	Location string `json:"Location"`
	// Store is the store name, e.g. "Root", "CA", "My", "Disallowed".
	Store string `json:"Store"`
	// Thumbprint is the SHA-1 hash Windows keys the certificate by, uppercase
	// hex with no separators.
	Thumbprint string `json:"Thumbprint"`
	// HasPrivateKey reports whether the store also holds the matching private
	// key. The key itself is never read.
	HasPrivateKey bool `json:"HasPrivateKey"`
	// Der is the certificate's raw bytes, base64 encoded. See Pem.
	Der string `json:"Der"`
}

// ID is the identity of a store entry.
//
// The same certificate legitimately appears in more than one store and in both
// locations, and it means something different in each: a certificate in Root
// is trusted while the same one in Disallowed is distrusted. So the thumbprint
// alone is not the identity. Keying on it would let the second entry collide
// with the first in the resource cache and silently report the first one's
// store.
func (c Certificate) ID() string {
	return c.Location + "/" + c.Store + "/" + c.Thumbprint
}

// Pem renders the certificate as PEM, empty when the entry carried no bytes or
// bytes that are not valid base64.
//
// Wrapped at 64 characters, which is what RFC 7468 requires of a generator and
// what every parser expects. An unwrapped body is accepted by Go's decoder but
// not by every consumer, so it is not worth emitting.
func (c Certificate) Pem() string {
	raw := strings.TrimSpace(c.Der)
	if raw == "" {
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(raw); err != nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(raw); i += 64 {
		end := min(i+64, len(raw))
		b.WriteString(raw[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}

// ParseCertificates reads the script's output.
//
// An empty document is not an error: a target whose stores could not be opened
// legitimately reports nothing.
func ParseCertificates(r io.Reader) ([]Certificate, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return []Certificate{}, nil
	}

	certs, err := powershell.UnmarshalList[Certificate]([]byte(trimmed))
	if err != nil {
		return nil, errors.New("failed to parse certificates: " + err.Error())
	}
	return certs, nil
}

// RootCertificatesScript reads the machine-wide Root store, which is what
// os.rootCertificates reports on Windows.
//
// Cert:\LocalMachine\Root is the logical store: it already holds the roots
// Windows downloaded into AuthRoot through the Automatic Root Certificates
// Update, as well as those pushed by Group Policy and the enterprise store, so
// AuthRoot is not read on its own. Measured on Windows Server 2022 (build
// 20348): Root held 33 certificates, AuthRoot 20, and all 20 of those were
// among the 33.
//
// Unlike CertificatesScript, a store that cannot be opened stops the script,
// because an empty Root store reads as a host that trusts no CA.
const RootCertificatesScript = `
$ErrorActionPreference = 'Stop'
@(Get-ChildItem -Path 'Cert:\LocalMachine\Root' | ForEach-Object {
  [PSCustomObject]@{
    Location = 'LocalMachine'
    Store = 'Root'
    Thumbprint = $_.Thumbprint
    Der = [Convert]::ToBase64String($_.RawData)
  }
}) | ConvertTo-Json -Compress -Depth 3
`

// PemBundle renders store entries as one PEM bundle, one block per entry.
//
// An entry whose bytes are absent or not valid base64 still gets a block, with
// no body. Dropping it would make the store look complete; a body that is not
// base64 would stop the PEM decoder and lose every entry after it. An empty
// block is decoded and then rejected by the x509 parser, so it is counted as
// unparseable, which is what it is.
func PemBundle(certs []Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		p := c.Pem()
		if p == "" {
			p = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
		}
		b.WriteString(p)
	}
	return b.String()
}

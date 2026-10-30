// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func storeCertificate(location, store, thumbprint string) *mqlWindowsCertificate {
	return &mqlWindowsCertificate{
		Location:   plugin.TValue[string]{Data: location, State: plugin.StateIsSet},
		Store:      plugin.TValue[string]{Data: store, State: plugin.StateIsSet},
		Thumbprint: plugin.TValue[string]{Data: thumbprint, State: plugin.StateIsSet},
	}
}

// Measured: Windows Server 2022 build 20348, IIS 10.0, 2026-10-30. A binding
// made with AddSslCertificate(thumbprint, "My") reads back with store "MY",
// while the store itself is named "My"; the catch-all's store is
// "WebHosting" on both sides. The shop certificate is also in the scanning
// account's CurrentUser\My, which IIS does not serve from, and the Orphan
// site's certificate was deleted from the store after it was bound. The
// CurrentUser entry comes first here, ahead of where the certificate script
// lists it, so that taking the first thumbprint match fails the test.
func TestIisBindingStoreCertificate(t *testing.T) {
	const (
		shop     = "7807EA7178B87920BDED09FE4FA8D024520652FC"
		catchall = "A5027978881039AD17D2BA47C52E9B177688C214"
		ca       = "4DCD0BD98A19B88CCD0B9133A7D512931CA94F1D"
		orphan   = "7304E31A3E9A774A958AAE5BC452AB0D61C69236"
	)
	userShop := storeCertificate("CurrentUser", "My", shop)
	machineShop := storeCertificate("LocalMachine", "My", shop)
	machineCA := storeCertificate("LocalMachine", "My", ca)
	webHosting := storeCertificate("LocalMachine", "WebHosting", catchall)
	certs := []any{userShop, machineCA, machineShop, webHosting}

	assert.Same(t, machineShop, iisBindingStoreCertificate(certs, "MY", shop))
	assert.Same(t, webHosting, iisBindingStoreCertificate(certs, "WebHosting", catchall))
	assert.Nil(t, iisBindingStoreCertificate(certs, "MY", orphan))
	assert.Nil(t, iisBindingStoreCertificate(certs, "MY", catchall), "in WebHosting, not in My")
}

// Synthetic: a binding without a store name and a thumbprint in lowercase,
// as netsh prints it; no target showed these.
func TestIisBindingStoreCertificateDefaultsAndCase(t *testing.T) {
	machineMy := storeCertificate("LocalMachine", "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678")
	certs := []any{machineMy}
	assert.Same(t, machineMy, iisBindingStoreCertificate(certs, "", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"))
	assert.Nil(t, iisBindingStoreCertificate(nil, "My", "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"))
}

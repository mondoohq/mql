// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package connection

import (
	"crypto/x509"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

func newImplicitKerberosClient(serverCert *x509.Certificate) (ldap.GSSAPIClient, func() error, error) {
	// When binding over TLS, supply an RFC 5929 tls-server-end-point channel
	// binding so DCs that enforce LDAP channel binding accept the SASL bind.
	if serverCert != nil {
		gssClient, err := gssapi.NewSSPIClientWithChannelBinding(serverCert)
		if err != nil {
			return nil, nil, fmt.Errorf("windows current-session Kerberos client (channel binding): %w", err)
		}
		return gssClient, gssClient.Close, nil
	}
	gssClient, err := gssapi.NewSSPIClient()
	if err != nil {
		return nil, nil, fmt.Errorf("windows current-session Kerberos client: %w", err)
	}
	return gssClient, gssClient.Close, nil
}

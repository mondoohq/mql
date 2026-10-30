// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package connection

import (
	"crypto/x509"
	"errors"

	"github.com/go-ldap/ldap/v3"
)

func newImplicitKerberosClient(_ *x509.Certificate) (ldap.GSSAPIClient, func() error, error) {
	return nil, nil, errors.New("--kerberos requires either --keytab, --ccache, or both --user and --password (Windows current-session authentication is only available on Windows)")
}

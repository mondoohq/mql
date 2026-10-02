// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Trust stores still ship roots with a negative serial number, EC-ACC on
// Debian 9 and 10 among them. Go 1.23 and later refuse to parse those, which
// silently drops them from the certificates resource behind
// os.rootCertificates, parse.certificates and java.truststores, and from
// certificates read off a TLS handshake.
// A scanner has to see every root the system trusts, so keep the pre-1.23
// parser behavior.
//
//go:debug x509negativeserial=1

package main

import (
	"os"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/provider"
)

func main() {
	plugin.Start(os.Args, provider.Init())
}

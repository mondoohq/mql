// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	DiscoveryAll    = "all"
	DiscoveryAuto   = "auto"
	DiscoveryRealms = "realms"
)

// PlatformIdKeycloakRealm prefixes the identifier of a realm asset. The host is
// part of the identifier because a realm name is only unique within one server,
// and the same names appear on every stage of a deployment.
const PlatformIdKeycloakRealm = "//platformid.api.mondoo.app/runtime/keycloak/host/"

// OptionCACert is the connection option naming the certificate authority to
// trust, either as the PEM itself or as a path to it. A Keycloak server is
// commonly published under a private authority, and trusting it keeps the
// certificate checked.
const OptionCACert = "ca-cert"

func NewKeycloakRealmPlatform(host, realm string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "keycloak", "host", host, "realm", realm},
	}
	PlatformByName("keycloak-realm").Apply(pf)
	return pf
}

// NewKeycloakRealmIdentifier builds the platform ID of a realm asset. Both
// segments are escaped, since a realm name may carry a slash and would
// otherwise produce an identifier that reads as a deeper path.
func NewKeycloakRealmIdentifier(host, realm string) string {
	return PlatformIdKeycloakRealm + url.PathEscape(host) + "/realm/" + url.PathEscape(realm)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// DiscoveryAuto is the default discovery target; it behaves like DiscoveryAll.
	DiscoveryAuto = "auto"
	// DiscoveryAll discovers the server plus every collection as its own asset.
	DiscoveryAll = "all"
	// DiscoveryInstance discovers the server only.
	DiscoveryInstance = "instance"
	// DiscoveryCollections discovers one asset per collection on the server.
	DiscoveryCollections = "collections"
	// DiscoveryNone connects to the server only, without per-collection assets.
	DiscoveryNone = "none"
)

const (
	// OptionHost is the Weaviate hostname or IP.
	OptionHost = "host"
	// OptionPort is the Weaviate REST API port.
	OptionPort = "port"
	// OptionScheme is the connection scheme, http or https.
	OptionScheme = "scheme"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
	// OptionScopedCollection marks a connection as scoped to a single
	// collection, making the asset a weaviate-collection rather than the server.
	OptionScopedCollection = "scoped-collection"
)

var (
	platformIdWeaviateServer     = "//platformid.api.mondoo.app/runtime/weaviate/server/"
	platformIdWeaviateCollection = "/collection/"
)

// NewWeaviateServerPlatform returns the platform for a Weaviate server asset.
func NewWeaviateServerPlatform(serverID string) *inventory.Platform {
	pf := &inventory.Platform{
		Name:                  "weaviate",
		Title:                 "Weaviate",
		Family:                []string{"weaviate"},
		Kind:                  "api",
		Runtime:               "weaviate",
		TechnologyUrlSegments: []string{"db", "weaviate", "server", serverID},
	}
	return pf
}

// NewWeaviateCollectionPlatform returns the platform for a single-collection
// asset discovered under a server.
func NewWeaviateCollectionPlatform(serverID, collection string) *inventory.Platform {
	pf := &inventory.Platform{
		Name:                  "weaviate-collection",
		Title:                 "Weaviate Collection",
		Family:                []string{"weaviate"},
		Kind:                  "api",
		Runtime:               "weaviate",
		TechnologyUrlSegments: []string{"db", "weaviate", "server", serverID, "collection", collection},
	}
	return pf
}

// NewWeaviateServerIdentifier returns the stable platform id for a server.
func NewWeaviateServerIdentifier(serverID string) string {
	return platformIdWeaviateServer + serverID
}

// NewWeaviateCollectionIdentifier returns the stable platform id for a
// collection, qualified by its server so it is unique across servers.
func NewWeaviateCollectionIdentifier(serverID, collection string) string {
	return platformIdWeaviateServer + serverID + platformIdWeaviateCollection + collection
}

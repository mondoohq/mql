// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/weaviate.json so the CLI and generated docs can list
// what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "weaviate", Title: "Weaviate", Family: []string{"weaviate"}, Kind: []string{"api"}, Runtime: []string{"weaviate"}},
	{Name: "weaviate-collection", Title: "Weaviate Collection", Family: []string{"weaviate"}, Kind: []string{"api"}, Runtime: []string{"weaviate"}},
}

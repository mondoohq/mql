// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/redisdb.json so the CLI and generated docs can list what
// the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "redisdb", Title: "Redis or Valkey", Family: []string{"redisdb"}, Kind: []string{"api"}, Runtime: []string{"redisdb"}},
}

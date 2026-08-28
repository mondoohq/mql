// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin/gen"
	"go.mondoo.com/mql/providers/notion/config"
)

func main() {
	gen.CLI(&config.Config)
}

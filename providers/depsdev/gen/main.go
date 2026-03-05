// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin/gen"
	"go.mondoo.com/mql/v13/providers/depsdev/config"
)

func main() {
	gen.CLI(&config.Config)
}

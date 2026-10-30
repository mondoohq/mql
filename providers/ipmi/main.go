// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ipmi/provider"
)

// This is the entry point for the IPMI provider.
//
// To test the provider, start the simulator:
// docker run -d -p 623:623/udp vaporio/ipmi-simulator
//
// Once the simulator is running, you can query it:
// mql shell ipmi ADMIN@0.0.0.0 --password 'ADMIN'
func main() {
	plugin.Start(os.Args, provider.Init())
}

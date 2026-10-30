// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opcua/provider"
)

// This is the entry point for the OPCUA provider.
//
// To test the provider, start the simulator:
// docker run --rm -it -p 50000:50000 -p 8080:8080 --name opcplc mcr.microsoft.com/iotedge/opc-plc:latest --pn=50000 --autoaccept --sph --sn=5 --sr=10 --st=uint --fn=5 --fr=1 --ft=uint --gn=5 --ut --dca
//
// Once the simulator is running, you can query it:
// mql shell opcua --endpoint opc.tcp://localhost:50000
func main() {
	plugin.Start(os.Args, provider.Init())
}

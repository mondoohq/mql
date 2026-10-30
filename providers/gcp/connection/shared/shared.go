// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type ConnectionType string

type GcpConnection interface {
	plugin.Connection
	Name() string
	Type() ConnectionType
	Config() *inventory.Config
	Asset() *inventory.Asset

	// Used to avoid verifying a client with the same options more than once
	Verify() error
	Hash() uint64
}

type Capabilities byte

const (
	Capability_Aws_Ebs Capabilities = 1 << iota
)

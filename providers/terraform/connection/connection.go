// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type ConnectionType string

var _ plugin.Closer = (*Connection)(nil)

// References:
// - https://developer.hashicorp.com/terraform/language/syntax/configuration
// - https://github.com/hashicorp/hcl/blob/main/hclsyntax/spec.md
type Connection struct {
	plugin.Connection
	name            string
	asset           *inventory.Asset
	platformID      string
	assetType       terraformAssetType
	parsed          *hclparse.Parser
	tfVars          map[string]*hcl.Attribute
	modulesManifest *ModuleManifest
	state           *State
	plan            *Plan
	closer          func()

	// cloneRoot is the directory a git connection cloned into. It is empty for
	// connections that read a path the user gave.
	cloneRoot string

	// dialect records whether this configuration is Terraform's or OpenTofu's.
	// For HCL it is detected from the files on disk; for state and plan files,
	// whose JSON representations are identical, it comes from the connector the
	// user invoked.
	dialect Dialect

	// features carries the active MQL feature flags (encoded bitset) for this
	// connection, as sent by the client at Connect time.
	features []byte

	// varCtx memoizes the resolved var.*/local.* evaluation context so it is
	// built only once per connection. Guarded by varCtxOnce.
	varCtx     *hcl.EvalContext
	varCtxOnce sync.Once
}

// SetFeatures stores the active MQL feature-flag bitset on the connection.
func (c *Connection) SetFeatures(features []byte) {
	c.features = features
}

// Features returns the active MQL feature-flag bitset for this connection.
func (c *Connection) Features() []byte {
	return c.features
}

// CloneRoot is the directory a git connection cloned into, or "" when the
// connection reads a path the user gave.
func (c *Connection) CloneRoot() string {
	return c.cloneRoot
}

func (c *Connection) Close() {
	if c.closer != nil {
		c.closer()
	}
}

// Dialect reports whether this configuration belongs to Terraform or OpenTofu.
func (c *Connection) Dialect() Dialect {
	if c.dialect == "" {
		return DialectTerraform
	}
	return c.dialect
}

func (c *Connection) Kind() string {
	return "code"
}

// Runtime tracks the dialect so it agrees with the platform catalog, whose
// opentofu-* entries declare a runtime of "opentofu". Other providers build
// their platform from conn.Runtime(); keeping the two in step here means this
// one can be wired up the same way without silently reporting a runtime that
// contradicts the platform.
func (c *Connection) Runtime() string {
	return string(c.Dialect())
}

func (c *Connection) Asset() *inventory.Asset {
	return c.asset
}

func (c *Connection) Name() string {
	return c.name
}

func (c *Connection) Parser() *hclparse.Parser {
	return c.parsed
}

func (c *Connection) TfVars() map[string]*hcl.Attribute {
	return c.tfVars
}

func (c *Connection) ModulesManifest() *ModuleManifest {
	return c.modulesManifest
}

func (c *Connection) Identifier() (string, error) {
	return c.platformID, nil
}

func (c *Connection) State() (*State, error) {
	return c.state, nil
}

func (c *Connection) Plan() (*Plan, error) {
	return c.plan, nil
}

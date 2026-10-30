// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"os"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// This is designed around https://developer.hashicorp.com/terraform/internals/json-format
// NOTE: it is very similar to the plan file format, but not exactly the same.

type State struct {
	FormatVersion    string       `json:"format_version,omitempty"`
	TerraformVersion string       `json:"terraform_version,omitempty"`
	Values           *StateValues `json:"values,omitempty"`
}

// StateValues is the representation of resolved values
type StateValues struct {
	Outputs    map[string]*Output `json:"outputs,omitempty"`
	RootModule *Module            `json:"root_module,omitempty"`
}

type Output struct {
	Sensitive bool            `json:"sensitive"`
	Value     json.RawMessage `json:"value,omitempty"`
	Type      json.RawMessage `json:"type,omitempty"`
}

// Module is the representation of a module in state. It can be the root module
// or a child module
type Module struct {
	// Address is the absolute module address, omitted for the root module
	Address      string      `json:"address,omitempty"`
	Resources    []*Resource `json:"resources,omitempty"`
	ChildModules []*Module   `json:"child_modules,omitempty"`
}

// WalkChildModules recursively walks the child modules and calls the callback
func (m *Module) WalkChildModules(walker func(m *Module)) {
	for _, child := range m.ChildModules {
		walker(child)
		child.WalkChildModules(walker)
	}
}

// Resource is the representation of a resource in the state
type Resource struct {
	// Address is the absolute resource address
	Address string `json:"address,omitempty"`

	// Mode can be "managed" or "data"
	Mode string `json:"mode,omitempty"`

	Type          string `json:"type,omitempty"`
	Name          string `json:"name,omitempty"`
	ProviderName  string `json:"provider_name"`
	SchemaVersion uint64 `json:"schema_version"`

	// AttributeValues is the JSON representation of the attribute values.
	// The structure depends on the resource type schema
	AttributeValues map[string]any `json:"values,omitempty"`

	// SensitiveValues is similar to AttributeValues, but with all sensitive
	// values replaced with true
	SensitiveValues json.RawMessage `json:"sensitive_values,omitempty"`

	// DependsOn contains a list of the resource's dependencies
	DependsOn []string `json:"depends_on,omitempty"`

	// Tainted is true if the resource is tainted in terraform state
	Tainted bool `json:"tainted,omitempty"`

	// Deposed is set if the resource is deposed in terraform state
	DeposedKey string `json:"deposed_key,omitempty"`
}

func NewStateConnection(id uint32, asset *inventory.Asset) (*Connection, error) {
	cc := asset.Connections[0]

	// NOTE: right now we are only supporting to load either state, plan or hcl files but not at the same time

	var assetType terraformAssetType
	var tfState State

	assetType = statefile
	stateFilePath := cc.Options["path"]
	log.Debug().Str("path", stateFilePath).Msg("load terraform state file")
	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return nil, err
	}
	// Reject encrypted and raw state files up front. Both decode cleanly into an
	// empty State, which would scan as a state file holding zero resources.
	if err := validateStateDocument(data); err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &tfState)
	if err != nil {
		return nil, err
	}

	return &Connection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		assetType:  assetType,

		state: &tfState,
		// The state JSON is identical between the two tools (OpenTofu keeps the
		// `terraform_version` key for compatibility), so there is nothing in the
		// file to detect. The dialect comes from the connector the user invoked.
		dialect: ParseDialect(cc.Options[OptionDialect]),
	}, nil
}

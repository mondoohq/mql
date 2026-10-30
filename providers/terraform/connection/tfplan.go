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

type Plan struct {
	FormatVersion    string `json:"format_version,omitempty"`
	TerraformVersion string `json:"terraform_version,omitempty"`

	PriorState         json.RawMessage    `json:"prior_state,omitempty"`
	Configuration      json.RawMessage    `json:"configuration,omitempty"`
	PlannedValues      plannedStateValues `json:"planned_values"`
	Variables          Variables          `json:"variables,omitempty"`
	ResourceChanges    []ResourceChange   `json:"resource_changes,omitempty"`
	ResourceDrift      []ResourceChange   `json:"resource_drift,omitempty"`
	RelevantAttributes []resourceAttr     `json:"relevant_attributes,omitempty"`
	OutputChanges      map[string]change  `json:"output_changes,omitempty"`
	Applyable          bool               `json:"applyable,omitempty"`
	Errored            bool               `json:"errored,omitempty"`
}

type plannedStateValues struct {
	Outputs    map[string]output `json:"outputs,omitempty"`
	RootModule module            `json:"root_module"`
}

type output struct {
	Sensitive bool            `json:"sensitive"`
	Type      json.RawMessage `json:"type,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

// module is the representation of a module in state. This can be the root
// module or a child module.
type module struct {
	// Resources are sorted in a user-friendly order that is undefined at this
	// time, but consistent.
	Resources []resource `json:"resources,omitempty"`

	// Address is the absolute module address, omitted for the root module
	Address string `json:"address,omitempty"`

	// Each module object can optionally have its own nested "child_modules",
	// recursively describing the full module tree.
	ChildModules []module `json:"child_modules,omitempty"`
}

type resource struct {
	// Address is the absolute resource address
	Address string `json:"address,omitempty"`

	// Mode can be "managed" or "data"
	Mode string `json:"mode,omitempty"`

	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`

	// ProviderName allows the property "type" to be interpreted unambiguously
	// in the unusual situation where a provider offers a resource type whose
	// name does not start with its own name, such as the "googlebeta" provider
	// offering "google_compute_instance".
	ProviderName string `json:"provider_name,omitempty"`

	// SchemaVersion indicates which version of the resource type schema the
	// "values" property conforms to.
	SchemaVersion uint64 `json:"schema_version"`

	// AttributeValues is the JSON representation of the attribute values of the
	// resource, whose structure depends on the resource type schema. Any
	// unknown values are omitted or set to null, making them indistinguishable
	// from absent values.
	AttributeValues map[string]any `json:"values,omitempty"`

	// SensitiveValues is similar to AttributeValues, but with all sensitive
	// values replaced with true, and all non-sensitive leaf values omitted.
	SensitiveValues json.RawMessage `json:"sensitive_values,omitempty"`
}

type Variables map[string]*Variable

type Variable struct {
	Value json.RawMessage `json:"value,omitempty"`
}

// resourceChange is a description of an individual change action that Terraform
// plans to use to move from the prior state to a new state matching the
// configuration.
type ResourceChange struct {
	// Address is the absolute resource address
	Address string `json:"address,omitempty"`

	// PreviousAddress is the absolute address that this resource instance had
	// at the conclusion of a previous run.
	//
	// This will typically be omitted, but will be present if the previous
	// resource instance was subject to a "moved" block that we handled in the
	// process of creating this plan.
	//
	// Note that this behavior diverges from the internal plan data structure,
	// where the previous address is set equal to the current address in the
	// common case, rather than being omitted.
	PreviousAddress string `json:"previous_address,omitempty"`

	// ModuleAddress is the module portion of the above address. Omitted if the
	// instance is in the root module.
	ModuleAddress string `json:"module_address,omitempty"`

	// "managed" or "data"
	Mode string `json:"mode,omitempty"`

	Type         string `json:"type,omitempty"`
	Name         string `json:"name,omitempty"`
	ProviderName string `json:"provider_name,omitempty"`

	// "deposed", if set, indicates that this action applies to a "deposed"
	// object of the given instance rather than to its "current" object. Omitted
	// for changes to the current object.
	Deposed string `json:"deposed,omitempty"`

	// Change describes the change that will be made to this object
	Change change `json:"change"`

	// ActionReason is a keyword representing some optional extra context
	// for why the actions in Change.Actions were chosen.
	//
	// This extra detail is only for display purposes, to help a UI layer
	// present some additional explanation to a human user. The possible
	// values here might grow and change over time, so any consumer of this
	// information should be resilient to encountering unrecognized values
	// and treat them as an unspecified reason.
	ActionReason string `json:"action_reason,omitempty"`
}

// Change is the representation of a proposed change for an object.
type change struct {
	// Actions are the actions that will be taken on the object selected by the
	// properties below. Valid actions values are:
	//    ["no-op"]
	//    ["create"]
	//    ["read"]
	//    ["update"]
	//    ["delete", "create"]
	//    ["create", "delete"]
	//    ["delete"]
	// The two "replace" actions are represented in this way to allow callers to
	// e.g. just scan the list for "delete" to recognize all three situations
	// where the object will be deleted, allowing for any new deletion
	// combinations that might be added in future.
	Actions []string `json:"actions,omitempty"`

	// Before and After are representations of the object value both before and
	// after the action. For ["create"] and ["delete"] actions, either "before"
	// or "after" is unset (respectively). For ["no-op"], the before and after
	// values are identical. The "after" value will be incomplete if there are
	// values within it that won't be known until after apply.
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`

	// AfterUnknown is an object value with similar structure to After, but
	// with all unknown leaf values replaced with true, and all known leaf
	// values omitted.  This can be combined with After to reconstruct a full
	// value after the action, including values which will only be known after
	// apply.
	AfterUnknown json.RawMessage `json:"after_unknown,omitempty"`

	// BeforeSensitive and AfterSensitive are object values with similar
	// structure to Before and After, but with all sensitive leaf values
	// replaced with true, and all non-sensitive leaf values omitted. These
	// objects should be combined with Before and After to prevent accidental
	// display of sensitive values in user interfaces.
	BeforeSensitive json.RawMessage `json:"before_sensitive,omitempty"`
	AfterSensitive  json.RawMessage `json:"after_sensitive,omitempty"`

	// ReplacePaths is an array of arrays representing a set of paths into the
	// object value which resulted in the action being "replace". This will be
	// omitted if the action is not replace, or if no paths caused the
	// replacement (for example, if the resource was tainted). Each path
	// consists of one or more steps, each of which will be a number or a
	// string.
	ReplacePaths json.RawMessage `json:"replace_paths,omitempty"`
}

// resourceAttr contains the address and attribute of an external for the
// RelevantAttributes in the plan.
type resourceAttr struct {
	Resource string          `json:"resource"`
	Attr     json.RawMessage `json:"attribute"`
}

func NewPlanConnection(id uint32, asset *inventory.Asset) (*Connection, error) {
	cc := asset.Connections[0]

	// NOTE: right now we are only supporting to load either state, plan or hcl files but not at the same time

	var assetType terraformAssetType
	var tfPlan Plan

	assetType = planfile
	planfile := cc.Options["path"]
	log.Debug().Str("path", planfile).Msg("load terraform plan file")
	data, err := os.ReadFile(planfile)
	if err != nil {
		return nil, err
	}
	// Reject encrypted and binary plan files up front, so they cannot scan as a
	// plan holding zero resource changes.
	if err := validatePlanDocument(data); err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &tfPlan)
	if err != nil {
		return nil, err
	}

	return &Connection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		assetType:  assetType,

		plan: &tfPlan,
		// As with state files, the plan JSON carries no marker distinguishing
		// the two tools, so the dialect comes from the connector invoked.
		dialect: ParseDialect(cc.Options[OptionDialect]),
	}, nil
}

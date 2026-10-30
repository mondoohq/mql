// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"fmt"
)

// documentKind describes what a JSON document handed to the state or plan
// connection actually is. This provider reads the `terraform show -json`
// representation; every other shape has to be reported rather than parsed into
// an empty result.
type documentKind int

const (
	// documentShowJSON is the `terraform show -json` representation, the only
	// shape this provider can read.
	documentShowJSON documentKind = iota
	// documentEncrypted is an OpenTofu encrypted state or plan envelope.
	documentEncrypted
	// documentNativeState is a raw terraform.tfstate file.
	documentNativeState
	// documentUnrecognized is a JSON object that is neither.
	documentUnrecognized
)

// classifyDocument inspects the top-level keys of a JSON document to determine
// whether it is something this provider can read.
//
// The distinguishing keys:
//   - `encrypted_data` is the OpenTofu encryption envelope.
//   - `format_version` is emitted by every `terraform show -json` run.
//   - `version` (without `format_version`) is the native state file format.
func classifyDocument(data []byte) (documentKind, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return documentUnrecognized, err
	}

	if _, ok := probe["encrypted_data"]; ok {
		return documentEncrypted, nil
	}
	if _, ok := probe["format_version"]; ok {
		return documentShowJSON, nil
	}
	if _, ok := probe["version"]; ok {
		return documentNativeState, nil
	}
	return documentUnrecognized, nil
}

// validateStateDocument returns an actionable error when data is not the
// `terraform show -json` representation of a state file.
func validateStateDocument(data []byte) error {
	kind, err := classifyDocument(data)
	if err != nil {
		return fmt.Errorf("state file is not valid JSON: %w. "+
			"Convert it first with `terraform show -json > state.json`", err)
	}

	switch kind {
	case documentEncrypted:
		return fmt.Errorf("state file is encrypted and cannot be read. " +
			"Decrypt it by running `terraform show -json` (or `tofu show -json`) " +
			"with the encryption key configured, and scan that output")
	case documentNativeState:
		return fmt.Errorf("this is a raw state file, which this provider cannot read. " +
			"Convert it first with `terraform show -json > state.json` and scan that file")
	case documentUnrecognized:
		return fmt.Errorf("state file is missing the `format_version` field, so it is not " +
			"the output of `terraform show -json`. Convert the state file first with " +
			"`terraform show -json > state.json` and scan that file")
	}
	return nil
}

// validatePlanDocument returns an actionable error when data is not the
// `terraform show -json` representation of a plan file.
func validatePlanDocument(data []byte) error {
	kind, err := classifyDocument(data)
	if err != nil {
		return fmt.Errorf("plan file is not valid JSON: %w. "+
			"Binary plan files must be converted first with "+
			"`terraform show -json tfplan > tfplan.json`", err)
	}

	switch kind {
	case documentEncrypted:
		return fmt.Errorf("plan file is encrypted and cannot be read. " +
			"Decrypt it by running `terraform show -json` (or `tofu show -json`) " +
			"with the encryption key configured, and scan that output")
	case documentNativeState, documentUnrecognized:
		return fmt.Errorf("plan file is missing the `format_version` field, so it is not " +
			"the output of `terraform show -json`. Convert the plan file first with " +
			"`terraform show -json tfplan > tfplan.json` and scan that file")
	}
	return nil
}

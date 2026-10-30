// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package composerjson

import "encoding/json"

// composerJson represents a parsed composer.json file.
type composerJson struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Require     map[string]string `json:"require"`
	RequireDev  map[string]string `json:"require-dev"`
	License     composerLicense   `json:"license"`

	// evidence is a list of file paths where the composer.json was found.
	evidence []string `json:"-"`
}

// composerLicense is composer.json's `license`, which is either one license or
// a list of them.
//
// The two forms mean different things and both are legal:
//
//	"license": "MIT"
//	"license": ["LGPL-2.1-only", "GPL-3.0-or-later"]
//
// Composer defines the array as a DISJUNCTIVE license — the package is offered
// under any one of them and the consumer chooses — which is why it is carried
// as a list and rendered with languages.LicenseExpression rather than joined
// here. composer.lock records the same field the same way, so a project and its
// lockfile now answer the licence question identically instead of one of them
// answering it at all.
type composerLicense []string

func (l *composerLicense) UnmarshalJSON(data []byte) error {
	var slice []string
	if err := json.Unmarshal(data, &slice); err == nil {
		*l = slice
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*l = []string{single}
		return nil
	}
	// Any other shape states no license this can read. Leaving it empty keeps
	// the rest of the manifest rather than failing the file over one field.
	return nil
}

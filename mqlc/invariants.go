// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/utils/multierr"
)

// An Invariant is a condition that we expect compiled code to hold.
// This is used to find inconsistencies in our compiler and not for
// meant to be user facing
type Invariant struct {
	ShortName   string
	Description string
	Issues      []string
	// Checker returns true if the invariant holds
	Checker func(*llx.CodeBundle) bool
}

type InvariantFailed struct {
	ShortName string
	Source    string
}

func (e InvariantFailed) Error() string {
	return fmt.Sprintf("Invariant %q failed: Source => \n%+v", e.ShortName, e.Source)
}

type InvariantList []Invariant

func (l InvariantList) Check(cb *llx.CodeBundle) error {
	var err multierr.Errors
	for _, i := range l {
		if !i.Checker(cb) {
			err.Add(InvariantFailed{
				ShortName: i.ShortName,
				Source:    cb.Source,
			})
		}
	}

	return err.Deduplicate()
}

var Invariants = InvariantList{
	{
		ShortName:   "code is not nil",
		Description: `Make sure any compiled code is never just nil`,
		Checker: func(cb *llx.CodeBundle) bool {
			return cb.CodeV2 != nil
		},
	},
	{
		ShortName: "return-entrypoints-singular",
		Description: `
			The return statement indicates that the following expression
			is to be used for the value of the block. Our execution code
			assumes that only 1 value will be reported for the block.

			This means that there can only be 1 entrypoint. Further, it
			also means that num_entrypoints + num_datapoints == 1. The
			restriction on datapoints is just an artifact of the way things
			are written and can be changed, however the entrypoint should
			be the return value. I mention this as a reminder that not all
			parts of this invariant need to be this way forever and can be
			changed
		`,
		Issues: []string{
			"https://gitlab.com/mondoolabs/mondoo/-/issues/716",
		},
		Checker: func(cb *llx.CodeBundle) bool {
			return checkReturnEntrypointsV2(cb.CodeV2)
		},
	},
}

func checkReturnEntrypointsV2(code *llx.CodeV2) bool {
	for i := range code.Blocks {
		block := code.Blocks[i]

		if block.SingleValue {
			if len(code.Entrypoints())+len(code.Datapoints()) != 1 {
				return false
			}
		}
	}

	return true
}

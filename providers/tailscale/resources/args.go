// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
)

// withDefaultArg returns args with name set to value, unless args already
// carries name or value is empty. It returns the map so callers can safely
// pass a nil one, which would otherwise panic on assignment.
func withDefaultArg(args map[string]*llx.RawData, name string, value string) map[string]*llx.RawData {
	if value == "" {
		return args
	}
	if _, ok := args[name]; ok {
		return args
	}
	if args == nil {
		args = map[string]*llx.RawData{}
	}
	args[name] = llx.StringData(value)
	return args
}

// requiredStringArg reads a mandatory string argument out of an init's args.
//
// The value is asserted with comma-ok rather than a bare type assertion: a
// resource argument that resolves to null arrives with a nil Value, and a
// panic inside a provider goroutine takes down the whole scan rather than the
// single query that caused it.
func requiredStringArg(args map[string]*llx.RawData, name string) (string, error) {
	raw, ok := args[name]
	if !ok || raw == nil || raw.Value == nil {
		return "", fmt.Errorf("missing required argument '%s'", name)
	}

	value, ok := raw.Value.(string)
	if !ok {
		return "", fmt.Errorf("wrong type for argument '%s', expected a string", name)
	}
	if value == "" {
		return "", fmt.Errorf("missing required argument '%s'", name)
	}
	return value, nil
}

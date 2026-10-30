// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"runtime"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/execruntime"
)

func (m *mqlMondoo) version() (string, error) {
	return mql.GetVersion(), nil
}

func (m *mqlMondoo) build() (string, error) {
	return mql.GetBuild(), nil
}

func (m *mqlMondoo) arch() (string, error) {
	return runtime.GOOS + "-" + runtime.GOARCH, nil
}

func (m *mqlMondoo) jobEnvironment() (map[string]any, error) {
	// get the local agent runtime information
	ciEnv := execruntime.Detect()

	return map[string]any{
		"id":   ciEnv.Namespace,
		"name": ciEnv.Name,
	}, nil
}

func (m *mqlMondoo) capabilities() ([]any, error) {
	// This method should never be reached.
	// These values are set during the `connect` call.
	return []any{}, nil
}

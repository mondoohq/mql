// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"io"
)

type WindowsEnv struct {
	Key   string
	Value string
}

func ParseEnv(r io.Reader) (map[string]any, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// ConvertTo-Json emits a bare object, not a one-element array, when there
	// is a single variable.
	var env []WindowsEnv
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		var one WindowsEnv
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, err
		}
		env = []WindowsEnv{one}
	} else if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}

	res := map[string]any{}
	for i := range env {
		envVar := env[i]
		res[envVar.Key] = envVar.Value
	}

	return res, nil
}

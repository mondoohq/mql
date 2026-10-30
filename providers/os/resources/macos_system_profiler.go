// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// systemProfilerDataTypeRe matches the names system_profiler prints for
// -listDataTypes (SPPowerDataType, SPUSBHostDataType). The name becomes part
// of a shell command, so nothing else may get through.
var systemProfilerDataTypeRe = regexp.MustCompile(`^SP[A-Za-z0-9]+DataType$`)

func initMacosSystemProfiler(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	raw, ok := args["dataType"]
	if !ok || raw == nil {
		return nil, nil, errors.New("macos.systemProfiler requires a dataType, for example SPPowerDataType")
	}
	dataType, ok := raw.Value.(string)
	if !ok || !systemProfilerDataTypeRe.MatchString(dataType) {
		return nil, nil, fmt.Errorf("macos.systemProfiler: %q is not a system_profiler data type name, for example SPPowerDataType", raw.Value)
	}
	return args, nil, nil
}

func (s *mqlMacosSystemProfiler) id() (string, error) {
	return "macos.systemProfiler/" + s.DataType.Data, nil
}

func (s *mqlMacosSystemProfiler) items() ([]any, error) {
	dataType := s.DataType.Data
	stdout, err := s.run("system_profiler -json " + dataType)
	if err != nil {
		return nil, err
	}
	items, err := parseSystemProfilerItems([]byte(stdout), dataType)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		return items, nil
	}

	// system_profiler answers an unknown data type exactly like a known one
	// with nothing to report: exit 0 and an empty list. Only the list of
	// supported types tells them apart.
	known, err := s.run("system_profiler -listDataTypes")
	if err != nil {
		return nil, err
	}
	if !systemProfilerListsDataType(known, dataType) {
		return nil, fmt.Errorf("system_profiler on this Mac has no data type %s", dataType)
	}
	return items, nil
}

func (s *mqlMacosSystemProfiler) run(command string) (string, error) {
	res, err := NewResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(command),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return "", exit.Error
	} else if exit.Data != 0 {
		return "", fmt.Errorf("%s failed with exit code %d: %s", command, exit.Data, strings.TrimSpace(cmd.GetStderr().Data))
	}
	stdout := cmd.GetStdout()
	return stdout.Data, stdout.Error
}

// parseSystemProfilerItems reads the records out of `system_profiler -json
// <dataType>`, which wraps them in an object keyed by the data type:
//
//	{ "SPPowerDataType" : [ { "_name" : "spbattery_information", ... } ] }
func parseSystemProfilerItems(data []byte, dataType string) ([]any, error) {
	var report map[string]json.RawMessage
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("could not parse system_profiler output for %s: %w", dataType, err)
	}
	raw, ok := report[dataType]
	if !ok {
		return nil, fmt.Errorf("system_profiler output has no %s report", dataType)
	}
	var items []any
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("could not parse system_profiler output for %s: %w", dataType, err)
	}
	if items == nil {
		items = []any{}
	}
	return items, nil
}

// systemProfilerListsDataType reports whether `system_profiler
// -listDataTypes` output names dataType. The output is an "Available
// Datatypes:" header followed by one name per line.
func systemProfilerListsDataType(listOutput string, dataType string) bool {
	for line := range strings.SplitSeq(listOutput, "\n") {
		if strings.TrimSpace(line) == dataType {
			return true
		}
	}
	return false
}

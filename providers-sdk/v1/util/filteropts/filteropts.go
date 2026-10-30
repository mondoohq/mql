// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package filteropts provides shared helpers for parsing the raw --filters
// key/value options that providers use to narrow discovery.
package filteropts

import (
	"strconv"
	"strings"
)

// ParseCsvSliceOpt returns the comma-separated values for the given key as a
// slice. Empty keys or values are skipped, and a non-nil empty slice is
// returned when there is nothing to parse.
//
// Example:
//
//	key  = "regions"
//	opts = {"regions": "us-east-1,us-west-2"}
//	returns []string{"us-east-1", "us-west-2"}
func ParseCsvSliceOpt(opts map[string]string, key string) []string {
	res := []string{}
	for k, v := range opts {
		if k == "" || v == "" {
			continue
		}
		if k == key {
			res = append(res, strings.Split(v, ",")...)
		}
	}
	return res
}

// ParseBoolOpt returns the boolean value for the given key. If the key is
// missing or its value cannot be parsed as a boolean, defaultVal is returned.
//
// Example:
//
//	key        = "propagate-project-labels"
//	opts       = {"propagate-project-labels": "true"}
//	returns true
func ParseBoolOpt(opts map[string]string, key string, defaultVal bool) bool {
	if v, ok := opts[key]; ok {
		if parsed, err := strconv.ParseBool(v); err == nil {
			return parsed
		}
	}
	return defaultVal
}

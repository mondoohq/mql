// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousecloud/connection"
)

func (r *mqlClickhousecloud) id() (string, error) {
	return "clickhousecloud", nil
}

func clickhousecloudConn(runtime *plugin.Runtime) *connection.ClickhousecloudConnection {
	return runtime.Connection.(*connection.ClickhousecloudConnection)
}

// toAnySlice converts a string slice to []any for llx.
func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// timeData parses an RFC3339 timestamp into llx time data, or a set-null value
// when the string is empty or unparseable.
func timeData(s string) *llx.RawData {
	if s == "" {
		return llx.NilData
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return llx.NilData
	}
	return llx.TimeData(t)
}

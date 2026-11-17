// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers/yugabyte/connection"
)

// Synthetic: a flag counts as on only when every tablet server has it on.
func TestFlagTrueOnAll(t *testing.T) {
	on := map[string]string{"ysql_enable_auth": "true"}
	off := map[string]string{"ysql_enable_auth": "false"}

	if got, err := flagTrueOnAll([]map[string]string{on, on}, "ysql_enable_auth"); err != nil || !got {
		t.Errorf("all on = %v, %v", got, err)
	}
	if got, err := flagTrueOnAll([]map[string]string{on, off}, "ysql_enable_auth"); err != nil || got {
		t.Errorf("one off = %v, %v", got, err)
	}
	if _, err := flagTrueOnAll(nil, "ysql_enable_auth"); err == nil {
		t.Error("no tablet servers answered")
	}
	if _, err := flagTrueOnAll([]map[string]string{on, {}}, "ysql_enable_auth"); err == nil {
		t.Error("a server without the flag answered")
	}
	if _, err := flagTrueOnAll([]map[string]string{{"ysql_enable_auth": "***"}}, "ysql_enable_auth"); err == nil {
		t.Error("a masked value answered")
	}
}

// Synthetic: absent lists become empty lists, not nulls.
func TestHealthDict(t *testing.T) {
	d := healthDict(connection.Health{DeadNodes: []string{"a"}, MostRecentUptime: 5})
	if len(d["deadNodes"].([]any)) != 1 || len(d["leaderlessTablets"].([]any)) != 0 || d["mostRecentUptime"].(int64) != 5 {
		t.Errorf("got %v", d)
	}
}

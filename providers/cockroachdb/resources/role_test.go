// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestParseSessionSettings(t *testing.T) {
	got := parseSessionSettings([]string{"idle_in_session_timeout=15m", "search_path=public,app", "broken"})
	want := map[string]string{"idle_in_session_timeout": "15m", "search_path": "public,app"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSessionSettings = %v, want %v", got, want)
	}
}

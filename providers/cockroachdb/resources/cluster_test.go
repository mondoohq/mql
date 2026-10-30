// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestIsInsecureURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"postgresql://root@127.0.0.1:26257/defaultdb?sslmode=disable":                                                      true,
		"postgresql://root@127.0.0.1:26257/defaultdb?sslcert=%2Fcerts%2Fclient.root.crt&sslmode=verify-full&sslrootcert=x": false,
		"postgresql://root@127.0.0.1:26257/defaultdb":                                                                      false,
		"::not a url": false,
	} {
		if got := isInsecureURL(raw); got != want {
			t.Errorf("isInsecureURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestFormatClusterVersion(t *testing.T) {
	for raw, want := range map[string]string{
		`{"internal": 0, "major": 25, "minor": 4, "patch": 0}`:  "25.4",
		`{"internal": 12, "major": 25, "minor": 3, "patch": 0}`: "25.3-12",
	} {
		got, err := formatClusterVersion([]byte(raw))
		if err != nil || got != want {
			t.Errorf("formatClusterVersion(%s) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := formatClusterVersion([]byte("not json")); err == nil {
		t.Error("formatClusterVersion(not json) did not fail")
	}
}

func TestSettingType(t *testing.T) {
	for code, want := range map[string]string{
		"b": "bool", "i": "int", "f": "float", "s": "string", "e": "enum",
		"d": "duration", "z": "byteSize", "m": "version", "p": "p",
	} {
		if got := settingType(code); got != want {
			t.Errorf("settingType(%q) = %q, want %q", code, got, want)
		}
	}
}

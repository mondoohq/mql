// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCommitTitle_ShortListsProviders(t *testing.T) {
	confs := updateConfs{
		{name: "aws", version: "13.53.1"},
		{name: "azure", version: "13.34.1"},
	}
	got := confs.commitTitle()
	want := "🎉 aws-13.53.1, azure-13.34.1"
	if got != want {
		t.Fatalf("commitTitle() = %q, want %q", got, want)
	}
}

func TestCommitTitle_LongFallsBackToCount(t *testing.T) {
	// Build enough providers that the enumerated title exceeds GitHub's limit.
	var confs updateConfs
	for i := 0; i < 72; i++ {
		confs = append(confs, &providerConf{
			name:    fmt.Sprintf("provider%02d", i),
			version: "13.0.1",
		})
	}

	got := confs.commitTitle()
	if utf8.RuneCountInString(got) > maxTitleLen {
		t.Fatalf("commitTitle() length = %d chars, exceeds limit of %d: %q",
			utf8.RuneCountInString(got), maxTitleLen, got)
	}
	want := "🎉 Release 72 providers"
	if got != want {
		t.Fatalf("commitTitle() = %q, want %q", got, want)
	}
}

const testConfig = `var Config = plugin.Provider{
	Name:    "os",
	ID:      "go.mondoo.com/mql/providers/os",
	Version: "14.9.0",
	Requires: []plugin.ProviderDep{
		{ID: "go.mondoo.com/mql/providers/core", Name: "core", MinVersion: "13.0.0"},
		{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.0.0"},
	},
}`

func TestGetVersion_IgnoresMinVersion(t *testing.T) {
	// MinVersion listed before Version must not be picked up either.
	content := `Requires: []plugin.ProviderDep{{Name: "core", MinVersion: "13.0.0"}},
	Version: "14.9.0",`
	if got := getVersion(content); got != "14.9.0" {
		t.Fatalf("getVersion() = %q, want %q", got, "14.9.0")
	}
}

func TestSetVersion_KeepsMinVersion(t *testing.T) {
	got := setVersion(testConfig, "14.9.1")
	want := strings.Replace(testConfig, `Version: "14.9.0"`, `Version: "14.9.1"`, 1)
	if got != want {
		t.Fatalf("setVersion() =\n%s\nwant\n%s", got, want)
	}
	if n := strings.Count(got, `MinVersion: "13.0.0"`); n != 2 {
		t.Fatalf("setVersion() changed dependency MinVersions, %d of 2 left:\n%s", n, got)
	}
}

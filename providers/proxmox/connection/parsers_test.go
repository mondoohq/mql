// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"
)

// Inputs mirror real `apt list --upgradable` output: every line is a pending
// upgrade, the version column is the candidate (new) version, and the bracket
// carries the installed version as `[upgradable from: X]`.

func TestParseAptOutput_Upgradable(t *testing.T) {
	input := `Listing...
curl/jammy-updates,jammy-security 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.14]
libc6/jammy-updates 2.35-0ubuntu3.6 amd64 [upgradable from: 2.35-0ubuntu3.5]
`
	updates := ParseAptOutput(input)
	if len(updates) != 2 {
		t.Fatalf("expected 2 upgradable packages, got %d", len(updates))
	}

	curl := updates[0]
	if curl.Name != "curl" {
		t.Errorf("expected 'curl', got %q", curl.Name)
	}
	if !curl.Upgradable {
		t.Error("curl should be upgradable")
	}
	if curl.NewVersion != "7.81.0-1ubuntu1.16" {
		t.Errorf("expected new version '7.81.0-1ubuntu1.16', got %q", curl.NewVersion)
	}
	if curl.InstalledVersion != "7.81.0-1ubuntu1.14" {
		t.Errorf("expected installed version '7.81.0-1ubuntu1.14', got %q", curl.InstalledVersion)
	}
}

func TestParseAptOutput_SecuritySource(t *testing.T) {
	input := `Listing...
openssl/jammy-security 3.0.2-0ubuntu1.12 amd64 [upgradable from: 3.0.2-0ubuntu1.10]
`
	updates := ParseAptOutput(input)
	if len(updates) != 1 {
		t.Fatalf("expected 1 package, got %d", len(updates))
	}
	if updates[0].Severity != "security" {
		t.Errorf("expected severity 'security', got %q", updates[0].Severity)
	}
}

// A system with no pending upgrades prints only the "Listing..." header —
// which must yield zero updates, not a phantom row.
func TestParseAptOutput_NoUpgrades(t *testing.T) {
	updates := ParseAptOutput("Listing...\n")
	if len(updates) != 0 {
		t.Errorf("expected 0 packages when nothing is upgradable, got %d", len(updates))
	}
}

func TestParseAptOutput_Empty(t *testing.T) {
	updates := ParseAptOutput("")
	if len(updates) != 0 {
		t.Errorf("expected 0 packages for empty input, got %d", len(updates))
	}
}

func TestParseDnfOutput_Updates(t *testing.T) {
	input := `curl.x86_64                     7.76.1-26.el9_3.3       baseos
openssl.x86_64                  1:3.0.7-25.el9_3       baseos-security
vim-minimal.x86_64              2:8.2.2637-20.el9_1     appstream
`
	updates := ParseDnfOutput(input)
	if len(updates) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(updates))
	}

	for _, u := range updates {
		if !u.Upgradable {
			t.Errorf("package %s should be upgradable", u.Name)
		}
		if u.NewVersion == "" {
			t.Errorf("package %s should have a new version", u.Name)
		}
	}

	if updates[0].Name != "curl.x86_64" {
		t.Errorf("expected 'curl.x86_64', got %q", updates[0].Name)
	}
	if updates[1].Severity != "security" {
		t.Errorf("expected severity 'security' for openssl, got %q", updates[1].Severity)
	}
}

func TestParseDnfOutput_Empty(t *testing.T) {
	updates := ParseDnfOutput("")
	if len(updates) != 0 {
		t.Errorf("expected 0 packages for empty input, got %d", len(updates))
	}
}

func TestParseDnfOutput_SkipsMetaLines(t *testing.T) {
	input := `Last metadata expiration check: 1:23:45 ago on Mon 01 Jan 2024
curl.x86_64                     7.76.1-26.el9_3.3       baseos

Obsoleting Packages
old-pkg.x86_64                  1.0-1.el9               baseos
`
	updates := ParseDnfOutput(input)
	if len(updates) != 1 {
		t.Fatalf("expected 1 package (skipping meta lines), got %d", len(updates))
	}
	if updates[0].Name != "curl.x86_64" {
		t.Errorf("expected 'curl.x86_64', got %q", updates[0].Name)
	}
}

func TestParseWindowsHotfixes_Array(t *testing.T) {
	input := `[{"HotFixID":"KB5034441","Description":"Security Update"},{"HotFixID":"KB5034467","Description":"Update"}]`
	updates := ParseWindowsHotfixes(input)
	if len(updates) != 2 {
		t.Fatalf("expected 2 hotfixes, got %d", len(updates))
	}

	if updates[0].Name != "KB5034441" {
		t.Errorf("expected 'KB5034441', got %q", updates[0].Name)
	}
	if updates[0].Severity != "security" {
		t.Errorf("expected severity 'security', got %q", updates[0].Severity)
	}
	if updates[0].Upgradable {
		t.Error("hotfix should not be upgradable")
	}

	if updates[1].Severity != "enhancement" {
		t.Errorf("expected severity 'enhancement' for non-security update, got %q", updates[1].Severity)
	}
}

func TestParseWindowsHotfixes_SingleObject(t *testing.T) {
	// ConvertTo-Json returns a single object when there's only one hotfix
	input := `{"HotFixID":"KB5034441","Description":"Security Update"}`
	updates := ParseWindowsHotfixes(input)
	if len(updates) != 1 {
		t.Fatalf("expected 1 hotfix, got %d", len(updates))
	}
	if updates[0].Name != "KB5034441" {
		t.Errorf("expected 'KB5034441', got %q", updates[0].Name)
	}
}

func TestParseWindowsHotfixes_Empty(t *testing.T) {
	updates := ParseWindowsHotfixes("")
	if len(updates) != 0 {
		t.Errorf("expected 0 hotfixes for empty input, got %d", len(updates))
	}
}

func TestParseWindowsHotfixes_InvalidJSON(t *testing.T) {
	updates := ParseWindowsHotfixes("not json at all")
	if len(updates) != 0 {
		t.Errorf("expected 0 hotfixes for invalid JSON, got %d", len(updates))
	}
}

func TestParseWindowsHotfixes_SkipsEmptyHotFixID(t *testing.T) {
	input := `[{"HotFixID":"KB5034441","Description":"Update"},{"HotFixID":"","Description":"Update"}]`
	updates := ParseWindowsHotfixes(input)
	if len(updates) != 1 {
		t.Fatalf("expected 1 hotfix (skipping empty ID), got %d", len(updates))
	}
}

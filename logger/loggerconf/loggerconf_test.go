// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package loggerconf

import (
	"os"
	"path/filepath"
	"testing"

	"go.mondoo.com/mql/logger"
)

func clearEnvLevel(t *testing.T) {
	t.Helper()
	// ensure env vars don't override the configured level during the test
	t.Setenv("DEBUG", "")
	t.Setenv("TRACE", "")
	t.Setenv("MONDOO_LOG_LEVEL", "")
}

func TestConfigure_Level(t *testing.T) {
	clearEnvLevel(t)
	if err := Configure(&LoggingConfig{Writer: "cli", Level: "warn"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "warn" {
		t.Errorf("expected level warn, got %q", got)
	}
}

func TestConfigure_EmptyWriterDefaultsToCli(t *testing.T) {
	clearEnvLevel(t)
	if err := Configure(&LoggingConfig{Level: "error"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "error" {
		t.Errorf("expected level error, got %q", got)
	}
}

func TestConfigure_Nil(t *testing.T) {
	clearEnvLevel(t)
	if err := Configure(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "info" {
		t.Errorf("expected level info, got %q", got)
	}
}

func TestConfigure_EnvOverridesLevel(t *testing.T) {
	t.Setenv("DEBUG", "true")
	t.Setenv("TRACE", "")
	if err := Configure(&LoggingConfig{Writer: "cli", Level: "error"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "debug" {
		t.Errorf("expected env to force debug, got %q", got)
	}
}

func TestConfigure_MondooLogLevelOverridesConfig(t *testing.T) {
	// the cnspec-runner relies on MONDOO_LOG_LEVEL (set per job) overriding the
	// configured level; make sure that keeps working through Configure.
	t.Setenv("DEBUG", "")
	t.Setenv("TRACE", "")
	t.Setenv("MONDOO_LOG_LEVEL", "trace")
	if err := Configure(&LoggingConfig{Writer: "cli", Level: "error"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "trace" {
		t.Errorf("expected MONDOO_LOG_LEVEL to force trace, got %q", got)
	}
}

func TestConfigure_MondooLogLevelOverridesNilConfig(t *testing.T) {
	t.Setenv("DEBUG", "")
	t.Setenv("TRACE", "")
	t.Setenv("MONDOO_LOG_LEVEL", "warn")
	if err := Configure(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "warn" {
		t.Errorf("expected MONDOO_LOG_LEVEL to force warn, got %q", got)
	}
}

func TestConfigure_UnknownWriter(t *testing.T) {
	clearEnvLevel(t)
	if err := Configure(&LoggingConfig{Writer: "bogus"}); err == nil {
		t.Fatal("expected an error for an unknown writer")
	}
}

func TestConfigure_StackdriverRequiresOptions(t *testing.T) {
	clearEnvLevel(t)
	if err := Configure(&LoggingConfig{Writer: "stackdriver"}); err == nil {
		t.Fatal("expected an error when project-id is missing")
	}
	if err := Configure(&LoggingConfig{Writer: "stackdriver", Options: map[string]string{"project-id": "p"}}); err == nil {
		t.Fatal("expected an error when log-id is missing")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "logging.yaml")
	if err := os.WriteFile(yamlPath, []byte("writer: cli\nlevel: debug\noptions:\n  format: json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Writer != "cli" || opts.Level != "debug" || opts.Options["format"] != "json" {
		t.Errorf("unexpected options parsed from yaml: %+v", opts)
	}

	jsonPath := filepath.Join(dir, "logging.json")
	if err := os.WriteFile(jsonPath, []byte(`{"writer":"cli","level":"trace"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err = Load(jsonPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Writer != "cli" || opts.Level != "trace" {
		t.Errorf("unexpected options parsed from json: %+v", opts)
	}

	if _, err := Load(filepath.Join(dir, "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoad_Labels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logging.yaml")
	yaml := "writer: cli\noptions:\n  format: gcp-json\nlabels:\n  project_id: scanned-proj\n  scan_type: gcp\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	opts, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Labels["project_id"] != "scanned-proj" || opts.Labels["scan_type"] != "gcp" {
		t.Errorf("unexpected labels parsed from yaml: %+v", opts.Labels)
	}
}

func TestConfigure_GcpJSONWithLabels(t *testing.T) {
	clearEnvLevel(t)
	err := Configure(&LoggingConfig{
		Writer:  "cli",
		Level:   "info",
		Options: map[string]string{"format": "gcp-json"},
		Labels:  map[string]string{"project_id": "scanned-proj"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := logger.GetLevel(); got != "info" {
		t.Errorf("expected level info, got %q", got)
	}
}

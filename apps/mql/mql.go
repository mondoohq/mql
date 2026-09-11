// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"strings"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/apps/mql/cmd"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/selfupdate"
	"go.mondoo.com/mql/metrics"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"

	// Link in all vault backends (AWS, GCP, HashiCorp, keyring) so they
	// self-register with the vault registry. The in-memory backend is always
	// available via the SDK.
	_ "go.mondoo.com/mql/vault/register"
)

func main() {
	defer health.ReportPanic("mql", mql.Version, mql.Build)

	// Before anything resolves a channel. With update_channel unset, a
	// pre-release build follows the pre-release track rather than pulling
	// stable providers built against a different schema.
	config.SetRunningVersion(mql.GetVersion())

	// Clean up leftover .old binary from a previous in-place update (Windows).
	selfupdate.CleanupOldBinary()

	// Normalize --auto-update flag to handle both "--auto-update false" and "--auto-update=false" formats
	// This must happen before any argument parsing (self-update check or cobra)
	normalizeAutoUpdateFlag()

	// Check for self-update before anything else
	if run, localOnly := selfUpdateMode(); run {
		manifest := selfupdate.ChannelManifest(config.GetUpdateChannel())
		releaseURL := selfupdate.DefaultReleasesURL + "/mql/" + manifest
		if updatesURL := config.GetUpdatesURL(); updatesURL != "" {
			releaseURL = strings.TrimSuffix(updatesURL, "/") + "/mql/" + manifest
		}
		cfg := selfupdate.Config{
			Enabled:         true,
			RefreshInterval: selfupdate.DefaultRefreshInterval,
			ReleaseURL:      releaseURL,
			BinaryName:      "mql",
			CurrentVersion:  mql.GetVersion(),
		}
		// "version" does only the local switch (no network) so it stays fast while
		// still reporting the version that other commands transparently exec into.
		check := selfupdate.CheckAndUpdate
		if localOnly {
			check = selfupdate.CheckLocalAndUpdate
		}
		if updated, err := check(cfg); err != nil {
			// Log warning but don't block - only show in debug mode
			if os.Getenv("DEBUG") != "" {
				os.Stderr.WriteString("self-update check failed: " + err.Error() + "\n")
			}
		} else if updated {
			// On Windows, the process was replaced by spawning a new one
			// On Unix, ExecUpdatedBinary doesn't return on success
			return
		}
	}

	go metrics.Start()
	cmd.Execute()
}

// normalizeAutoUpdateFlag converts space-separated --auto-update flags to the = format.
// This ensures consistent handling across self-update checks, provider updates, and cobra.
// For example: "--auto-update false" becomes "--auto-update=false"
func normalizeAutoUpdateFlag() {
	newArgs := make([]string, 0, len(os.Args))
	skipNext := false

	for i, arg := range os.Args {
		if skipNext {
			skipNext = false
			continue
		}

		// Handle --auto-update VALUE format (space-separated)
		if arg == "--auto-update" && i+1 < len(os.Args) {
			next := os.Args[i+1]
			// Check if next arg looks like a bool value
			if next == "false" || next == "0" || next == "true" || next == "1" {
				// Convert to = format and skip the next arg
				newArgs = append(newArgs, "--auto-update="+next)
				skipNext = true
				continue
			}
		}

		newArgs = append(newArgs, arg)
	}

	os.Args = newArgs
}

// selfUpdateMode decides whether a self-update should be attempted, and whether
// it must stay local-only (no network). It uses viper config and CLI flags to
// determine if auto-update is enabled.
//
// The "version" command runs a local-only check: it must not pay a network
// round-trip, but it still has to switch to a newer already-staged binary so it
// reports the same version every other command transparently execs into (see
// issue #7751). "help"/"-h" skip self-update entirely.
//
// Note: normalizeAutoUpdateFlag() must be called before this function to convert
// space-separated flags (--auto-update false) to the = format (--auto-update=false).
func selfUpdateMode() (run, localOnly bool) {
	// Skip if disabled via environment variable
	// This also prevents infinite loops after an update (the updated process
	// is spawned with MONDOO_AUTO_UPDATE=false)
	if val := os.Getenv(selfupdate.EnvAutoUpdate); val == "false" || val == "0" {
		return false, false
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "--help", "-h":
			// Help output never represents "the version I'm running" and should
			// be instant, so skip self-update entirely.
			return false, false
		case "version", "--version":
			// Report the effective version without a network round-trip.
			localOnly = true
		}
	}

	// Initialize viper to read config files (same as detectConnectorName in cli/providers)
	config.InitViperConfig()

	// Check if the AutoUpdateEngine feature flag is enabled
	if !config.GetFeatures().IsActive(mql.AutoUpdateEngine) {
		return false, false
	}

	// Get auto_update setting from config (defaults to true if not set)
	autoUpdate := config.GetAutoUpdate()

	// Check for --auto-update=VALUE flag (already normalized from space-separated format)
	for _, arg := range os.Args {
		if arg == "--auto-update=false" || arg == "--auto-update=0" {
			return false, false
		}
		if arg == "--auto-update=true" || arg == "--auto-update=1" {
			return true, localOnly
		}
	}

	return autoUpdate, localOnly
}

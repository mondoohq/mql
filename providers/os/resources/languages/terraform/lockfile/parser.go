// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lockfile

// terraformLock represents a parsed .terraform.lock.hcl file.
type terraformLock struct {
	// Providers is the list of locked provider entries.
	Providers []providerEntry

	// evidence is a list of file paths where the lock file was found.
	evidence []string
}

// providerEntry represents a single provider block in the lock file.
type providerEntry struct {
	// Source is the full provider source address as written, registry host
	// included when the file names one (e.g.
	// "registry.terraform.io/hashicorp/aws").
	Source string
	// Version is the resolved provider version.
	Version string
	// Constraints is the version constraint the configuration asked for (e.g.
	// "~> 5.0"). Terraform omits the line entirely when required_providers
	// declares a source with no version, so an empty value means "not
	// recorded", never "unconstrained".
	Constraints string
	// ZipHashes are the "zh:" entries: the SHA-256 of each official release
	// zip, one per target platform, hex encoded.
	ZipHashes []string
	// DirHashes are the "h1:" entries: Terraform's own directory hash, base64
	// encoded over a manifest of the extracted files. Retained because it is
	// the hash Terraform actually verifies, but deliberately not reported as a
	// package checksum — it is neither a plain SHA-256 nor taken over the same
	// bytes as a zh: entry, so filing both under one algorithm would state two
	// incomparable digests for one component.
	DirHashes []string
}

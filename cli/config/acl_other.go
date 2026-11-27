// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package config

// restrictAccess is a no-op outside Windows, where file modes (see
// PrivateFileMode) govern access to the config.
func restrictAccess(path string) error { return nil }

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resourceclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEsxcliNamespaceUnavailableRegex(t *testing.T) {
	// Errors from hosts that lack a namespace because the feature is too new
	// (keypersistence pre-7.0u2, tls pre-8.0) or the hardware lacks a TPM should
	// be treated as "not configured", not propagated.
	unsupported := []string{
		"Error: Not supported on this host",
		"Unknown command or namespace system security keypersistence get",
		"Unknown command or namespace system tls server get",
		"Invalid namespace: keypersistence",
		"This host does not have a TPM",
	}
	for _, msg := range unsupported {
		assert.True(t, esxcliNamespaceUnavailableRegex.MatchString(msg), "expected match: %q", msg)
	}

	// Genuine failures (auth, connectivity) must surface as real errors.
	realErrors := []string{
		"connection refused",
		"401 Unauthorized",
		"context deadline exceeded",
	}
	for _, msg := range realErrors {
		assert.False(t, esxcliNamespaceUnavailableRegex.MatchString(msg), "expected no match: %q", msg)
	}
}

func TestBuildAdvancedSetting(t *testing.T) {
	// esxcli emits BOTH the int and string variant of the value/default
	// columns for every setting; the inapplicable one is present but empty.
	// buildAdvancedSetting must select the pair named by Type rather than let
	// map-iteration order pick a winner.
	t.Run("integer setting ignores the empty string columns", func(t *testing.T) {
		val := map[string][]string{
			"Path":               {"/DataMover/HardwareAcceleratedMove"},
			"Description":        {"Enable hardware accelerated VMFS data movement"},
			"Type":               {"integer"},
			"DefaultIntValue":    {"1"},
			"DefaultStringValue": {""},
			"IntValue":           {"0"},
			"StringValue":        {""},
			"MaxValue":           {"1"},
			"MinValue":           {"0"},
		}
		// Run many times: map iteration order is randomized, so the old
		// dual-write code would flip Default/Value between iterations.
		for i := range 200 {
			s := buildAdvancedSetting(val)
			assert.Equal(t, "1", s.Default, "iteration %d", i)
			assert.Equal(t, "0", s.Value, "iteration %d", i)
			assert.Equal(t, "DataMover.HardwareAcceleratedMove", s.Key)
			assert.Equal(t, "/DataMover/HardwareAcceleratedMove", s.Path)
			assert.Equal(t, "Enable hardware accelerated VMFS data movement", s.Description)
			assert.True(t, s.Overridden(), "1 != 0 is an override")
		}
	})

	t.Run("string setting reads the string columns", func(t *testing.T) {
		val := map[string][]string{
			"Path":               {"/Syslog/global/logHost"},
			"Type":               {"string"},
			"DefaultIntValue":    {"0"},
			"DefaultStringValue": {""},
			"IntValue":           {"0"},
			"StringValue":        {"tcp://loghost:514"},
		}
		for i := range 200 {
			s := buildAdvancedSetting(val)
			assert.Equal(t, "", s.Default, "iteration %d", i)
			assert.Equal(t, "tcp://loghost:514", s.Value, "iteration %d", i)
			assert.Equal(t, "Syslog.global.logHost", s.Key)
			assert.True(t, s.Overridden(), "empty default != set value")
		}
	})

	t.Run("matching int default and value is not an override", func(t *testing.T) {
		val := map[string][]string{
			"Path":            {"/Net/BlockGuestBPDU"},
			"Type":            {"integer"},
			"DefaultIntValue": {"0"},
			"IntValue":        {"0"},
		}
		s := buildAdvancedSetting(val)
		assert.Equal(t, "0", s.Default)
		assert.Equal(t, "0", s.Value)
		assert.False(t, s.Overridden())
	})

	t.Run("absent or multi-valued columns yield empty", func(t *testing.T) {
		s := buildAdvancedSetting(map[string][]string{
			"Type":            {"integer"},
			"DefaultIntValue": {"1", "2"}, // malformed: not len-1
		})
		assert.Equal(t, "", s.Default)
		assert.Equal(t, "", s.Value)
		assert.Equal(t, "", s.Path)
	})
}

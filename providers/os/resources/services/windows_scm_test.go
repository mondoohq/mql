// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/mock"

	"github.com/stretchr/testify/assert"
)

func TestScmServiceState(t *testing.T) {
	tests := []struct {
		state uint32
		want  State
	}{
		{0, ServiceUnknown},
		{1, ServiceStopped},
		{2, ServiceStartPending},
		{3, ServiceStopPending},
		{4, ServiceRunning},
		{5, ServiceContinuePending},
		{6, ServicePausePending},
		{7, ServicePaused},
		{8, ServiceUnknown},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("state %d", tc.state), func(t *testing.T) {
			assert.Equal(t, tc.want, scmServiceState(tc.state))
		})
	}
}

func TestScmStartTypeEnabled(t *testing.T) {
	tests := []struct {
		name      string
		startType uint32
		want      bool
	}{
		{"boot", 0, true},
		{"system", 1, true},
		{"automatic", 2, true},
		{"manual", 3, true},
		{"disabled", 4, false},
		{"undocumented", 5, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scmStartTypeEnabled(tc.startType))
		})
	}
}

func TestNewSCMService(t *testing.T) {
	t.Run("running automatic service", func(t *testing.T) {
		assert.Equal(t, &Service{
			Name:        "WinDefend",
			Description: "Helps protect users from malware and other potentially unwanted software",
			State:       ServiceRunning,
			Type:        "windows",
			Installed:   true,
			Running:     true,
			Enabled:     true,
		}, newSCMService("WinDefend", "Helps protect users from malware and other potentially unwanted software", 4, 2))
	})

	t.Run("stopping service is not running", func(t *testing.T) {
		s := newSCMService("Spooler", "Print Spooler", 3, 2)
		assert.Equal(t, ServiceStopPending, s.State)
		assert.False(t, s.Running)
	})

	t.Run("paused service is not running", func(t *testing.T) {
		s := newSCMService("W32Time", "Windows Time", 7, 3)
		assert.Equal(t, ServicePaused, s.State)
		assert.False(t, s.Running)
		assert.True(t, s.Enabled)
	})

	t.Run("disabled stopped service", func(t *testing.T) {
		s := newSCMService("PhoneSvc", "Phone Service", 1, 4)
		assert.Equal(t, ServiceStopped, s.State)
		assert.False(t, s.Running)
		assert.False(t, s.Enabled)
		assert.True(t, s.Installed)
	})
}

func TestWindowsNativeEnabled(t *testing.T) {
	for value, want := range map[string]bool{
		"":      false,
		"off":   false,
		"0":     false,
		"false": false,
		"yes":   false,
		"on":    true,
		"ON":    true,
		" on ":  true,
		"true":  true,
		"1":     true,
	} {
		t.Setenv(windowsNativeEnvVar, value)
		assert.Equal(t, want, windowsNativeEnabled(), "%s=%q", windowsNativeEnvVar, value)
	}
}

// The native path is only taken when it is asked for and mql runs on the
// Windows machine it scans. Without the variable every scan uses Get-Service,
// which is what makes the native path safe to ship before it is proven.
func TestUseNativeWindowsServices(t *testing.T) {
	localConn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})

	t.Setenv(windowsNativeEnvVar, "")
	assert.False(t, useNativeWindowsServices(localConn, "windows"), "off unless asked for")

	t.Setenv(windowsNativeEnvVar, "on")
	assert.True(t, useNativeWindowsServices(localConn, "windows"))
	assert.False(t, useNativeWindowsServices(localConn, "linux"), "only on Windows")
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/alpine-container.toml"))
	require.NoError(t, err)
	assert.False(t, useNativeWindowsServices(mockConn, "windows"), "only on a local scan")
}

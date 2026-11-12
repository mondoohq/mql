// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"

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
		}, newSCMService("WinDefend", "Helps protect users from malware and other potentially unwanted software", 4, true))
	})

	t.Run("stopping service is not running", func(t *testing.T) {
		s := newSCMService("Spooler", "Print Spooler", 3, true)
		assert.Equal(t, ServiceStopPending, s.State)
		assert.False(t, s.Running)
	})

	t.Run("paused service is not running", func(t *testing.T) {
		s := newSCMService("W32Time", "Windows Time", 7, true)
		assert.Equal(t, ServicePaused, s.State)
		assert.False(t, s.Running)
		assert.True(t, s.Enabled)
	})

	t.Run("disabled stopped service", func(t *testing.T) {
		s := newSCMService("PhoneSvc", "Phone Service", 1, false)
		assert.Equal(t, ServiceStopped, s.State)
		assert.False(t, s.Running)
		assert.False(t, s.Enabled)
		assert.True(t, s.Installed)
	})

	t.Run("unreadable start type is listed as installed and enabled", func(t *testing.T) {
		enabled, _, _, _ := resolveEnabled(
			func() (uint32, error) { return 0, syscall.Errno(5) },
			func() (uint32, error) { return 0, syscall.Errno(2) },
		)
		s := newSCMService("McmSvc", "", 1, enabled)
		assert.True(t, s.Installed)
		assert.True(t, s.Enabled)
		assert.False(t, s.Running)
		assert.Equal(t, ServiceStopped, s.State)
	})
}

// The native path is only taken when it is asked for and mql runs on the
// Windows machine it scans. Without the variable every scan uses Get-Service,
// which is what makes the native path safe to ship before it is proven.
func TestUseNativeWindowsServices(t *testing.T) {
	localConn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})

	t.Setenv(shared.WindowsNativeEnv, "")
	assert.False(t, useNativeWindowsServices(localConn, "windows"), "off unless asked for")

	t.Setenv(shared.WindowsNativeEnv, "on")
	assert.True(t, useNativeWindowsServices(localConn, "windows"))
	assert.False(t, useNativeWindowsServices(localConn, "linux"), "only on Windows")
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/alpine-container.toml"))
	require.NoError(t, err)
	assert.False(t, useNativeWindowsServices(mockConn, "windows"), "only on a local scan")
}

func TestResolveEnabled(t *testing.T) {
	value := func(v uint32) func() (uint32, error) { return func() (uint32, error) { return v, nil } }
	fail := func(err error) func() (uint32, error) { return func() (uint32, error) { return 0, err } }

	t.Run("service control manager answers, registry not read", func(t *testing.T) {
		enabled, src, scmErr, regErr := resolveEnabled(value(scmStartDisabled), func() (uint32, error) {
			t.Fatal("registry must not be read")
			return 0, nil
		})
		assert.False(t, enabled)
		assert.Equal(t, startTypeFromSCM, src)
		assert.NoError(t, scmErr)
		assert.NoError(t, regErr)
	})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"access denied", syscall.Errno(5)},
		{"file not found", syscall.Errno(2)},
		{"MUI file not found", syscall.Errno(15100)},
	} {
		t.Run(tc.name+" reads the registry", func(t *testing.T) {
			enabled, src, scmErr, regErr := resolveEnabled(fail(tc.err), value(scmStartDisabled))
			assert.False(t, enabled)
			assert.Equal(t, startTypeFromRegistry, src)
			assert.ErrorIs(t, scmErr, tc.err)
			assert.NoError(t, regErr)

			enabled, _, _, _ = resolveEnabled(fail(tc.err), value(scmStartDemand))
			assert.True(t, enabled)
		})
	}

	t.Run("undocumented registry value counts as failed", func(t *testing.T) {
		enabled, src, _, regErr := resolveEnabled(fail(syscall.Errno(2)), value(5))
		assert.True(t, enabled)
		assert.Equal(t, startTypeUnknown, src)
		assert.Error(t, regErr)
	})

	t.Run("both fail reports enabled without failing", func(t *testing.T) {
		enabled, src, scmErr, regErr := resolveEnabled(fail(syscall.Errno(5)), fail(errors.New("no key")))
		assert.True(t, enabled)
		assert.Equal(t, startTypeUnknown, src)
		assert.ErrorIs(t, scmErr, syscall.Errno(5))
		assert.EqualError(t, regErr, "no key")
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"fmt"
	"testing"

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
			Description: "Microsoft Defender Antivirus Service",
			State:       ServiceRunning,
			Type:        "windows",
			Installed:   true,
			Running:     true,
			Enabled:     true,
		}, newSCMService("WinDefend", "Microsoft Defender Antivirus Service", 4, 2))
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

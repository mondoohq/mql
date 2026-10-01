// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/services"
)

func TestParseServiceLaunchD(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/macos.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("launchctl list")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)
	m, err := services.ParseServiceLaunchD(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 15, len(m), "detected the right amount of services")

	assert.Equal(t, "com.apple.SafariHistoryServiceAgent", m[0].Name, "service name detected")
	assert.Equal(t, false, m[0].Running, "service is running")
	assert.Equal(t, true, m[0].Installed, "service is installed")
	assert.Equal(t, "launchd", m[0].Type, "service type is added")
}

// launchctl reports the last exit status as a signed integer. Matching it as a
// single digit dropped every job that had been killed (-9, -15) or exited with
// a multi-digit code, which silently hid around 40% of the services on a
// normal macOS install -- including third-party security agents.
func TestParseServiceLaunchDNonZeroStatus(t *testing.T) {
	input := strings.Join([]string{
		"PID\tStatus\tLabel",
		"28494\t-9\tcom.apple.accessibility.axassetsd",
		"-\t-9\tcom.apple.AccessibilityVisualsAgent",
		"-\t-15\tcom.apple.terminated.by.sigterm",
		"1354\t0\tcom.crowdstrike.falcon.UserAgent",
		"-\t0\tcom.apple.screensharing.agent",
		"500\t78\tcom.example.multidigit",
		"-\t127\tcom.example.exit127",
	}, "\n")

	list, err := services.ParseServiceLaunchD(strings.NewReader(input))
	require.NoError(t, err)

	byName := map[string]*services.Service{}
	for _, s := range list {
		byName[s.Name] = s
	}

	// the header line must not be picked up as a service
	assert.NotContains(t, byName, "Label")
	assert.Len(t, list, 7)

	for _, name := range []string{
		"com.apple.accessibility.axassetsd",
		"com.apple.AccessibilityVisualsAgent",
		"com.apple.terminated.by.sigterm",
		"com.example.multidigit",
		"com.example.exit127",
	} {
		assert.Contains(t, byName, name, "service with a non-zero exit status must still be listed")
	}

	// a PID means the job is running; "-" means it is not
	assert.True(t, byName["com.apple.accessibility.axassetsd"].Running)
	assert.False(t, byName["com.apple.AccessibilityVisualsAgent"].Running)
	assert.True(t, byName["com.crowdstrike.falcon.UserAgent"].Running)
}

// A label must not keep the carriage return of a CRLF line ending.
func TestParseServiceLaunchDCRLF(t *testing.T) {
	input := "PID\tStatus\tLabel\r\n-\t0\tcom.apple.SafariHistoryServiceAgent\r\n1354\t0\tcom.crowdstrike.falcon.UserAgent\r\n"

	list, err := services.ParseServiceLaunchD(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "com.apple.SafariHistoryServiceAgent", list[0].Name)
	assert.Equal(t, "com.crowdstrike.falcon.UserAgent", list[1].Name)
}

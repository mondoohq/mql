// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/services"
)

func TestWindowsServiceParser(t *testing.T) {
	data, err := os.Open("./testdata/windows2019.json")
	if err != nil {
		t.Fatal(err)
	}

	srvs, err := services.ParseWindowsService(data)
	assert.Nil(t, err)
	assert.Equal(t, 7, len(srvs))

	expected := &services.Service{
		Name:        "PolicyAgent",
		Description: "IPsec Policy Agent",
		State:       "ServiceStopped",
		Running:     false,
		Installed:   true,
		Enabled:     true,
		Type:        "windows",
	}
	found := findService(srvs, "PolicyAgent")
	assert.EqualValues(t, expected, found)

	expected = &services.Service{
		Name:        "PlugPlay",
		Description: "Plug and Play",
		State:       "ServiceRunning",
		Running:     true,
		Installed:   true,
		Enabled:     true,
		Type:        "windows",
	}
	found = findService(srvs, "PlugPlay")
	assert.EqualValues(t, expected, found)

	expected = &services.Service{
		Name:        "PhoneSvc",
		Description: "Phone Service",
		State:       "ServiceStopped",
		Running:     false,
		Installed:   true,
		Enabled:     false,
		Type:        "windows",
	}
	found = findService(srvs, "PhoneSvc")
	assert.EqualValues(t, expected, found)
}

func findService(srvs []*services.Service, name string) *services.Service {
	for i := range srvs {
		if srvs[i].Name == name {
			return srvs[i]
		}
	}
	return nil
}

// Get-Service's ServiceControllerStatus values, as they arrive in the JSON.
// 3 is StopPending: a service that is still stopping is not stopped yet.
func TestWindowsServiceState(t *testing.T) {
	for status, want := range map[int]services.State{
		1: services.ServiceStopped,
		2: services.ServiceStartPending,
		3: services.ServiceStopPending,
		4: services.ServiceRunning,
		5: services.ServiceContinuePending,
		6: services.ServicePausePending,
		7: services.ServicePaused,
		0: services.ServiceUnknown,
	} {
		s := services.WindowsService{Status: status}
		assert.Equal(t, want, s.State(), "status %d", status)
		assert.Equal(t, status == 4, s.IsRunning(), "status %d", status)
	}
}

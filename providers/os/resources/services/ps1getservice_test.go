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
		Description: "Internet Protocol security (IPsec) supports network-level peer authentication, data origin authentication, data integrity, data confidentiality (encryption), and replay protection.  This service enforces IPsec policies created through the IP Security Policies snap-in or the command-line tool \"netsh ipsec\".  If you stop this service, you may experience network connectivity issues if your policy requires that connections use IPsec.  Also,remote management of Windows Defender Firewall is not available when this service is stopped.",
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
		Description: "Enables a computer to recognize and adapt to hardware changes with little or no user input. Stopping or disabling this service will result in system instability.",
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
		Description: "", // null in Win32_Service: no description, not the display name
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

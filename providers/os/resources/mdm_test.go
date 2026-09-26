// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func TestMdmVendor(t *testing.T) {
	cases := map[string]string{
		"https://i.manage.microsoft.com/DeviceGatewayProxy/cimhandler.ashx": "intune",
		"https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx": "intune",
		"https://acme.jamfcloud.com/mdm/ServerURL":                          "jamf",
		"https://ACME.JAMFCLOUD.COM:8443/mdm/ServerURL":                     "jamf",
		"https://acme.kandji.io/mdm/checkin":                                "kandji",
		"https://cn1234.awmdm.com/deviceservices/AppleMDM/Processor.aspx":   "workspaceone",
		"https://a.simplemdm.com/mdm":                                       "simplemdm",
		"https://mdm.example.com/MDMServiceConfig?id=1":                     "",
		// a suffix only matches on a label boundary
		"https://notjamfcloud.com/mdm":           "",
		"https://jamfcloud.com.evil.example/mdm": "",
		"":                                       "",
		"not a url":                              "",
		"://missing":                             "",
	}
	for in, want := range cases {
		assert.Equal(t, want, mdmVendor(in), in)
	}
}

func TestMacosMdmResult(t *testing.T) {
	assert.Equal(t, mdmResult{}, macosMdmResult(mdmEnrollment{}))
	// DEP reported without an enrollment is not an enrollment
	assert.Equal(t, mdmResult{}, macosMdmResult(mdmEnrollment{dep: true}))

	r := macosMdmResult(mdmEnrollment{enrolled: true, dep: true, serverUrl: "https://acme.kandji.io/mdm"})
	assert.Equal(t, mdmResult{enrolled: true, serverURL: "https://acme.kandji.io/mdm", method: "automated"}, r)

	r = macosMdmResult(mdmEnrollment{enrolled: true, userApproved: true, serverUrl: "https://acme.jamfcloud.com/mdm"})
	assert.Equal(t, "user", r.method)
}

func TestWindowsMdmResult(t *testing.T) {
	one := int64(1)
	r, err := windowsMdmResult(&windows.MdmState{
		AutopilotTenantID: "tenant",
		Enrollments: []windows.MdmEnrollment{
			{ID: "Context"},
			{ID: "A", EnrollmentState: &one, ServerURL: "https://r.manage.microsoft.com/x"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, mdmResult{enrolled: true, serverURL: "https://r.manage.microsoft.com/x", method: "automated"}, r)

	// Autopilot and Group Policy say nothing without an active enrollment
	r, err = windowsMdmResult(&windows.MdmState{AutopilotTenantID: "tenant", AutoEnrollMdm: &one})
	require.NoError(t, err)
	assert.Equal(t, mdmResult{}, r)

	_, err = windowsMdmResult(&windows.MdmState{Unreadable: 2})
	assert.Error(t, err)
}

// A device that is not enrolled reports enrolled false and every other field
// null, never an empty string a check could compare against.
func TestMdmResultSet_NotEnrolledIsNull(t *testing.T) {
	m := &mqlMdm{}
	mdmResult{}.set(m)
	assert.Equal(t, plugin.StateIsSet, m.Enrolled.State)
	assert.False(t, m.Enrolled.Data)
	for _, f := range []plugin.TValue[string]{m.Vendor, m.ServerUrl, m.Method} {
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, f.State)
	}
}

func TestMdmResultSet_UnknownVendorIsNull(t *testing.T) {
	m := &mqlMdm{}
	mdmResult{enrolled: true, serverURL: "https://mdm.example.com/x", method: "user"}.set(m)
	assert.Equal(t, "https://mdm.example.com/x", m.ServerUrl.Data)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, m.Vendor.State)
	assert.Equal(t, "user", m.Method.Data)
}

func TestMdmResultSet_DeviceIdentity(t *testing.T) {
	// Made-up identifiers.
	id := detwin.DeviceIdentity{
		IntuneDeviceID: "0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9",
		EntraTenantID:  "11223344-5566-7788-99aa-bbccddeeff00",
		EntraDeviceID:  "c0ffee00-1234-4abc-8def-0123456789ab",
	}
	null := plugin.StateIsSet | plugin.StateIsNull

	t.Run("enrolled in Intune reports the device and tenant", func(t *testing.T) {
		m := &mqlMdm{}
		mdmResult{enrolled: true, serverURL: "https://r.manage.microsoft.com/EnrollmentServer", identity: id}.set(m)
		assert.Equal(t, id.IntuneDeviceID, m.DeviceId.Data)
		assert.Equal(t, id.EntraTenantID, m.TenantId.Data)
		assert.Equal(t, id.EntraDeviceID, m.EntraDeviceId.Data)
	})

	t.Run("enrolled elsewhere does not report Intune IDs", func(t *testing.T) {
		m := &mqlMdm{}
		mdmResult{enrolled: true, serverURL: "https://acme.jamfcloud.com/mdm", identity: id}.set(m)
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.TenantId.State)
		assert.Equal(t, id.EntraDeviceID, m.EntraDeviceId.Data, "Entra join is independent of the MDM")
	})

	t.Run("not enrolled ignores a leftover Intune certificate", func(t *testing.T) {
		m := &mqlMdm{}
		mdmResult{identity: id}.set(m)
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.TenantId.State)
		assert.Equal(t, id.EntraDeviceID, m.EntraDeviceId.Data)
	})

	t.Run("nothing detected is null", func(t *testing.T) {
		m := &mqlMdm{}
		mdmResult{enrolled: true, serverURL: "https://r.manage.microsoft.com/x"}.set(m)
		for _, f := range []plugin.TValue[string]{m.DeviceId, m.TenantId, m.EntraDeviceId} {
			assert.Equal(t, null, f.State)
		}
	})
}

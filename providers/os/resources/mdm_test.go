// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

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
	"go.mondoo.com/mql/utils/syncx"
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
	require.NoError(t, mdmResult{}.set(m))
	assert.Equal(t, plugin.StateIsSet, m.Enrolled.State)
	assert.False(t, m.Enrolled.Data)
	for _, f := range []plugin.TValue[string]{m.Vendor, m.ServerUrl, m.Method} {
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, f.State)
	}
}

func TestMdmResultSet_UnknownVendorIsNull(t *testing.T) {
	m := &mqlMdm{}
	require.NoError(t, mdmResult{enrolled: true, serverURL: "https://mdm.example.com/x", method: "user"}.set(m))
	assert.Equal(t, "https://mdm.example.com/x", m.ServerUrl.Data)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, m.Vendor.State)
	assert.Equal(t, "user", m.Method.Data)
}

func TestMdmAndEntra_DeviceKinds(t *testing.T) {
	// Made-up identifiers.
	full := detwin.DeviceIdentity{
		IntuneDeviceID: "0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9",
		EntraTenantID:  "11223344-5566-7788-99aa-bbccddeeff00",
		EntraDeviceID:  "c0ffee00-1234-4abc-8def-0123456789ab",
	}
	entraOnly := detwin.DeviceIdentity{
		EntraTenantID: full.EntraTenantID,
		EntraDeviceID: full.EntraDeviceID,
	}
	null := plugin.StateIsSet | plugin.StateIsNull
	newMdm := func() *mqlMdm {
		return &mqlMdm{MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}}
	}

	t.Run("Intune-enrolled and Entra-joined", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{enrolled: true, serverURL: "https://r.manage.microsoft.com/EnrollmentServer", identity: full}.set(m))
		assert.Equal(t, "intune", m.Vendor.Data)
		assert.Equal(t, full.IntuneDeviceID, m.DeviceId.Data)
		require.NotNil(t, m.Intune.Data)
		assert.Equal(t, full.IntuneDeviceID, m.Intune.Data.DeviceId.Data)
		assert.Equal(t, full.EntraTenantID, m.Intune.Data.TenantId.Data)

		e := &mqlEntra{}
		entraFromIdentity(full).set(e)
		assert.True(t, e.Joined.Data)
		assert.Equal(t, full.EntraDeviceID, e.DeviceId.Data)
		assert.Equal(t, full.EntraTenantID, e.TenantId.Data)
	})

	t.Run("Entra-joined without MDM", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{identity: entraOnly}.set(m))
		assert.False(t, m.Enrolled.Data)
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.Intune.State)

		e := &mqlEntra{}
		entraFromIdentity(entraOnly).set(e)
		assert.True(t, e.Joined.Data)
		assert.Equal(t, full.EntraDeviceID, e.DeviceId.Data)
		assert.Equal(t, full.EntraTenantID, e.TenantId.Data)
	})

	t.Run("managed by another MDM", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{enrolled: true, serverURL: "https://acme.jamfcloud.com/mdm"}.set(m))
		assert.Equal(t, "jamf", m.Vendor.Data)
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.Intune.State)

		// No Entra detection ran (e.g. macOS): not joined.
		e := &mqlEntra{}
		entraResult{}.set(e)
		assert.False(t, e.Joined.Data)
		assert.Equal(t, null, e.DeviceId.State)
		assert.Equal(t, null, e.TenantId.State)
	})

	t.Run("unmanaged", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{}.set(m))
		assert.False(t, m.Enrolled.Data)
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.Intune.State)

		e := &mqlEntra{}
		entraFromIdentity(detwin.DeviceIdentity{}).set(e)
		assert.False(t, e.Joined.Data)
		assert.Equal(t, null, e.DeviceId.State)
		assert.Equal(t, null, e.TenantId.State)
	})

	t.Run("a leftover Intune certificate on an unenrolled device is ignored", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{identity: full}.set(m))
		assert.Equal(t, null, m.DeviceId.State)
		assert.Equal(t, null, m.Intune.State)
	})

	t.Run("an Intune tenant without an Entra device ID is not a join", func(t *testing.T) {
		e := &mqlEntra{}
		entraFromIdentity(detwin.DeviceIdentity{IntuneDeviceID: full.IntuneDeviceID, EntraTenantID: full.EntraTenantID}).set(e)
		assert.False(t, e.Joined.Data)
		assert.Equal(t, null, e.TenantId.State)
	})

	t.Run("enrolled in Intune with an unreadable certificate", func(t *testing.T) {
		m := newMdm()
		require.NoError(t, mdmResult{enrolled: true, serverURL: "https://r.manage.microsoft.com/x"}.set(m))
		assert.Equal(t, null, m.DeviceId.State)
		require.NotNil(t, m.Intune.Data)
		assert.Equal(t, null, m.Intune.Data.DeviceId.State)
		assert.Equal(t, null, m.Intune.Data.TenantId.State)
	})
}

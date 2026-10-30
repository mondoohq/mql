// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceGuardScriptFitsCommandLine(t *testing.T) {
	assert.LessOrEqual(t, len(PSGetDeviceGuard), PSMaxScriptLength,
		"the Device Guard collection script has grown past what fits on the command line")
}

func TestParseDeviceGuardStatus(t *testing.T) {
	f, err := os.Open("./testdata/deviceguard_status.json")
	require.NoError(t, err)
	defer f.Close()

	dg, err := ParseDeviceGuardStatus(f)
	require.NoError(t, err)

	// Each tag is pinned individually: a mistyped one yields a zero value, and
	// a zero value here reads as "not enforced" or "nothing running" on a host
	// that is neither.
	assert.Equal(t, PSInt64Array{1, 2, 3, 5, 7}, dg.AvailableSecurityProperties)
	assert.Equal(t, PSInt64Array{1, 2}, dg.SecurityServicesConfigured)
	assert.Equal(t, PSInt64Array{2}, dg.SecurityServicesRunning)
	require.NotNil(t, dg.CodeIntegrityPolicyEnforcementStatus)
	assert.Equal(t, int64(2), *dg.CodeIntegrityPolicyEnforcementStatus)
	require.NotNil(t, dg.UsermodeCodeIntegrityPolicyEnforcementStatus)
	assert.Equal(t, int64(0), *dg.UsermodeCodeIntegrityPolicyEnforcementStatus)
	require.NotNil(t, dg.VirtualizationBasedSecurityStatus)
	assert.Equal(t, int64(2), *dg.VirtualizationBasedSecurityStatus)
}

func TestDeviceGuardConfiguredIsNotRunning(t *testing.T) {
	// The reading this whole change exists for: Credential Guard (service 1)
	// is configured and did not start, which the policy registry values alone
	// cannot express.
	f, err := os.Open("./testdata/deviceguard_status.json")
	require.NoError(t, err)
	defer f.Close()

	dg, err := ParseDeviceGuardStatus(f)
	require.NoError(t, err)
	assert.Contains(t, dg.SecurityServicesConfigured, int64(1))
	assert.NotContains(t, dg.SecurityServicesRunning, int64(1))
}

func TestParseDeviceGuardStatusNullables(t *testing.T) {
	t.Run("absent scalars stay null rather than becoming 0", func(t *testing.T) {
		// 0 means "off" for every one of these, so decoding an absent value to
		// 0 would report a definite reading the host never gave.
		dg, err := ParseDeviceGuardStatus(strings.NewReader(
			`{"AvailableSecurityProperties":null,"CodeIntegrityPolicyEnforcementStatus":null,` +
				`"UsermodeCodeIntegrityPolicyEnforcementStatus":null,"VirtualizationBasedSecurityStatus":null}`))
		require.NoError(t, err)
		assert.Nil(t, dg.AvailableSecurityProperties)
		assert.Nil(t, dg.SecurityServicesConfigured)
		assert.Nil(t, dg.SecurityServicesRunning)
		assert.Nil(t, dg.CodeIntegrityPolicyEnforcementStatus)
		assert.Nil(t, dg.UsermodeCodeIntegrityPolicyEnforcementStatus)
		assert.Nil(t, dg.VirtualizationBasedSecurityStatus)
	})

	t.Run("an explicit 0 is not absent", func(t *testing.T) {
		dg, err := ParseDeviceGuardStatus(strings.NewReader(
			`{"SecurityServicesRunning":[],"VirtualizationBasedSecurityStatus":0}`))
		require.NoError(t, err)
		require.NotNil(t, dg.SecurityServicesRunning)
		assert.Len(t, dg.SecurityServicesRunning, 0)
		require.NotNil(t, dg.VirtualizationBasedSecurityStatus)
		assert.Equal(t, int64(0), *dg.VirtualizationBasedSecurityStatus)
	})

	t.Run("a wrapped list still decodes", func(t *testing.T) {
		dg, err := ParseDeviceGuardStatus(strings.NewReader(
			`{"SecurityServicesRunning":{"value":[1,2],"Count":2}}`))
		require.NoError(t, err)
		assert.Equal(t, PSInt64Array{1, 2}, dg.SecurityServicesRunning)
	})
}

func TestParseDeviceGuardStatusRejectsEmptyOutput(t *testing.T) {
	// No output means the reading cannot be trusted. Returning an all-null
	// status instead would let "nothing is running" stand as an answer.
	_, err := ParseDeviceGuardStatus(strings.NewReader("   \n"))
	assert.Error(t, err)
}

// Real Win32_DeviceGuard readings from Windows Server 2016 (10.0.14393), 2022
// (10.0.20348) and 2025 (10.0.26100), captured through the shipped
// PSGetDeviceGuard script. Server 2019 (10.0.17763) produced output identical
// to 2022, so it is covered by the same fixture.
//
// The platform properties are where the versions diverge, and they are the
// reason a service that is configured will not start: 2016 offers DMA
// protection, 2022 offers nothing. Neither host has any security service
// configured or running, and both must read that as a real [0] rather than as
// a null or an empty list.
func TestParseDeviceGuardServerBaselines(t *testing.T) {
	for _, tc := range []struct {
		name                string
		fixture             string
		availableProperties []int64
		codeIntegrityStatus int64
	}{
		{"Windows Server 2016 offers DMA protection", "deviceguard_server2016.json", []int64{3}, 0},
		{"Windows Server 2022 offers no relevant property", "deviceguard_server2022.json", []int64{0}, 0},
		// 2025 is the only one of the four that offers hypervisor support (1),
		// NX (5) and MBEC (7), and the only one whose kernel code integrity
		// policy is enforced (2) out of the box.
		{"Windows Server 2025 offers hypervisor, DMA, NX and MBEC", "deviceguard_server2025.json", []int64{1, 3, 5, 7}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open("./testdata/" + tc.fixture)
			require.NoError(t, err)
			defer f.Close()

			status, err := ParseDeviceGuardStatus(f)
			require.NoError(t, err)

			assert.Equal(t, tc.availableProperties, []int64(status.AvailableSecurityProperties))
			// every code the four hosts report has to be one the schema
			// documents (0-8), or the resource is handing back a number with
			// no meaning attached
			for _, code := range status.AvailableSecurityProperties {
				assert.GreaterOrEqual(t, code, int64(0))
				assert.LessOrEqual(t, code, int64(8))
			}

			// "nothing is running" is an answer, not an absence: these must be
			// a one-element list holding 0, never nil.
			require.NotNil(t, status.SecurityServicesConfigured)
			require.NotNil(t, status.SecurityServicesRunning)
			assert.Equal(t, []int64{0}, []int64(status.SecurityServicesConfigured))
			assert.Equal(t, []int64{0}, []int64(status.SecurityServicesRunning))

			// the scalars are reported, so they must be 0 rather than null
			require.NotNil(t, status.VirtualizationBasedSecurityStatus)
			require.NotNil(t, status.CodeIntegrityPolicyEnforcementStatus)
			require.NotNil(t, status.UsermodeCodeIntegrityPolicyEnforcementStatus)
			assert.Equal(t, int64(0), *status.VirtualizationBasedSecurityStatus)
			assert.Equal(t, tc.codeIntegrityStatus, *status.CodeIntegrityPolicyEnforcementStatus)
			assert.Equal(t, int64(0), *status.UsermodeCodeIntegrityPolicyEnforcementStatus)
		})
	}
}

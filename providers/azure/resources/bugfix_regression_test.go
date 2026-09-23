// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

// TestGetStatePowerStates pins the full set of power states Azure reports.
// Only running and deallocated used to be mapped, so a stopped-but-allocated
// VM - still billed, still holding its IP - reported "unknown", and
// where(state == "stopped") silently missed it.
func TestGetStatePowerStates(t *testing.T) {
	status := func(codes ...string) compute.VirtualMachineInstanceView {
		v := compute.VirtualMachineInstanceView{}
		for _, c := range codes {
			v.Statuses = append(v.Statuses, &compute.InstanceViewStatus{Code: strp(c)})
		}
		return v
	}

	for _, tc := range []struct {
		name  string
		view  compute.VirtualMachineInstanceView
		works string
	}{
		{"running", status("PowerState/running"), "running"},
		{"stopped", status("PowerState/stopped"), "stopped"},
		{"deallocated", status("PowerState/deallocated"), "deallocated"},
		{"starting", status("PowerState/starting"), "starting"},
		{"stopping", status("PowerState/stopping"), "stopping"},
		{"deallocating", status("PowerState/deallocating"), "deallocating"},
		{"nil statuses", compute.VirtualMachineInstanceView{}, "unknown"},
		{"no power state", status("ProvisioningState/succeeded"), "unknown"},
		// ARM returns provisioning and power state together; the power state
		// must win regardless of ordering.
		{"mixed, power first", status("PowerState/stopped", "ProvisioningState/succeeded"), "stopped"},
		{"mixed, power last", status("ProvisioningState/succeeded", "PowerState/stopped"), "stopped"},
		{"empty suffix ignored", status("PowerState/"), "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.works, getState(tc.view))
		})
	}

	t.Run("nil status element", func(t *testing.T) {
		v := compute.VirtualMachineInstanceView{
			Statuses: []*compute.InstanceViewStatus{nil, {Code: strp("PowerState/running")}, {Code: nil}},
		}
		assert.NotPanics(t, func() { assert.Equal(t, "running", getState(v)) })
	})
}

// TestAksSecurityProfileFlags locks in that an absent ARM sub-block means the
// feature is OFF, reported as explicit false. Returning null instead let
// `clusters.all(defenderEnabled && workloadIdentityEnabled)` pass on exactly
// the clusters it should fail, because null && null is true in MQL.
func TestAksSecurityProfileFlags(t *testing.T) {
	t.Run("nil profile is all false", func(t *testing.T) {
		f := aksSecurityProfileFlags(nil)
		assert.False(t, f.defenderEnabled)
		assert.False(t, f.defenderSecurityGatingEnabled)
		assert.False(t, f.imageCleanerEnabled)
		assert.False(t, f.workloadIdentityEnabled)
		assert.False(t, f.azureKeyVaultKmsEnabled)
		assert.Empty(t, f.azureKeyVaultKmsKeyID)
		assert.Nil(t, f.imageCleanerIntervalHours)
	})

	t.Run("empty profile is all false", func(t *testing.T) {
		f := aksSecurityProfileFlags(&clusters.ManagedClusterSecurityProfile{})
		assert.False(t, f.defenderEnabled)
		assert.False(t, f.workloadIdentityEnabled)
		assert.False(t, f.azureKeyVaultKmsEnabled)
	})

	t.Run("populated profile", func(t *testing.T) {
		hours := int32(48)
		f := aksSecurityProfileFlags(&clusters.ManagedClusterSecurityProfile{
			Defender: &clusters.ManagedClusterSecurityProfileDefender{
				SecurityMonitoring: &clusters.ManagedClusterSecurityProfileDefenderSecurityMonitoring{Enabled: boolp(true)},
				SecurityGating:     &clusters.ManagedClusterSecurityProfileDefenderSecurityGating{Enabled: boolp(true)},
			},
			ImageCleaner:     &clusters.ManagedClusterSecurityProfileImageCleaner{Enabled: boolp(true), IntervalHours: &hours},
			WorkloadIdentity: &clusters.ManagedClusterSecurityProfileWorkloadIdentity{Enabled: boolp(true)},
			AzureKeyVaultKms: &clusters.AzureKeyVaultKms{Enabled: boolp(true), KeyID: strp("https://v.vault.azure.net/keys/k/1")},
		})
		assert.True(t, f.defenderEnabled)
		assert.True(t, f.defenderSecurityGatingEnabled)
		assert.True(t, f.imageCleanerEnabled)
		assert.True(t, f.workloadIdentityEnabled)
		assert.True(t, f.azureKeyVaultKmsEnabled)
		assert.Equal(t, "https://v.vault.azure.net/keys/k/1", f.azureKeyVaultKmsKeyID)
		require.NotNil(t, f.imageCleanerIntervalHours)
		assert.Equal(t, int32(48), *f.imageCleanerIntervalHours)
	})

	// The sub-block is present but its Enabled pointer is nil: still false,
	// and it must not panic on the way there.
	t.Run("present block with nil Enabled", func(t *testing.T) {
		f := aksSecurityProfileFlags(&clusters.ManagedClusterSecurityProfile{
			Defender:         &clusters.ManagedClusterSecurityProfileDefender{},
			WorkloadIdentity: &clusters.ManagedClusterSecurityProfileWorkloadIdentity{},
		})
		assert.False(t, f.defenderEnabled)
		assert.False(t, f.workloadIdentityEnabled)
	})
}

func TestAdvancedNetworkingFields(t *testing.T) {
	t.Run("nil profile falls back to the disabled defaults", func(t *testing.T) {
		enabled, transit, accel, secEnabled := advancedNetworkingFields(nil)
		assert.False(t, enabled)
		assert.False(t, secEnabled)
		assert.Equal(t, "None", transit)
		assert.Equal(t, "None", accel)
	})

	t.Run("populated", func(t *testing.T) {
		wg := clusters.TransitEncryptionTypeWireGuard
		bpf := clusters.AccelerationModeBpfVeth
		enabled, transit, accel, secEnabled := advancedNetworkingFields(&clusters.AdvancedNetworking{
			Enabled:     boolp(true),
			Performance: &clusters.AdvancedNetworkingPerformance{AccelerationMode: &bpf},
			Security: &clusters.AdvancedNetworkingSecurity{
				Enabled:           boolp(true),
				TransitEncryption: &clusters.AdvancedNetworkingSecurityTransitEncryption{Type: &wg},
			},
		})
		assert.True(t, enabled)
		assert.True(t, secEnabled)
		assert.Equal(t, string(wg), transit)
		assert.Equal(t, string(bpf), accel)
	})
}

// TestProtocolCoversAll covers the value the effective-rules API actually
// emits. armnetwork.EffectiveSecurityRuleProtocol is one of All/Tcp/Udp, so a
// deny-all rule arrives as "All" - and used to not shadow anything, producing
// a spurious internetReachable:true.
func TestProtocolCoversAll(t *testing.T) {
	for _, tc := range []struct {
		deny, allow string
		covers      bool
	}{
		{"All", "Tcp", true},
		{"all", "Udp", true},
		{"All", "All", true},
		{"*", "Tcp", true},
		{"Any", "Tcp", true},
		{"", "Tcp", true},
		{"Tcp", "Tcp", true},
		{"tcp", "TCP", true},
		// A specific deny must not cover a different protocol, and must not
		// cover the wildcard.
		{"Tcp", "Udp", false},
		{"Tcp", "All", false},
		{"Udp", "Tcp", false},
	} {
		t.Run(fmt.Sprintf("deny=%q_allow=%q", tc.deny, tc.allow), func(t *testing.T) {
			assert.Equal(t, tc.covers, protocolCovers(tc.deny, tc.allow))
		})
	}
}

// TestRulePortIntervalsEmptyString: an empty destinationPortRange means "this
// form is not in use", not "all ports". Treating it as 0-65535 let a deny
// scoped to one port shadow every allow, flipping an exposed host to
// internetReachable:false.
func TestRulePortIntervalsEmptyString(t *testing.T) {
	t.Run("empty singular alongside populated plural", func(t *testing.T) {
		got := rulePortIntervals(map[string]any{
			"destinationPortRange":  "",
			"destinationPortRanges": []any{"3389"},
		})
		assert.Equal(t, []portInterval{{3389, 3389}}, got)
	})

	t.Run("both absent means all ports", func(t *testing.T) {
		assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{}))
	})

	t.Run("empty singular alone means all ports", func(t *testing.T) {
		assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{"destinationPortRange": ""}))
	})

	t.Run("wildcard still means all ports", func(t *testing.T) {
		assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{"destinationPortRange": "*"}))
	})

	t.Run("range and single", func(t *testing.T) {
		assert.Equal(t, []portInterval{{80, 443}}, rulePortIntervals(map[string]any{"destinationPortRange": "80-443"}))
		assert.Equal(t, []portInterval{{22, 22}}, rulePortIntervals(map[string]any{"destinationPortRange": "22"}))
	})

	t.Run("malformed falls back to all ports", func(t *testing.T) {
		assert.Equal(t, []portInterval{{0, 65535}}, rulePortIntervals(map[string]any{"destinationPortRange": "abc"}))
	})
}

// TestNestedResourceID guards the extraction that replaced a chain of bare
// type assertions on decoded ARM JSON. Every malformed shape must yield "" -
// which callers read as a legitimate null - rather than panicking.
func TestNestedResourceID(t *testing.T) {
	for _, tc := range []struct {
		name string
		prop any
		key  string
		want string
	}{
		{"happy path", map[string]any{"natGateway": map[string]any{"id": "/subscriptions/s/natGateways/n"}}, "natGateway", "/subscriptions/s/natGateways/n"},
		{"key absent", map[string]any{}, "natGateway", ""},
		{"key is nil", map[string]any{"natGateway": nil}, "natGateway", ""},
		{"key is not a map", map[string]any{"natGateway": "oops"}, "natGateway", ""},
		{"id missing", map[string]any{"natGateway": map[string]any{}}, "natGateway", ""},
		{"id not a string", map[string]any{"natGateway": map[string]any{"id": 42}}, "natGateway", ""},
		{"props not a map", "not a map", "natGateway", ""},
		{"props nil", nil, "natGateway", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Equal(t, tc.want, nestedResourceID(tc.prop, tc.key))
			})
		})
	}
}

// TestIsAzureNotConfigured: 404/403 mean "not configured / not permitted to
// look" and degrade to null. 429 and 5xx must NOT, or a throttled call would
// report an authoritative "not configured" for a resource that is configured.
func TestIsAzureNotConfigured(t *testing.T) {
	respErr := func(code int) error { return &azcore.ResponseError{StatusCode: code} }

	assert.True(t, isAzureNotConfigured(respErr(http.StatusNotFound)))
	assert.True(t, isAzureNotConfigured(respErr(http.StatusForbidden)))
	assert.True(t, isAzureNotConfigured(fmt.Errorf("wrapped: %w", respErr(http.StatusNotFound))))

	assert.False(t, isAzureNotConfigured(respErr(http.StatusTooManyRequests)))
	assert.False(t, isAzureNotConfigured(respErr(http.StatusInternalServerError)))
	assert.False(t, isAzureNotConfigured(respErr(http.StatusBadRequest)))
	assert.False(t, isAzureNotConfigured(errors.New("plain error")))
	assert.False(t, isAzureNotConfigured(nil))
}

// TestPimUnavailable: the old implementation matched any 4xx, so a 429 from
// Microsoft.Authorization was reported as "this tenant has no PIM" - a
// subscription with standing Owner eligibilities silently returned zero.
func TestPimUnavailable(t *testing.T) {
	respErr := func(code int) error { return &azcore.ResponseError{StatusCode: code} }

	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		assert.True(t, pimUnavailable(respErr(code)), "status %d should be treated as no PIM data", code)
	}
	for _, code := range []int{http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway} {
		assert.False(t, pimUnavailable(respErr(code)), "status %d must surface, not be swallowed", code)
	}
	assert.False(t, pimUnavailable(errors.New("plain error")))
	assert.False(t, pimUnavailable(nil))
}

func TestVpnNatRuleMappingsToDict(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		got, err := vpnNatRuleMappingsToDict(nil)
		require.NoError(t, err)
		assert.Equal(t, []any{}, got)
	})

	t.Run("skips nil elements", func(t *testing.T) {
		got, err := vpnNatRuleMappingsToDict([]*network.VPNNatRuleMapping{
			nil,
			{AddressSpace: strp("10.0.0.0/24"), PortRange: strp("100-200")},
			nil,
		})
		require.NoError(t, err)
		require.Len(t, got, 1)
		m, ok := got[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.0/24", m["addressSpace"])
	})
}

// TestStrPtrsToAnySkipsNil documents the contract that replaced
// convert.SliceStrPtrToInterface at ~40 call sites: that helper dereferences
// every element with no guard and panics on a nil, which is unrecoverable in
// a provider goroutine.
func TestStrPtrsToAnySkipsNil(t *testing.T) {
	assert.NotPanics(t, func() {
		got := strPtrsToAny([]*string{strp("a"), nil, strp("b")})
		assert.Equal(t, []any{"a", "b"}, got)
	})
	assert.Equal(t, []any{}, strPtrsToAny(nil))

	assert.NotPanics(t, func() {
		assert.Equal(t, []string{"a"}, azureStrPtrsToStr([]*string{nil, strp("a")}))
	})
}

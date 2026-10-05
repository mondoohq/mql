// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseWinRegistryHotpatch(t *testing.T) {

	t.Run("parse hptpatching settings correctly", func(t *testing.T) {
		data := `{
			"Name":  "Hotpatch Enrollment Package",
			"HotPatchTableSize": "4096",
			"EnableVirtualizationBasedSecurity": "1"
		}`

		m, err := ParseWinRegistryHotpatch(strings.NewReader(data))
		assert.Nil(t, err)
		assert.True(t, m)
	})

	t.Run("parse missing table size", func(t *testing.T) {
		data := `{
			"Name":  "Hotpatch Enrollment Package",
			"HotPatchTableSize": "0",
			"EnableVirtualizationBasedSecurity": "1"
		}`

		m, err := ParseWinRegistryHotpatch(strings.NewReader(data))
		assert.Nil(t, err)
		assert.False(t, m)
	})

	t.Run("parse missing name", func(t *testing.T) {
		data := `{
			"Name":  "",
			"HotPatchTableSize": "4096",
			"EnableVirtualizationBasedSecurity": "1"
		}`

		m, err := ParseWinRegistryHotpatch(strings.NewReader(data))
		assert.Nil(t, err)
		assert.False(t, m)
	})

	t.Run("parse missing VBS", func(t *testing.T) {
		data := `{
			"Name":  "Hotpatch Enrollment Package",
			"HotPatchTableSize": "1",
			"EnableVirtualizationBasedSecurity": "0"
		}`

		m, err := ParseWinRegistryHotpatch(strings.NewReader(data))
		assert.Nil(t, err)
		assert.False(t, m)
	})

	t.Run("parse empty JSON", func(t *testing.T) {
		data := `{
			"Name":  "",
			"HotPatchTableSize": "0",
			"EnableVirtualizationBasedSecurity": "0"
		}`

		m, err := ParseWinRegistryHotpatch(strings.NewReader(data))
		assert.Nil(t, err)
		assert.False(t, m)
	})
}

func TestParseWinRegistryClientHotpatch(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"registry fallback: rebootless and VBS configured", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1"}`, true},
		{"no rebootless updates", `{"AllowRebootlessUpdates":"0","EnableVirtualizationBasedSecurity":"1"}`, false},
		{"registry fallback: VBS not configured", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"0"}`, false},
		{"empty values", `{"AllowRebootlessUpdates":"","EnableVirtualizationBasedSecurity":""}`, false},
		{"VBS running without registry config", `{"AllowRebootlessUpdates":"1","VirtualizationBasedSecurityStatus":"2"}`, true},
		{"VBS running with registry config", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"2"}`, true},
		{"VBS enabled but not running wins over registry=1", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"1"}`, false},
		{"VBS status 0 wins over registry=1", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":"0"}`, false},
		{"VBS running but rebootless missing", `{"VirtualizationBasedSecurityStatus":"2"}`, false},
		{"VBS running but rebootless disabled", `{"AllowRebootlessUpdates":"0","VirtualizationBasedSecurityStatus":"2"}`, false},
		{"missing WMI status falls back to registry", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1"}`, true},
		{"empty WMI status falls back to registry", `{"AllowRebootlessUpdates":"1","EnableVirtualizationBasedSecurity":"1","VirtualizationBasedSecurityStatus":""}`, true},
		{"rebootless missing, registry VBS set", `{"EnableVirtualizationBasedSecurity":"1"}`, false},
		{"empty object", `{}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseWinRegistryClientHotpatch(strings.NewReader(tc.data))
			assert.Nil(t, err)
			assert.Equal(t, tc.want, m)
		})
	}

	t.Run("json round-trip keeps VBS running state", func(t *testing.T) {
		in := WindowsClientHotpatch{AllowRebootlessUpdates: "1", EnableVirtualizationBasedSecurity: "1", VirtualizationBasedSecurityStatus: "2"}
		b, err := json.Marshal(in)
		assert.Nil(t, err)
		var out WindowsClientHotpatch
		assert.Nil(t, json.Unmarshal(b, &out))
		assert.Equal(t, in, out)
	})
}

func TestHotpatchSupported(t *testing.T) {
	t.Run("client amd64 build 26100 with sufficient UBR", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "5000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client amd64 build 26100 with exact minimum UBR", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "2033",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client amd64 build 26100 with UBR below minimum", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "2000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	t.Run("client arm64 build 26100 with sufficient UBR", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "5000",
			Arch:    "ARM64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client arm64 build 26100 with exact minimum UBR", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "4929",
			Arch:    "ARM64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client arm64 build 26100 with UBR below arm64 minimum", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "3775",
			Arch:    "ARM64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	t.Run("client build 26100 with empty UBR", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "26100",
			Build:   "",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	t.Run("client build above 26100 always supported", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "27000",
			Build:   "100",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client build 22000 not supported", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise",
			Version: "22000",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	t.Run("server build 20348 supported", func(t *testing.T) {
		pf := &inventory.Platform{
			Version: "20348",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "3"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("server build 19041 not supported", func(t *testing.T) {
		pf := &inventory.Platform{
			Version: "19041",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "3"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	// Edition guard: Home / SE can never be enrolled in hotpatch. The Pro
	// family can (e.g. Microsoft 365 Business Premium keeps devices on Pro).

	t.Run("client Pro 26200 with high UBR accepted", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Pro",
			Version: "26200",
			Build:   "8246",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client Pro for Workstations accepted", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Pro for Workstations",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client Home rejected by edition guard", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Home",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})

	t.Run("client Pro Education accepted", func(t *testing.T) {
		// Pro Education is supported by Intune quality-update policies.
		pf := &inventory.Platform{
			Title:   "Windows 11 Pro Education",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client Education accepted", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 Education",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client IoT Enterprise accepted", func(t *testing.T) {
		pf := &inventory.Platform{
			Title:   "Windows 11 IoT Enterprise",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client Enterprise multi-session accepted", func(t *testing.T) {
		// Cloud PC / Win365 Enterprise multi-session SKU is in the eligible
		// license list and reports an "Enterprise multi-session" title.
		pf := &inventory.Platform{
			Title:   "Windows 11 Enterprise multi-session",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.True(t, hotpatchSupported(pf))
	})

	t.Run("client empty title rejected", func(t *testing.T) {
		// Missing Title means we can't tell what's running. Hotpatch eligibility
		// must default to refuse — failing open here surfaces hotpatch-only
		// KBs on every asset whose detection didn't fill Title.
		pf := &inventory.Platform{
			Title:   "",
			Version: "27000",
			Arch:    "AMD64",
			Labels:  map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		assert.False(t, hotpatchSupported(pf))
	})
}

func TestIsHotpatchEligibleClientEdition(t *testing.T) {
	cases := []struct {
		title    string
		eligible bool
	}{
		{"Windows 11 Enterprise", true},
		{"Windows 11 Enterprise Evaluation", true},
		{"Windows 11 Enterprise multi-session", true},
		{"Windows 11 IoT Enterprise", true},
		{"Windows 11 Education", true},
		{"WINDOWS 11 ENTERPRISE", true}, // case-insensitive
		{"Windows 11 Pro", true},
		{"Windows 11 Pro for Workstations", true},
		{"Windows 11 Pro Education", true},
		{"Windows 11 Professional", true},
		{"Windows 11 Proxy Edition", false}, // "pro" only as a substring
		{"Windows 11 Home", false},
		{"Windows 11 Home Single Language", false},
		{"Windows 11 SE", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			assert.Equal(t, tc.eligible, isHotpatchEligibleClientEdition(tc.title))
		})
	}
}

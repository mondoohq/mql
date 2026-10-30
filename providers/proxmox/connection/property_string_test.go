// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePropertyStringOverRealConfigLines(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		defaultKey string
		want       map[string]string
	}{
		{
			name:       "efi vars disk with pre-enrolled keys",
			raw:        "local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1,size=528K",
			defaultKey: "file",
			want: map[string]string{
				"file":              "local-lvm:vm-100-disk-1",
				"efitype":           "4m",
				"pre-enrolled-keys": "1",
				"size":              "528K",
			},
		},
		{
			name:       "efi vars disk with no options at all",
			raw:        "local-lvm:vm-101-disk-0",
			defaultKey: "file",
			want:       map[string]string{"file": "local-lvm:vm-101-disk-0"},
		},
		{
			name:       "vtpm state disk",
			raw:        "local-lvm:vm-100-disk-2,size=4M,version=v2.0",
			defaultKey: "file",
			want: map[string]string{
				"file":    "local-lvm:vm-100-disk-2",
				"size":    "4M",
				"version": "v2.0",
			},
		},
		{
			name:       "cpu line whose flag list contains semicolons",
			raw:        "host,flags=+spec-ctrl;+ssbd;-md-clear,hidden=1",
			defaultKey: "cputype",
			want: map[string]string{
				"cputype": "host",
				// the semicolons must survive: only commas separate elements
				"flags":  "+spec-ctrl;+ssbd;-md-clear",
				"hidden": "1",
			},
		},
		{
			name:       "cpu line naming the model explicitly",
			raw:        "cputype=x86-64-v2-AES,hidden=0",
			defaultKey: "cputype",
			want:       map[string]string{"cputype": "x86-64-v2-AES", "hidden": "0"},
		},
		{
			name:       "amd sev line",
			raw:        "type=snp,no-debug=1,no-key-sharing=1,kernel-hashes=0",
			defaultKey: "type",
			want: map[string]string{
				"type":           "snp",
				"no-debug":       "1",
				"no-key-sharing": "1",
				"kernel-hashes":  "0",
			},
		},
		{
			name:       "amd sev line with only the positional type",
			raw:        "std",
			defaultKey: "type",
			want:       map[string]string{"type": "std"},
		},
		{
			name:       "rng device",
			raw:        "/dev/urandom,max_bytes=1024,period=1000",
			defaultKey: "source",
			want: map[string]string{
				"source":    "/dev/urandom",
				"max_bytes": "1024",
				"period":    "1000",
			},
		},
		{
			name:       "webauthn block has no positional value",
			raw:        "rp=Proxmox VE,origin=https://pve.example.test:8006,id=pve.example.test,allow-subdomains=0",
			defaultKey: "",
			want: map[string]string{
				"rp":               "Proxmox VE",
				"origin":           "https://pve.example.test:8006",
				"id":               "pve.example.test",
				"allow-subdomains": "0",
			},
		},
		{
			name:       "absent config line",
			raw:        "",
			defaultKey: "file",
			want:       map[string]string{},
		},
		{
			name:       "a bare token after the first element is not a second positional",
			raw:        "local:disk,junk,size=4M",
			defaultKey: "file",
			want:       map[string]string{"file": "local:disk", "size": "4M"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ParsePropertyString(tc.raw, tc.defaultKey))
		})
	}
}

func TestPropBoolKeepsAbsentApartFromZero(t *testing.T) {
	// A VM whose EFI vars disk exists but never mentions pre-enrolled-keys and
	// a VM that spells out pre-enrolled-keys=0 are different configurations,
	// and a VM with no efidisk0 at all is a third. Collapsing any of them into
	// a plain false would report Secure Boot state nobody read.
	props := ParsePropertyString("local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1", "file")
	require.NotNil(t, PropBool(props, "pre-enrolled-keys"))
	require.True(t, *PropBool(props, "pre-enrolled-keys"))

	off := ParsePropertyString("local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=0", "file")
	require.NotNil(t, PropBool(off, "pre-enrolled-keys"))
	require.False(t, *PropBool(off, "pre-enrolled-keys"))

	absent := ParsePropertyString("local-lvm:vm-100-disk-1,efitype=4m", "file")
	require.Nil(t, PropBool(absent, "pre-enrolled-keys"))

	noDevice := ParsePropertyString("", "file")
	require.Nil(t, PropBool(noDevice, "pre-enrolled-keys"))

	// the boolean spellings some releases emit
	require.True(t, *PropBool(map[string]string{"x": "true"}, "x"))
	require.False(t, *PropBool(map[string]string{"x": "false"}, "x"))
}

func TestConfigBoolAcceptsEveryShapeAndReportsAbsentAsNil(t *testing.T) {
	// The config map comes straight from encoding/json, so the same flag
	// arrives as a number, a string, or a real boolean depending on the
	// endpoint and the Proxmox release.
	cfg := map[string]any{
		"kvm":     float64(0),
		"debug":   float64(1),
		"console": "0",
		"real":    true,
		"nulled":  nil,
	}

	require.NotNil(t, ConfigBool(cfg, "kvm"))
	require.False(t, *ConfigBool(cfg, "kvm"))
	require.True(t, *ConfigBool(cfg, "debug"))
	require.False(t, *ConfigBool(cfg, "console"))
	require.True(t, *ConfigBool(cfg, "real"))

	// absent, explicitly null, and a nil map all mean "not stated"
	require.Nil(t, ConfigBool(cfg, "missing"))
	require.Nil(t, ConfigBool(cfg, "nulled"))
	require.Nil(t, ConfigBool(nil, "kvm"))
}

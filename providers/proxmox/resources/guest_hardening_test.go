// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

func TestParseHotplugFeaturesReportsWhatTheHypervisorAllows(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		found bool
		want  []any
	}{
		{
			// The case that matters most: a VM nobody configured still accepts
			// a USB device or a disk attached while it runs, so an empty list
			// here would report the opposite of the truth.
			name:  "absent key falls back to the Proxmox default set",
			found: false,
			want:  []any{"network", "disk", "usb"},
		},
		{
			name:  "the 1 shorthand expands to the same default set",
			raw:   "1",
			found: true,
			want:  []any{"network", "disk", "usb"},
		},
		{
			name:  "0 is the only value that disables hotplug outright",
			raw:   "0",
			found: true,
			want:  []any{},
		},
		{
			name:  "an explicit list is reported verbatim",
			raw:   "network,disk,cpu,memory,usb,cloudinit",
			found: true,
			want:  []any{"network", "disk", "cpu", "memory", "usb", "cloudinit"},
		},
		{
			name:  "a narrowed list drops the default extras",
			raw:   "network",
			found: true,
			want:  []any{"network"},
		},
		{
			name:  "whitespace and empty elements are ignored",
			raw:   "network, disk,",
			found: true,
			want:  []any{"network", "disk"},
		},
		{
			// PVE never emits this, but a key present with an empty value must
			// not read as "hotplug disabled".
			name:  "present but empty falls back to the default set",
			raw:   "",
			found: true,
			want:  []any{"network", "disk", "usb"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, parseHotplugFeatures(tc.raw, tc.found))
		})
	}
}

func TestSplitCPUFlagsKeepsTheSignOnEachFlag(t *testing.T) {
	// `+spec-ctrl` and `-spec-ctrl` are opposite answers to the same audit
	// question, so the sign has to survive the split.
	require.Equal(t,
		[]any{"+spec-ctrl", "+ssbd", "-md-clear"},
		splitCPUFlags("+spec-ctrl;+ssbd;-md-clear"))

	require.Equal(t, []any{"+aes"}, splitCPUFlags("+aes"))
	require.Equal(t, []any{"+aes", "-pdpe1gb"}, splitCPUFlags(" +aes ; -pdpe1gb "))

	// no flags overridden is an empty list, never nil, so `.length` and
	// `.contains` behave the same as on a populated one
	require.Equal(t, []any{}, splitCPUFlags(""))
	require.Equal(t, []any{}, splitCPUFlags(";;"))
}

func TestParseRemoveVanishedTreatsNoneAsNothingRemoved(t *testing.T) {
	tests := []struct {
		raw  string
		want []any
	}{
		// Proxmox spells "remove nothing" as the literal string `none`, which
		// must not become a removal target named "none".
		{"none", []any{}},
		{"", []any{}},
		{"entry", []any{"entry"}},
		{"entry;properties;acl", []any{"entry", "properties", "acl"}},
		{"acl;entry", []any{"acl", "entry"}},
		{" entry ; acl ", []any{"entry", "acl"}},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			require.Equal(t, tc.want, parseRemoveVanished(tc.raw))
		})
	}
}

func TestUnixOrNullKeepsAnAbsentTimestampNull(t *testing.T) {
	// A zero epoch would render as 1970 and read as a sync that really ran.
	require.Equal(t, llx.NilData, unixOrNull(0))
	require.Equal(t, llx.NilData, unixOrNull(-1))

	got := unixOrNull(1755000000)
	require.NotEqual(t, llx.NilData, got)
	ts, ok := got.Value.(*time.Time)
	require.True(t, ok)
	require.Equal(t, int64(1755000000), ts.Unix())
}

func TestRealmSyncEnabledAppliesTheDocumentedDefault(t *testing.T) {
	// Proxmox runs a job whose definition omits `enabled`, so reporting false
	// there would report a schedule that is actually in force as switched off.
	require.Equal(t, true, realmSyncEnabled(nil).Value)

	on := connection.PveBool(true)
	off := connection.PveBool(false)
	require.Equal(t, true, realmSyncEnabled(&on).Value)
	require.Equal(t, false, realmSyncEnabled(&off).Value)
}

func TestRealmTFATypeExtractsTheChallengeType(t *testing.T) {
	// /access/domains serializes tfa as a property string, so the raw value is
	// not the answer to "which second factor does this realm demand".
	require.Equal(t, "oath", realmTFAType("type=oath,step=30,digits=6"))
	require.Equal(t, "yubico", realmTFAType("type=yubico,id=1234,key=abcd"))
	require.Equal(t, "", realmTFAType(""))

	// A value carrying no type= is returned as it stands: the realm still
	// enforces something, and dropping it would read as no second factor.
	require.Equal(t, "oath", realmTFAType("oath"))
}

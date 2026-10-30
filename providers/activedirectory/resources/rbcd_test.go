// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

// webServerSID is a synthetic computer-account SID, S-1-5-21-100-200-300-1108,
// standing in for a host granted resource-based constrained delegation.
var webServerSID = []byte{
	0x01,                               // revision
	0x05,                               // sub-authority count
	0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
	0x15, 0x00, 0x00, 0x00, // 21
	0x64, 0x00, 0x00, 0x00, // 100
	0xC8, 0x00, 0x00, 0x00, // 200
	0x2C, 0x01, 0x00, 0x00, // 300
	0x54, 0x04, 0x00, 0x00, // 1108
}

// appServerSID is a second synthetic computer-account SID,
// S-1-5-21-100-200-300-1109.
var appServerSID = []byte{
	0x01,
	0x05,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x15, 0x00, 0x00, 0x00, // 21
	0x64, 0x00, 0x00, 0x00, // 100
	0xC8, 0x00, 0x00, 0x00, // 200
	0x2C, 0x01, 0x00, 0x00, // 300
	0x55, 0x04, 0x00, 0x00, // 1109
}

func TestRBCDPrincipalSIDs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{
			name: "single trustee",
			raw:  buildSD(buildDACL(buildBasicACE(rightGenericAll, webServerSID))),
			want: []string{"S-1-5-21-100-200-300-1108"},
		},
		{
			name: "two trustees keep DACL order",
			raw: buildSD(buildDACL(
				buildBasicACE(rightGenericAll, webServerSID),
				buildBasicACE(rightGenericAll, appServerSID),
			)),
			want: []string{"S-1-5-21-100-200-300-1108", "S-1-5-21-100-200-300-1109"},
		},
		{
			name: "duplicate ACEs for one trustee collapse",
			raw: buildSD(buildDACL(
				buildBasicACE(rightGenericAll, webServerSID),
				buildBasicACE(rightGenericWrite, webServerSID),
			)),
			want: []string{"S-1-5-21-100-200-300-1108"},
		},
		{
			name: "well-known trustee",
			raw:  buildSD(buildDACL(buildBasicACE(rightGenericAll, everyoneSID))),
			want: []string{"S-1-1-0"},
		},
		{
			name: "object ACE trustee",
			raw: buildSD(buildDACL(buildObjectACE(
				rightGenericAll, 0x00, nil, nil, webServerSID,
			))),
			want: []string{"S-1-5-21-100-200-300-1108"},
		},
		{
			name: "empty attribute",
			raw:  nil,
			want: nil,
		},
		{
			name: "zero-length attribute",
			raw:  []byte{},
			want: nil,
		},
		{
			name: "descriptor with an empty DACL",
			raw:  buildSD(buildDACL()),
			want: []string{},
		},
		{
			name: "descriptor too short to be a security descriptor",
			raw:  []byte{0x01, 0x00, 0x04, 0x80},
			want: []string{},
		},
		{
			name: "truncated DACL",
			raw:  buildSD(buildDACL(buildBasicACE(rightGenericAll, webServerSID)))[:24],
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rbcdPrincipalSIDs(tt.raw)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rbcdPrincipalSIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRBCDPrincipalSIDsMatchesRBCDBoolean pins the invariant that the boolean
// the provider has always exposed and the new principal list agree: an empty
// attribute means rbcd is false and there are no principals, and a populated
// attribute means rbcd is true and the trustees are readable.
func TestRBCDPrincipalSIDsMatchesRBCDBoolean(t *testing.T) {
	tests := []struct {
		name           string
		raw            []byte
		wantRBCD       bool
		wantPrincipals int
	}{
		{"attribute absent", nil, false, 0},
		{
			name:           "attribute present with one trustee",
			raw:            buildSD(buildDACL(buildBasicACE(rightGenericAll, webServerSID))),
			wantRBCD:       true,
			wantPrincipals: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is the expression computers() uses for the rbcd field.
			rbcd := len(tt.raw) > 0
			if rbcd != tt.wantRBCD {
				t.Errorf("rbcd = %v, want %v", rbcd, tt.wantRBCD)
			}

			principals := rbcdPrincipalSIDs(tt.raw)
			if len(principals) != tt.wantPrincipals {
				t.Errorf("rbcdPrincipalSIDs() returned %d principals (%v), want %d",
					len(principals), principals, tt.wantPrincipals)
			}
		})
	}
}

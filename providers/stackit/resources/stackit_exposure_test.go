// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestNicsHavePublicIp(t *testing.T) {
	cases := []struct {
		name string
		nics []any
		want bool
	}{
		{"has public ip", []any{map[string]any{"publicIp": "203.0.113.5"}}, true},
		{"second nic has ip", []any{map[string]any{"publicIp": ""}, map[string]any{"publicIp": "203.0.113.5"}}, true},
		{"empty public ip", []any{map[string]any{"publicIp": ""}}, false},
		{"no public ip key", []any{map[string]any{"nicId": "x"}}, false},
		{"no nics", []any{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nicsHavePublicIp(c.nics); got != c.want {
				t.Errorf("nicsHavePublicIp(%v) = %v, want %v", c.nics, got, c.want)
			}
		})
	}
}

func TestSecurityRuleOpenToInternet(t *testing.T) {
	cases := []struct {
		direction string
		ipRange   string
		want      bool
	}{
		{"ingress", "0.0.0.0/0", true},
		{"ingress", "::/0", true},
		{"INGRESS", "0.0.0.0/0", true},
		{"ingress", "203.0.113.0/24", false},
		{"ingress", "", false},
		{"egress", "0.0.0.0/0", false},
	}
	for _, c := range cases {
		if got := securityRuleOpenToInternet(c.direction, c.ipRange); got != c.want {
			t.Errorf("securityRuleOpenToInternet(%q, %q) = %v, want %v", c.direction, c.ipRange, got, c.want)
		}
	}
}

func TestCidrIsAnyAddress(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{" 0.0.0.0/0 ", true},
		{"10.0.0.0/8", false},
		{"203.0.113.0/24", false},
		{"", false},
	}
	for _, c := range cases {
		if got := cidrIsAnyAddress(c.in); got != c.want {
			t.Errorf("cidrIsAnyAddress(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAclAllowsAnyAddress(t *testing.T) {
	cases := []struct {
		name   string
		ranges []string
		want   bool
	}{
		{"empty list is open", nil, true},
		{"all-blank list is open", []string{"", "  "}, true},
		{"contains ipv4 default route", []string{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"contains ipv6 default route", []string{"::/0"}, true},
		{"restricted ranges only", []string{"10.0.0.0/8", "203.0.113.0/24"}, false},
		{"single restricted range", []string{"192.168.0.0/16"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aclAllowsAnyAddress(c.ranges); got != c.want {
				t.Errorf("aclAllowsAnyAddress(%v) = %v, want %v", c.ranges, got, c.want)
			}
		})
	}
}

func TestDictStrSlice(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want []string
	}{
		{"json array of strings", []any{"a", "b"}, []string{"a", "b"}},
		{"json array mixed", []any{"a", 1, "b"}, []string{"a", "b"}},
		{"string slice passthrough", []string{"x"}, []string{"x"}},
		{"comma separated", "10.0.0.0/8, 0.0.0.0/0", []string{"10.0.0.0/8", "0.0.0.0/0"}},
		{"single string", "0.0.0.0/0", []string{"0.0.0.0/0"}},
		{"blank string", "  ", nil},
		{"nil", nil, nil},
		{"other type", 42, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dictStrSlice(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("dictStrSlice(%v) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("dictStrSlice(%v)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestDictBool(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"TRUE", true},
		{"false", false},
		{"yes", false},
		{1, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := dictBool(c.in); got != c.want {
			t.Errorf("dictBool(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLbAccessControlRanges(t *testing.T) {
	options := map[string]any{
		"accessControl": map[string]any{
			"allowedSourceRanges": []any{"0.0.0.0/0", "10.0.0.0/8"},
		},
	}
	got := lbAccessControlRanges(options)
	if len(got) != 2 || got[0] != "0.0.0.0/0" || got[1] != "10.0.0.0/8" {
		t.Errorf("lbAccessControlRanges = %v", got)
	}
	if r := lbAccessControlRanges(map[string]any{}); r != nil {
		t.Errorf("lbAccessControlRanges(empty) = %v, want nil", r)
	}
	if r := lbAccessControlRanges("not a map"); r != nil {
		t.Errorf("lbAccessControlRanges(scalar) = %v, want nil", r)
	}
}

func TestLbPrivateNetworkOnly(t *testing.T) {
	if !lbPrivateNetworkOnly(map[string]any{"privateNetworkOnly": true}) {
		t.Error("want private-network-only true")
	}
	if lbPrivateNetworkOnly(map[string]any{"privateNetworkOnly": false}) {
		t.Error("want private-network-only false")
	}
	if lbPrivateNetworkOnly(map[string]any{}) {
		t.Error("absent flag should be false")
	}
}

func TestLbExposure(t *testing.T) {
	openAcl := map[string]any{
		"accessControl": map[string]any{"allowedSourceRanges": []any{"0.0.0.0/0"}},
	}
	restrictedAcl := map[string]any{
		"accessControl": map[string]any{"allowedSourceRanges": []any{"10.0.0.0/8"}},
	}
	cases := []struct {
		name          string
		ext           string
		privateOnly   bool
		options       any
		wantReachable bool
		wantPublic    bool
		wantAllows    bool
	}{
		{"public + open acl", "203.0.113.5", false, openAcl, true, true, true},
		{"public + restricted acl", "203.0.113.5", false, restrictedAcl, false, true, false},
		{"public + no acl is open", "203.0.113.5", false, map[string]any{}, true, true, true},
		{"private network only", "203.0.113.5", true, openAcl, false, false, true},
		{"no external address", "", false, openAcl, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reachable, public, allows := lbExposure(c.ext, c.privateOnly, c.options)
			if reachable != c.wantReachable || public != c.wantPublic || allows != c.wantAllows {
				t.Errorf("lbExposure = (%v,%v,%v), want (%v,%v,%v)",
					reachable, public, allows, c.wantReachable, c.wantPublic, c.wantAllows)
			}
		})
	}
}

func TestDbaasInstanceReachable(t *testing.T) {
	cases := []struct {
		name   string
		params any
		want   bool
	}{
		{"public + open acl", map[string]any{"enable_public_access": true, "sgw_acl": "0.0.0.0/0"}, true},
		{"public + no acl", map[string]any{"enable_public_access": true}, true},
		{"public + restricted acl", map[string]any{"enable_public_access": true, "sgw_acl": "10.0.0.0/8"}, false},
		{"public string true", map[string]any{"enable_public_access": "true"}, true},
		{"explicit not public overrides an open acl", map[string]any{"enable_public_access": false, "sgw_acl": "0.0.0.0/0"}, false},
		{"explicit string false overrides an open acl", map[string]any{"enable_public_access": "false", "sgw_acl": "0.0.0.0/0"}, false},
		// The API does not send enable_public_access (no InstanceParameters
		// model declares it), so the verdict has to come from sgw_acl alone.
		// Reading the absent key as false made every instance unreachable.
		{"absent public flag + open acl is reachable", map[string]any{"sgw_acl": "0.0.0.0/0"}, true},
		{"absent public flag + restricted acl", map[string]any{"sgw_acl": "10.0.0.0/8"}, false},
		{"absent public flag + no acl is reachable", map[string]any{}, true},
		{"acl as list", map[string]any{"enable_public_access": true, "sgw_acl": []any{"::/0"}}, true},
		{"nil params", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dbaasInstanceReachable(c.params); got != c.want {
				t.Errorf("dbaasInstanceReachable(%v) = %v, want %v", c.params, got, c.want)
			}
		})
	}
}

func TestFlexInstanceReachable(t *testing.T) {
	cases := []struct {
		name string
		acl  []any
		want bool
	}{
		{"empty acl is not flagged (no public-endpoint signal)", []any{}, false},
		{"contains default route", []any{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"restricted ranges only", []any{"10.0.0.0/8", "203.0.113.0/24"}, false},
		{"ipv6 default route", []any{"::/0"}, true},
		{"non-string entries ignored", []any{1, "192.168.0.0/16"}, false},
		{"non-string entries with default route still open", []any{1, "0.0.0.0/0"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := flexInstanceReachable(c.acl); got != c.want {
				t.Errorf("flexInstanceReachable(%v) = %v, want %v", c.acl, got, c.want)
			}
		})
	}
}

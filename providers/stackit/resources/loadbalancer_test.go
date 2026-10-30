// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"testing"

	alb "github.com/stackitcloud/stackit-sdk-go/services/alb/v2api"
	loadbalancer "github.com/stackitcloud/stackit-sdk-go/services/loadbalancer/v2api"
)

// TestAlbDisableTargetSecurityGroupAssignmentAbsentIsNull pins the application
// load balancer to the same tri-state reading as the network one. It used to
// read the flag through the non-pointer getter, so an absent value came back
// as false: an assurance that the managed group is attached on a balancer
// whose setting was never read.
func TestAlbDisableTargetSecurityGroupAssignmentAbsentIsNull(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    *bool
	}{
		{"flag absent reads null", `{"name":"alb1"}`, nil},
		{"operator opted out", `{"name":"alb1","disableTargetSecurityGroupAssignment":true}`, new(true)},
		{"managed group attached", `{"name":"alb1","disableTargetSecurityGroupAssignment":false}`, new(false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lb alb.LoadBalancer
			if err := json.Unmarshal([]byte(tc.payload), &lb); err != nil {
				t.Fatalf("decoding alb payload: %v", err)
			}
			assertBoolPtr(t, "lbDisableTargetSecurityGroupAssignment(alb)", lbDisableTargetSecurityGroupAssignment(&lb), tc.want)
		})
	}
}

func TestListenerSNINames(t *testing.T) {
	if got := listenerSNINames(nil); len(got) != 0 {
		t.Fatalf("nil input: expected empty slice, got %#v", got)
	}

	n1, n2 := "a.example.com", "b.example.com"
	in := []loadbalancer.ServerNameIndicator{{Name: &n1}, {Name: &n2}}
	got := listenerSNINames(in)
	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

// decodeLoadBalancer builds a loadbalancer.LoadBalancer from a payload shaped
// like the one ListLoadBalancers returns, so the opt-out flag is read through
// the same JSON path the provider takes.
func decodeLoadBalancer(t *testing.T, payload string) *loadbalancer.LoadBalancer {
	t.Helper()
	var lb loadbalancer.LoadBalancer
	if err := json.Unmarshal([]byte(payload), &lb); err != nil {
		t.Fatalf("decoding load balancer payload: %v", err)
	}
	return &lb
}

func TestLbDisableTargetSecurityGroupAssignment(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    *bool
	}{
		{
			name:    "flag absent is unreadable, not an assurance that the group is attached",
			payload: `{"name":"lb1"}`,
			want:    nil,
		},
		{
			name:    "operator opted out, so backends carry only hand-attached groups",
			payload: `{"name":"lb1","disableTargetSecurityGroupAssignment":true}`,
			want:    new(true),
		},
		{
			name:    "managed target group is attached",
			payload: `{"name":"lb1","disableTargetSecurityGroupAssignment":false}`,
			want:    new(false),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lbDisableTargetSecurityGroupAssignment(decodeLoadBalancer(t, tc.payload))
			assertBoolPtr(t, "lbDisableTargetSecurityGroupAssignment", got, tc.want)
		})
	}
}

func TestLbDisableTargetSecurityGroupAssignmentNilBalancer(t *testing.T) {
	if got := lbDisableTargetSecurityGroupAssignment(nil); got != nil {
		t.Fatalf("lbDisableTargetSecurityGroupAssignment(nil) = %v, want null", *got)
	}
}

// TestLoadBalancerSecurityGroupIds pins the ids the balancer carries inline,
// which is what the typed accessors resolve against the project's group list.
// A balancer with no managed group must yield empty ids so the accessors
// report null rather than looking up a group that was never named.
func TestLoadBalancerSecurityGroupIds(t *testing.T) {
	lb := decodeLoadBalancer(t, `{"name":"lb1",`+
		`"loadBalancerSecurityGroup":{"id":"sg-lb","name":"lb-group"},`+
		`"targetSecurityGroup":{"id":"sg-target","name":"target-group"}}`)
	sg, ok := lb.GetLoadBalancerSecurityGroupOk()
	if !ok || sg == nil || sg.GetId() != "sg-lb" {
		t.Fatalf("loadBalancerSecurityGroup id = %#v, want %q", sg, "sg-lb")
	}
	target, ok := lb.GetTargetSecurityGroupOk()
	if !ok || target == nil || target.GetId() != "sg-target" {
		t.Fatalf("targetSecurityGroup id = %#v, want %q", target, "sg-target")
	}

	bare := decodeLoadBalancer(t, `{"name":"lb1"}`)
	if sg, ok := bare.GetLoadBalancerSecurityGroupOk(); ok || sg != nil {
		t.Fatalf("balancer with no managed group reported one: %#v", sg)
	}
	if sg, ok := bare.GetTargetSecurityGroupOk(); ok || sg != nil {
		t.Fatalf("balancer with no target group reported one: %#v", sg)
	}
}

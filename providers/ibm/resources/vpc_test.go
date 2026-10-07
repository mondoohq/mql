// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unmarshal runs the SDK's own unmarshaller, so the tests see the concrete
// variant types the API produces rather than hand-built structs.
func unmarshal[T any](t *testing.T, doc string, fn func(map[string]json.RawMessage, any) error) *T {
	t.Helper()
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(doc), &raw))
	var out *T
	require.NoError(t, fn(raw, &out))
	return out
}

func TestDecodeSecurityGroupRulesAllVariants(t *testing.T) {
	sg := unmarshal[vpcv1.SecurityGroup](t, `{
		"id": "sg-1", "name": "web", "crn": "crn:sg-1",
		"rules": [
			{"id": "r1", "direction": "inbound", "ip_version": "ipv4", "protocol": "tcp",
			 "port_min": 22, "port_max": 22, "remote": {"cidr_block": "0.0.0.0/0"}},
			{"id": "r2", "direction": "inbound", "ip_version": "ipv4", "protocol": "icmp",
			 "type": 8, "code": 0, "remote": {"address": "203.0.113.5"}},
			{"id": "r3", "direction": "outbound", "ip_version": "ipv4", "protocol": "all",
			 "remote": {"id": "sg-2", "crn": "crn:sg-2", "name": "db"}}
		]}`, vpcv1.UnmarshalSecurityGroup)

	rules, err := decodeSecurityGroupRules(sg.Rules)
	require.NoError(t, err)
	require.Len(t, rules, 3)

	assert.Equal(t, "tcp", rules[0].Protocol)
	assert.Equal(t, int64(22), *rules[0].PortMin)
	assert.Equal(t, int64(22), *rules[0].PortMax)
	assert.Equal(t, "0.0.0.0/0", rules[0].Remote.CIDRBlock)

	assert.Equal(t, "icmp", rules[1].Protocol)
	assert.Equal(t, int64(8), *rules[1].Type)
	assert.Equal(t, int64(0), *rules[1].Code)
	assert.Nil(t, rules[1].PortMin, "an ICMP rule has no port range")
	assert.Equal(t, "203.0.113.5", rules[1].Remote.Address)

	assert.Equal(t, "all", rules[2].Protocol)
	assert.Equal(t, "outbound", rules[2].Direction)
	assert.Equal(t, "sg-2", rules[2].Remote.ID)
	assert.Empty(t, rules[2].Remote.CIDRBlock)
}

func TestSecurityGroupRuleArgsKeepAbsentPortsNull(t *testing.T) {
	args := securityGroupRuleArgs("k", securityGroupRule{Protocol: "all", Direction: "inbound"})
	// A rule over all ports has no range: null, not 0, so "portMin == 0"
	// cannot be mistaken for a real port.
	assert.Nil(t, args["portMin"].Value)
	assert.Nil(t, args["portMax"].Value)
	assert.Nil(t, args["icmpType"].Value)
}

func TestNetworkACLRuleDecode(t *testing.T) {
	acl := unmarshal[vpcv1.NetworkACL](t, `{
		"id": "acl-1", "name": "default", "crn": "crn:acl-1",
		"rules": [
			{"id": "a1", "name": "allow-ssh", "action": "allow", "direction": "inbound", "ip_version": "ipv4",
			 "protocol": "tcp", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
			 "source_port_min": 1, "source_port_max": 65535, "destination_port_min": 22, "destination_port_max": 22,
			 "created_at": "2026-01-01T00:00:00Z", "href": "h"},
			{"id": "a2", "name": "deny-all", "action": "deny", "direction": "inbound", "ip_version": "ipv4",
			 "protocol": "all", "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
			 "created_at": "2026-01-01T00:00:00Z", "href": "h"}
		]}`, vpcv1.UnmarshalNetworkACL)

	var rules []networkACLRule
	for _, r := range acl.Rules {
		var nr networkACLRule
		require.NoError(t, asJSON(r, &nr))
		rules = append(rules, nr)
	}
	require.Len(t, rules, 2)
	assert.Equal(t, "allow", rules[0].Action)
	assert.Equal(t, int64(22), *rules[0].DestinationPortMin)
	assert.Equal(t, "deny", rules[1].Action)
	assert.Nil(t, rules[1].DestinationPortMin)
}

func TestInstanceArgs(t *testing.T) {
	i := unmarshal[vpcv1.Instance](t, `{
		"id": "i-1", "crn": "crn:i-1", "name": "web-1", "status": "running",
		"enable_secure_boot": true, "confidential_compute_mode": "disabled",
		"metadata_service": {"enabled": true, "protocol": "https", "response_hop_limit": 1},
		"profile": {"name": "bx2-2x8", "href": "h"}, "memory": 8,
		"vcpu": {"architecture": "amd64", "count": 2, "manufacturer": "intel"},
		"zone": {"name": "us-south-1", "href": "h"}
	}`, vpcv1.UnmarshalInstance)

	args := instanceArgs("us-south", *i)
	assert.Equal(t, "ibm.vpc.instance/crn:i-1", args["__id"].Value)
	assert.Equal(t, true, args["enableSecureBoot"].Value)
	assert.Equal(t, true, args["metadataServiceEnabled"].Value)
	assert.Equal(t, "https", args["metadataServiceProtocol"].Value)
	assert.Equal(t, int64(1), args["metadataServiceResponseHopLimit"].Value)
	assert.Equal(t, int64(2), args["vcpuCount"].Value)
	assert.Equal(t, "bx2-2x8", args["profile"].Value)
	assert.Equal(t, "us-south-1", args["zone"].Value)
}

func TestInstanceArgsWithoutMetadataService(t *testing.T) {
	args := instanceArgs("us-south", vpcv1.Instance{})
	// An absent metadata service block is null, not "disabled".
	assert.Nil(t, args["metadataServiceEnabled"].Value)
	assert.Nil(t, args["enableSecureBoot"].Value)
	assert.Nil(t, args["createdAt"].Value)
}

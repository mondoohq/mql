// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/core"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// securityRuleDirection values, matching core.SecurityRuleDirectionEnum. Security
// list rules carry no direction of their own: which list they came from decides it.
const (
	securityRuleIngress = "INGRESS"
	securityRuleEgress  = "EGRESS"
)

// securityRule is the normalized form of a rule from either source OCI models
// them in: a security list's IngressSecurityRule/EgressSecurityRule, or a
// network security group's SecurityRule. The two carry the same information
// through different SDK types, so both are adapted to this shape and rendered
// by one builder.
type securityRule struct {
	// id is the rule's own OCID when OCI assigns one. Network security group
	// rules have one; security list rules are positional and do not, so their
	// cache key falls back to the container OCID plus the rule's index.
	id              string
	direction       string
	protocol        string
	description     string
	source          string
	sourceType      string
	destination     string
	destinationType string
	stateless       bool
	tcpOptions      *core.TcpOptions
	udpOptions      *core.UdpOptions
	icmpOptions     *core.IcmpOptions
}

// securityRuleFromIngress adapts a security list's ingress rule.
func securityRuleFromIngress(r core.IngressSecurityRule) securityRule {
	return securityRule{
		direction:   securityRuleIngress,
		protocol:    stringValue(r.Protocol),
		description: stringValue(r.Description),
		source:      stringValue(r.Source),
		sourceType:  string(r.SourceType),
		stateless:   boolValue(r.IsStateless),
		tcpOptions:  r.TcpOptions,
		udpOptions:  r.UdpOptions,
		icmpOptions: r.IcmpOptions,
	}
}

// securityRuleFromEgress adapts a security list's egress rule.
func securityRuleFromEgress(r core.EgressSecurityRule) securityRule {
	return securityRule{
		direction:       securityRuleEgress,
		protocol:        stringValue(r.Protocol),
		description:     stringValue(r.Description),
		destination:     stringValue(r.Destination),
		destinationType: string(r.DestinationType),
		stateless:       boolValue(r.IsStateless),
		tcpOptions:      r.TcpOptions,
		udpOptions:      r.UdpOptions,
		icmpOptions:     r.IcmpOptions,
	}
}

// securityRuleFromNsg adapts a network security group rule, which unlike a
// security list rule states its own direction and carries an OCID.
func securityRuleFromNsg(r core.SecurityRule) securityRule {
	return securityRule{
		id:              stringValue(r.Id),
		direction:       string(r.Direction),
		protocol:        stringValue(r.Protocol),
		description:     stringValue(r.Description),
		source:          stringValue(r.Source),
		sourceType:      string(r.SourceType),
		destination:     stringValue(r.Destination),
		destinationType: string(r.DestinationType),
		stateless:       boolValue(r.IsStateless),
		tcpOptions:      r.TcpOptions,
		udpOptions:      r.UdpOptions,
		icmpOptions:     r.IcmpOptions,
	}
}

// rulePorts returns the source and destination port bounds a rule covers.
//
// OCI nests them one level deeper than the rule, under whichever of tcpOptions
// or udpOptions the protocol selects, and a rule sets at most one of the two. A
// nil bound is not zero: it means the rule states no range for that end, which
// covers every port. Callers pass the pointers straight to llx.IntDataPtr so
// that distinction survives into the schema rather than collapsing to 0.
func rulePorts(r securityRule) (srcMin, srcMax, dstMin, dstMax *int) {
	var src, dst *core.PortRange
	switch {
	case r.tcpOptions != nil:
		src, dst = r.tcpOptions.SourcePortRange, r.tcpOptions.DestinationPortRange
	case r.udpOptions != nil:
		src, dst = r.udpOptions.SourcePortRange, r.udpOptions.DestinationPortRange
	}
	if src != nil {
		srcMin, srcMax = src.Min, src.Max
	}
	if dst != nil {
		dstMin, dstMax = dst.Min, dst.Max
	}
	return srcMin, srcMax, dstMin, dstMax
}

// newSecurityRule builds the MQL resource for one rule. containerID is the OCID
// of the security list or network security group holding it, and index its
// position within that container's rule list; together they form the cache key
// for rules OCI gives no OCID of their own.
func newSecurityRule(runtime *plugin.Runtime, containerID string, index int, r securityRule) (*mqlOciNetworkSecurityRule, error) {
	ruleID := r.id
	if ruleID == "" {
		ruleID = containerID + "/" + r.direction + "/" + strconv.Itoa(index)
	}

	srcMin, srcMax, dstMin, dstMax := rulePorts(r)

	var icmpType, icmpCode *int
	if r.icmpOptions != nil {
		icmpType, icmpCode = r.icmpOptions.Type, r.icmpOptions.Code
	}

	res, err := CreateResource(runtime, "oci.network.securityRule", map[string]*llx.RawData{
		"__id":               llx.StringData(ruleID),
		"direction":          llx.StringData(r.direction),
		"protocol":           llx.StringData(r.protocol),
		"description":        llx.StringData(r.description),
		"source":             llx.StringData(r.source),
		"sourceType":         llx.StringData(r.sourceType),
		"destination":        llx.StringData(r.destination),
		"destinationType":    llx.StringData(r.destinationType),
		"stateless":          llx.BoolData(r.stateless),
		"sourcePortMin":      llx.IntDataPtr(srcMin),
		"sourcePortMax":      llx.IntDataPtr(srcMax),
		"destinationPortMin": llx.IntDataPtr(dstMin),
		"destinationPortMax": llx.IntDataPtr(dstMax),
		"icmpType":           llx.IntDataPtr(icmpType),
		"icmpCode":           llx.IntDataPtr(icmpCode),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciNetworkSecurityRule), nil
}

// newSecurityRules builds the MQL resources for a container's rules, keeping
// their order so an index stays a stable cache key across queries.
func newSecurityRules(runtime *plugin.Runtime, containerID string, rules []securityRule) ([]any, error) {
	res := make([]any, 0, len(rules))
	for i := range rules {
		rule, err := newSecurityRule(runtime, containerID, i, rules[i])
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

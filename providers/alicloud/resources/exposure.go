// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "strings"

// internetExposed reports whether the ECS instance has inbound reachability from
// the public internet, before security-group rules are applied. An instance is
// exposed when it carries a directly-assigned public IP address or an associated
// elastic IP address.
func (i *mqlAlicloudEcsInstance) internetExposed() (bool, error) {
	if len(i.PublicIpAddresses.Data) > 0 {
		return true, nil
	}
	if strings.TrimSpace(i.EipAddress.Data) != "" {
		return true, nil
	}
	return false, nil
}

// isInternetFacing reports whether a load balancer address type designates a
// public (internet-facing) endpoint. Shared by the CLB, ALB, and NLB accessors.
func isInternetFacing(addressType string) bool {
	return strings.EqualFold(strings.TrimSpace(addressType), "internet")
}

// internetFacing reports whether the CLB instance serves traffic from the public
// internet, which is the case when its address type is internet.
func (l *mqlAlicloudSlbLoadBalancer) internetFacing() (bool, error) {
	return isInternetFacing(l.AddressType.Data), nil
}

// internetFacing reports whether the ALB serves traffic from the public
// internet, which is the case when its address type is Internet.
func (l *mqlAlicloudAlbLoadBalancer) internetFacing() (bool, error) {
	return isInternetFacing(l.AddressType.Data), nil
}

// internetFacing reports whether the NLB serves traffic from the public
// internet, which is the case when its address type is Internet.
func (l *mqlAlicloudNlbLoadBalancer) internetFacing() (bool, error) {
	return isInternetFacing(l.AddressType.Data), nil
}

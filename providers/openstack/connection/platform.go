// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/sha256"
	"encoding/hex"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Discovery targets understood by the openstack connector.
const (
	// DiscoveryAuto is the default; it keeps the connection as a single root
	// (project/domain/system) asset and does not expand into child assets.
	DiscoveryAuto = "auto"
	// DiscoveryAll expands every supported child-asset type.
	DiscoveryAll = "all"
	// DiscoverySecurityGroups expands the scope into one asset per security group.
	DiscoverySecurityGroups = "security-groups"
)

// OptionSecurityGroup carries the id of the security group a child connection is
// scoped to. Present only on discovered openstack-security-group assets.
const OptionSecurityGroup = "security-group"

// scopeIdentifier returns the platform id of the connection's root scope
// (project, domain, or system) — the same id detect() assigns to the root
// asset. Child platform ids are anchored under it so they stay stable and
// unique across scans.
func (c *OpenstackConnection) scopeIdentifier() string {
	switch {
	case c.ProjectID() != "":
		return PlatformIdOpenstackProject + c.ProjectID()
	case c.DomainID() != "":
		return PlatformIdOpenstackDomain + c.DomainID()
	default:
		sum := sha256.Sum256([]byte(c.AuthURL()))
		return PlatformIdOpenstackSystem + hex.EncodeToString(sum[:])
	}
}

// SecurityGroupPlatform describes a single discovered OpenStack security group,
// mirroring the naming of other providers' object platforms (aws-security-group,
// digitalocean-firewall).
func SecurityGroupPlatform() *inventory.Platform {
	p := &inventory.Platform{}
	PlatformByName("openstack-security-group").Apply(p)
	return p
}

// NewSecurityGroupIdentifier builds the platform id for a single security group,
// anchored under the connection's root scope.
func (c *OpenstackConnection) NewSecurityGroupIdentifier(sgID string) string {
	return c.scopeIdentifier() + "/security-group/" + sgID
}

// SecurityGroupID returns the id of the security group this connection is scoped
// to, or an empty string when the connection is a root scope.
func (c *OpenstackConnection) SecurityGroupID() string {
	return c.Conf.Options[OptionSecurityGroup]
}

// SubAssetPlatform reports the platform, platform id, and name when the
// connection is scoped to a single discovered child asset (currently a security
// group). It returns nils for a root (project/domain/system) scope.
func (c *OpenstackConnection) SubAssetPlatform() (*inventory.Platform, string, string) {
	if sgID := c.SecurityGroupID(); sgID != "" {
		return SecurityGroupPlatform(), c.NewSecurityGroupIdentifier(sgID), "OpenStack Security Group " + sgID
	}
	return nil, "", ""
}

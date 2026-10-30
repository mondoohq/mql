// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "portainer-server",
		Title:   "Portainer Server",
		Family:  []string{"portainer"},
		Kind:    []string{"api"},
		Runtime: []string{"portainer"},
	},
	{
		Name:    "portainer-environment",
		Title:   "Portainer Environment",
		Family:  []string{"portainer"},
		Kind:    []string{"api"},
		Runtime: []string{"portainer"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}

// Discovery targets
const (
	DiscoveryAuto         = "auto"
	DiscoveryAll          = "all"
	DiscoveryEnvironments = "environments"
	DiscoveryDocker       = "docker"
	DiscoveryKubernetes   = "kubernetes"
	DiscoveryEdge         = "edge"
)

// Connection options
const (
	OptionAddress  = "address"
	OptionInsecure = "insecure"
	// OptionEnvironmentID scopes a connection to a single managed environment
	// (endpoint) discovered from the Portainer instance.
	OptionEnvironmentID = "environment-id"
	// OptionEnvironmentType carries the Portainer endpoint type of a discovered
	// environment so the sub-asset platform can be labelled correctly.
	OptionEnvironmentType = "environment-type"
)

// EnvironmentType returns a human-readable name for a Portainer endpoint type.
// See https://github.com/portainer/portainer for the canonical enum.
func EnvironmentType(t int64) string {
	switch t {
	case 1:
		return "docker"
	case 2:
		return "agent-docker"
	case 3:
		return "azure-aci"
	case 4:
		return "edge-agent-docker"
	case 5:
		return "kubernetes"
	case 6:
		return "agent-kubernetes"
	case 7:
		return "edge-agent-kubernetes"
	default:
		return "unknown"
	}
}

// IsDockerEnvironment reports whether the endpoint type is a Docker/Swarm one.
func IsDockerEnvironment(t int64) bool {
	return t == 1 || t == 2 || t == 4
}

// IsKubernetesEnvironment reports whether the endpoint type is a Kubernetes one.
func IsKubernetesEnvironment(t int64) bool {
	return t == 5 || t == 6 || t == 7
}

// IsEdgeEnvironment reports whether the endpoint type is an Edge-agent one.
func IsEdgeEnvironment(t int64) bool {
	return t == 4 || t == 7
}

// EnvironmentStatus maps the Portainer endpoint status enum to a string.
// Portainer declares the status as enums 1,2,3,4: the open-source edition only
// names 1 (up) and 2 (down), while 3 (provisioning) and 4 (error) are reported
// by cloud-provisioned environments and carry a StatusMessage.
func EnvironmentStatus(s int64) string {
	switch s {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "provisioning"
	case 4:
		return "error"
	default:
		return "unknown"
	}
}

// AccessPolicyRole maps a Portainer environment role id, as it appears in the
// team and user access policies, to the role name used by the API.
func AccessPolicyRole(r int64) string {
	switch r {
	case 1:
		return "environment_administrator"
	case 2:
		return "helpdesk_user"
	case 3:
		return "standard_user"
	case 4:
		return "readonly_user"
	case 5:
		return "operator_user"
	default:
		return "unknown"
	}
}

// AuthenticationMethod maps the Portainer settings authentication-method enum.
func AuthenticationMethod(m int64) string {
	switch m {
	case 1:
		return "internal"
	case 2:
		return "ldap"
	case 3:
		return "oauth"
	default:
		return "unknown"
	}
}

// UserRole maps the Portainer user role enum to a string.
func UserRole(r int64) string {
	switch r {
	case 1:
		return "administrator"
	case 2:
		return "standard"
	default:
		return "unknown"
	}
}

// EdgeStackDeploymentType maps the Portainer Edge stack deployment-type enum.
func EdgeStackDeploymentType(t int64) string {
	switch t {
	case 0:
		return "compose"
	case 1:
		return "kubernetes"
	default:
		return "unknown"
	}
}

// MembershipRole maps the Portainer team-membership role enum to a string.
func MembershipRole(r int64) string {
	switch r {
	case 1:
		return "leader"
	case 2:
		return "member"
	default:
		return "unknown"
	}
}

// RegistryType maps the Portainer registry type enum to a string. The API
// documents seven values and rejects any other on create, so an unlisted value
// is reported as unknown rather than guessed at.
func RegistryType(t int64) string {
	switch t {
	case 1:
		return "quay"
	case 2:
		return "azure"
	case 3:
		return "custom"
	case 4:
		return "gitlab"
	case 5:
		return "proget"
	case 6:
		return "dockerhub"
	case 7:
		return "ecr"
	default:
		return "unknown"
	}
}

// StackType maps the Portainer stack type enum to a string.
func StackType(t int64) string {
	switch t {
	case 1:
		return "swarm"
	case 2:
		return "compose"
	case 3:
		return "kubernetes"
	default:
		return "unknown"
	}
}

// StackStatus maps the Portainer stack status enum to a string.
func StackStatus(s int64) string {
	switch s {
	case 1:
		return "active"
	case 2:
		return "inactive"
	default:
		return "unknown"
	}
}

// WebhookType maps the Portainer webhook type enum to a string.
func WebhookType(t int64) string {
	switch t {
	case 1:
		return "service"
	case 2:
		return "container"
	default:
		return "unknown"
	}
}

func InstancePlatform() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"virtualization", "portainer", "instance"},
	}
	PlatformByName("portainer-server").Apply(p)
	return p
}

func EnvironmentPlatform(envType int64) *inventory.Platform {
	p := &inventory.Platform{
		// The specific endpoint type is only known at runtime, so set the
		// concrete title here; Apply preserves an already-set title.
		Title:                 "Portainer Environment (" + EnvironmentType(envType) + ")",
		TechnologyUrlSegments: []string{"virtualization", "portainer", "environment"},
	}
	PlatformByName("portainer-environment").Apply(p)
	return p
}

func NewInstancePlatformID(instanceID string) string {
	return "//platformid.api.mondoo.app/runtime/portainer/instance/" + instanceID
}

func NewEnvironmentPlatformID(instanceID string, envID int64) string {
	return NewInstancePlatformID(instanceID) + "/environment/" + strconv.FormatInt(envID, 10)
}

// SubAssetPlatform returns the platform, platform id and name for a connection
// that has been scoped to a single discovered environment. When the connection
// is a plain instance connection it returns nil.
func (c *PortainerConnection) SubAssetPlatform() (*inventory.Platform, string, string) {
	envIDStr := c.Conf.Options[OptionEnvironmentID]
	if envIDStr == "" {
		return nil, "", ""
	}
	envID, err := strconv.ParseInt(envIDStr, 10, 64)
	if err != nil {
		return nil, "", ""
	}
	// The environment type is stored as a connection option at discovery time;
	// fall back to 0 ("unknown") only if it is missing or malformed.
	envType, _ := strconv.ParseInt(c.Conf.Options[OptionEnvironmentType], 10, 64)
	return EnvironmentPlatform(envType), NewEnvironmentPlatformID(c.InstanceKey(), envID), "Portainer environment " + envIDStr
}

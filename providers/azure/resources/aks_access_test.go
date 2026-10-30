// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAksNodeAdminAccess(t *testing.T) {
	t.Run("nil properties report no administrator accounts", func(t *testing.T) {
		linux, keys, windows := aksNodeAdminAccess(nil)
		assert.Empty(t, linux)
		assert.Empty(t, windows)
		// Empty, never nil: an absent list must render as [] rather than null.
		assert.NotNil(t, keys)
		assert.Len(t, keys, 0)
	})

	t.Run("linux profile with an ssh key", func(t *testing.T) {
		user := "azureuser"
		key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0000000000000000000000000000000000000000000"
		props := &clusters.ManagedClusterProperties{
			LinuxProfile: &clusters.LinuxProfile{
				AdminUsername: &user,
				SSH: &clusters.SSHConfiguration{
					PublicKeys: []*clusters.SSHPublicKey{nil, {KeyData: &key}, {}},
				},
			},
		}
		linux, keys, windows := aksNodeAdminAccess(props)
		assert.Equal(t, "azureuser", linux)
		assert.Equal(t, []any{key}, keys)
		assert.Empty(t, windows)
	})

	t.Run("linux profile without ssh keys", func(t *testing.T) {
		user := "azureuser"
		props := &clusters.ManagedClusterProperties{
			LinuxProfile: &clusters.LinuxProfile{AdminUsername: &user},
		}
		linux, keys, _ := aksNodeAdminAccess(props)
		assert.Equal(t, "azureuser", linux)
		assert.Len(t, keys, 0)
	})

	t.Run("windows profile administrator", func(t *testing.T) {
		user := "winadmin"
		password := "never-exposed"
		props := &clusters.ManagedClusterProperties{
			WindowsProfile: &clusters.ManagedClusterWindowsProfile{
				AdminUsername: &user,
				AdminPassword: &password,
			},
		}
		linux, _, windows := aksNodeAdminAccess(props)
		assert.Empty(t, linux)
		assert.Equal(t, "winadmin", windows)
	})
}

func TestAksNodePoolHostAccess(t *testing.T) {
	t.Run("nil properties permit nothing extra", func(t *testing.T) {
		sysctls, ports, tags, asgs := aksNodePoolHostAccess(nil)
		assert.Len(t, sysctls, 0)
		assert.Len(t, ports, 0)
		assert.Len(t, tags, 0)
		assert.Nil(t, asgs)
	})

	t.Run("kubelet unsafe sysctls", func(t *testing.T) {
		one := "kernel.msg*"
		two := "net.core.somaxconn"
		empty := ""
		props := &clusters.ManagedClusterAgentPoolProfileProperties{
			KubeletConfig: &clusters.KubeletConfig{
				AllowedUnsafeSysctls: []*string{&one, nil, &empty, &two},
			},
		}
		sysctls, _, _, _ := aksNodePoolHostAccess(props)
		assert.Equal(t, []any{one, two}, sysctls)
	})

	t.Run("allowed host ports, ip tags and application security groups", func(t *testing.T) {
		start := int32(8080)
		end := int32(8090)
		proto := clusters.ProtocolTCP
		tagType := "RoutingPreference"
		tagValue := "Internet"
		asg := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/asg1"
		blank := ""
		props := &clusters.ManagedClusterAgentPoolProfileProperties{
			NetworkProfile: &clusters.AgentPoolNetworkProfile{
				AllowedHostPorts: []*clusters.PortRange{
					nil,
					{PortStart: &start, PortEnd: &end, Protocol: &proto},
				},
				NodePublicIPTags:          []*clusters.IPTag{nil, {IPTagType: &tagType, Tag: &tagValue}},
				ApplicationSecurityGroups: []*string{&asg, nil, &blank},
			},
		}
		_, ports, tags, asgs := aksNodePoolHostAccess(props)
		require.Len(t, ports, 1)
		assert.Equal(t, map[string]any{
			"portStart": int64(8080),
			"portEnd":   int64(8090),
			"protocol":  "TCP",
		}, ports[0])
		assert.Equal(t, map[string]any{"RoutingPreference": "Internet"}, tags)
		assert.Equal(t, []string{asg}, asgs)
	})

	t.Run("a port range without a protocol keeps the ports it did report", func(t *testing.T) {
		start := int32(22)
		props := &clusters.ManagedClusterAgentPoolProfileProperties{
			NetworkProfile: &clusters.AgentPoolNetworkProfile{
				AllowedHostPorts: []*clusters.PortRange{{PortStart: &start}},
			},
		}
		_, ports, _, _ := aksNodePoolHostAccess(props)
		require.Len(t, ports, 1)
		assert.Equal(t, map[string]any{"portStart": int64(22)}, ports[0])
	})
}

func TestCreateTrustedAccessRoleBindingRawData(t *testing.T) {
	t.Run("nil binding is an error, never a blank row", func(t *testing.T) {
		_, err := createTrustedAccessRoleBindingRawData(nil)
		assert.Error(t, err)
	})

	t.Run("a binding without an id is an error", func(t *testing.T) {
		_, err := createTrustedAccessRoleBindingRawData(&clusters.TrustedAccessRoleBinding{})
		assert.Error(t, err)
	})

	t.Run("full binding", func(t *testing.T) {
		id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c/trustedAccessRoleBindings/b1"
		name := "b1"
		role := "Microsoft.MachineLearningServices/workspaces/mlworkload"
		blank := ""
		source := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws"
		state := clusters.TrustedAccessRoleBindingProvisioningStateSucceeded
		args, err := createTrustedAccessRoleBindingRawData(&clusters.TrustedAccessRoleBinding{
			ID:   &id,
			Name: &name,
			Properties: &clusters.TrustedAccessRoleBindingProperties{
				Roles:             []*string{&role, nil, &blank},
				SourceResourceID:  &source,
				ProvisioningState: &state,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, llx.StringData(id), args["id"])
		assert.Equal(t, llx.StringData(name), args["name"])
		assert.Equal(t, llx.StringData(source), args["sourceResourceId"])
		assert.Equal(t, llx.StringData("Succeeded"), args["provisioningState"])
		assert.Equal(t, []any{role}, args["roles"].Value)
	})

	t.Run("a binding with no properties reports null rather than a fabricated state", func(t *testing.T) {
		id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c/trustedAccessRoleBindings/b1"
		args, err := createTrustedAccessRoleBindingRawData(&clusters.TrustedAccessRoleBinding{ID: &id})
		require.NoError(t, err)
		assert.Equal(t, llx.NilData, args["provisioningState"])
		assert.Equal(t, llx.NilData, args["sourceResourceId"])
		assert.Equal(t, []any{}, args["roles"].Value)
	})
}

// The two classifiers must disagree on 403: a refused read is not an absence.
// If they ever agree, a lister cannot tell "nothing is granted" from "not
// allowed to look", and a Trusted Access audit passes on a cluster whose
// grants were never read.
func TestAzureAccessDeniedAndFeatureUnavailableAreDistinct(t *testing.T) {
	forbidden := armError(http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	assert.True(t, isAzureAccessDenied(forbidden))
	assert.False(t, isAzureFeatureUnavailable(forbidden))

	notFound := armError(http.StatusNotFound, `{"error":{"code":"ResourceNotFound","message":"not found"}}`)
	assert.False(t, isAzureAccessDenied(notFound))
	assert.True(t, isAzureFeatureUnavailable(notFound))

	notRegistered := armError(http.StatusBadRequest, bodyAksNotPrivateLink)
	assert.False(t, isAzureAccessDenied(notRegistered))
	assert.True(t, isAzureFeatureUnavailable(notRegistered))

	// A transport failure carries no ARM response. Treating it as either an
	// absence or a refusal would turn a network blip into a clean answer.
	transport := errors.New("dial tcp: i/o timeout")
	assert.False(t, isAzureAccessDenied(transport))
	assert.False(t, isAzureFeatureUnavailable(transport))

	serverError := armError(http.StatusInternalServerError, `{"error":{"code":"InternalServerError","message":"boom"}}`)
	assert.False(t, isAzureAccessDenied(serverError))
	assert.False(t, isAzureFeatureUnavailable(serverError))
}
